#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2023  Jannik Hartung
# Tool to import p0f fingerprints into pkappa2.
# Usage: ./p0f.py <pcap file>
from types import SimpleNamespace
import aiohttp
from aiofile import async_open
import asyncio
import dataclasses
import sys
import tempfile
from datetime import datetime, timedelta
from typing import Any, Dict, List, Set, Tuple, Union

PKAPPA_API_URL = 'http://localhost:8080/api'
FINGERPRINT_CHUNK_SIZE = 20 # mind the 100 stream page limit
FINGERPRINT_CHUNK_COUNT = 30

@dataclasses.dataclass
class Fingerprint:
    timestamp: str = dataclasses.field(default_factory=str)
    mod: str = dataclasses.field(default_factory=str)
    client_ip: str = dataclasses.field(default_factory=str)
    client_port: int = dataclasses.field(default_factory=int)
    server_ip: str = dataclasses.field(default_factory=str)
    server_port: int = dataclasses.field(default_factory=int)
    subject: str = dataclasses.field(default_factory=str)
    extra: Dict[str, str] = dataclasses.field(default_factory=dict)

@dataclasses.dataclass
class StreamResult:
    streams: List[Any]
    elapsed: float

class Pkappa2ClientException(Exception):
    pass

class Pkappa2Client:
    def __init__(self, session: aiohttp.ClientSession, url: str):
        self.base_url = url
        self.session = session
        self.tags = set()
    
    async def init(self) -> None:
        self.tags = await self.get_tags()

    async def search_streams(self, fingerprints: List[Fingerprint]) -> Union[StreamResult, None]:
        query = []
        for fingerprint in fingerprints:
            timestamp_start = datetime.strptime(fingerprint.timestamp, '%Y/%m/%d %H:%M:%S')
            timestamp_end = timestamp_start + timedelta(seconds=1)
            timestamp = timestamp_start.strftime('%Y-%m-%d %H%M%S') + ":" + timestamp_end.strftime('%Y-%m-%d %H%M%S')
            query.append(f'(time:"{timestamp}" chost:{fingerprint.client_ip} cport:{fingerprint.client_port} shost:{fingerprint.server_ip} sport:{fingerprint.server_port})')
            # query.append(f'(chost:{fingerprint.client_ip} cport:{fingerprint.client_port} shost:{fingerprint.server_ip} sport:{fingerprint.server_port})')
        query = f'protocol:tcp ({" OR ".join(query)})'

        timing_context = RequestContext()
        async with self.session.post(f"{self.base_url}/search.json", params={"page": "0"}, data=query, trace_request_ctx=timing_context) as response:
            if response.status != 200:
                error = await response.text()
                raise Pkappa2ClientException(f"search failed: {response.status} {error}")
            result = await response.json()
            if 'Error' in result:
                raise Pkappa2ClientException(f"search failed: {result} (query={query})")
            if 'MoreResults' in result and result['MoreResults']:
                print(f"warning: more results available on second page")
            streams = result['Results']
            if len(streams) == 0:
                return None
            return StreamResult(streams, timing_context.end - timing_context.start)

    async def get_tags(self) -> Set[str]:
        async with self.session.get(f"{self.base_url}/tags") as response:
            if response.status != 200:
                error = await response.text()
                raise Pkappa2ClientException(f"get tags failed: {response.status} {error}")
            tags = await response.json()
            return set([tag['Name'] for tag in tags])

    async def add_mark(self, mark_name: str, stream_ids: List[int]) -> float:
        timing_context = RequestContext()
        if mark_name not in self.tags:
            stream_id_str = ','.join([str(stream_id) for stream_id in stream_ids])
            async with self.session.put(f"{self.base_url}/tags", params={"name": mark_name, "color": "#a366ff"}, data=f"id:{stream_id_str}", trace_request_ctx=timing_context) as response:
                if response.status != 200:
                    error = await response.text()
                    # try again if the tag was created in the meantime
                    if response.status == 400 and "tag already exists" in error:
                        self.tags.add(mark_name)
                        return await self.add_mark(mark_name, stream_ids)
                    raise Pkappa2ClientException(f"add tag failed: {response.status} {error}")
                self.tags.add(mark_name)
                return timing_context.end - timing_context.start
        else:
            async with self.session.patch(f"{self.base_url}/tags", params={"name": mark_name, "method": "mark_add", "stream": list(map(str, stream_ids))}, trace_request_ctx=timing_context) as response:
                if response.status != 200:
                    error = await response.text()
                    raise Pkappa2ClientException(f"update tag failed: {response.status} {error}")
                return timing_context.end - timing_context.start

async def get_fingerprints(filename: str) -> List[Fingerprint]:
    # run p0f to get the fingerprints
    with tempfile.NamedTemporaryFile('w') as tf:
        proc = await asyncio.create_subprocess_exec('./p0f', '-r', filename, '-o', tf.name, stdout=asyncio.subprocess.DEVNULL)
        exit_code = await proc.wait()
        if exit_code != 0:
            stderr = await proc.stderr.read() if proc.stderr else b''
            print(f'p0f failed: {exit_code}: {stderr}')
            sys.exit(1)
        
        # read the fingerprints
        fingerprints = []
        async with async_open(tf.name, 'r') as f:
            async for line in f:
                timestamp_and_data = line.split(']', 1)
                fingerprint = Fingerprint()
                fingerprint.timestamp = timestamp_and_data[0][1:]
                parameters = timestamp_and_data[1][1:].split('|')
                for param in parameters:
                    # [2012/01/04 10:26:14] mod=mtu|cli=1.2.3.4/1234|srv=4.3.2.1/80|subj=cli|link=DSL|raw_mtu=1492
                    if param.startswith('mod='):
                        fingerprint.mod = param.split('=')[1]
                    elif param.startswith('cli='):
                        cli = param.split('=')[1]
                        fingerprint.client_ip = cli.split('/')[0]
                        fingerprint.client_port = int(cli.split('/')[1])
                    elif param.startswith('srv='):
                        srv = param.split('=')[1]
                        fingerprint.server_ip = srv.split('/')[0]
                        fingerprint.server_port = int(srv.split('/')[1])
                    elif param.startswith('subj='):
                        fingerprint.subject = param.split('=')[1]
                    else:
                        pair = param.split('=')
                        fingerprint.extra[pair[0]] = pair[1].strip()
                fingerprints.append(fingerprint)
    return fingerprints

@dataclasses.dataclass
class RequestContext:
    start: float = 0.0
    end: float = 0.0

async def on_request_start(session: aiohttp.ClientSession, trace_config_ctx: SimpleNamespace, params: aiohttp.TraceRequestStartParams) -> None:
    if trace_config_ctx.trace_request_ctx is not None:
        trace_config_ctx.trace_request_ctx.start = asyncio.get_event_loop().time()

async def on_request_end(session: aiohttp.ClientSession, trace_config_ctx: SimpleNamespace, params: aiohttp.TraceRequestEndParams) -> None:
    if trace_config_ctx.trace_request_ctx is not None:
        trace_config_ctx.trace_request_ctx.end = asyncio.get_event_loop().time()

async def main():
    print(f'Processing fingerprints of packets in {sys.argv[1]}...')
    start = asyncio.get_event_loop().time()
    all_fingerprints = await get_fingerprints(sys.argv[1])
    mod_blocklist = ['http request', 'http response', 'host change', 'ip sharing', 'uptime']
    client_fingerprints = list(filter(lambda f: f.subject == 'cli' and f.mod not in mod_blocklist, all_fingerprints))
    print(f'Fingerprints: {len(all_fingerprints)}, filtered client fingerprints: {len(client_fingerprints)} (p0f: {asyncio.get_event_loop().time() - start:.02f}s))')
    
    def get_stream_timestamps(stream):
        def strip_timezone(timestamp):
            if '.' in timestamp:
                return timestamp[:timestamp.index('.')]
            return timestamp
        first_packet = strip_timezone(stream['FirstPacket'])
        last_packet = strip_timezone(stream['LastPacket'])
        return datetime.strptime(first_packet, '%Y-%m-%dT%H:%M:%S'), datetime.strptime(last_packet, '%Y-%m-%dT%H:%M:%S')# + timedelta(seconds=1)

    # keep track of the time it takes to send the requests
    trace_config = aiohttp.TraceConfig()
    trace_config.on_request_start.append(on_request_start)
    trace_config.on_request_end.append(on_request_end)

    async with aiohttp.ClientSession(trace_configs=[trace_config]) as session:
        client = Pkappa2Client(session, PKAPPA_API_URL)
        await client.init()
        for chunk_start in range(0, len(client_fingerprints), FINGERPRINT_CHUNK_SIZE * FINGERPRINT_CHUNK_COUNT):
            chunk_end = min(chunk_start + FINGERPRINT_CHUNK_SIZE * FINGERPRINT_CHUNK_COUNT, len(client_fingerprints))
            fingerprint_groups = [client_fingerprints[idx:idx + FINGERPRINT_CHUNK_SIZE] for idx in range(chunk_start, chunk_end, FINGERPRINT_CHUNK_SIZE)]
            streams_groups: List[Union[StreamResult, None]] = await asyncio.gather(*[client.search_streams(fingerprint) for fingerprint in fingerprint_groups if fingerprint])
            try:
                elapsed = max([stream.elapsed for stream in streams_groups if stream is not None])
                print(f'Processing fingerprints {chunk_start}-{chunk_end}/{len(client_fingerprints)} (query {elapsed:.02f}s)...')
                elapsed = 0.0
                added_streams = 0
                for fingerprints, streams in zip(fingerprint_groups, streams_groups):
                    if streams is None:
                        print(fingerprints)
                        print('  not found')
                        continue

                    # print(f'  found {len(streams)} streams')
                    marks_to_add: Dict[str, List[int]] = {}
                    for fingerprint in fingerprints:
                        for stream in streams.streams:
                            stream_data = stream['Stream']
                            fingerprint_timestamp = datetime.strptime(fingerprint.timestamp, '%Y/%m/%d %H:%M:%S')
                            first_packet, last_packet = get_stream_timestamps(stream_data)

                            if fingerprint.client_ip == stream_data['Client']['Host'] \
                            and fingerprint.client_port == stream_data['Client']['Port'] \
                            and fingerprint.server_ip == stream_data['Server']['Host'] \
                            and fingerprint.server_port == stream_data['Server']['Port'] \
                            and fingerprint_timestamp >= first_packet \
                            and fingerprint_timestamp <= last_packet:
                                stream_id = stream_data['ID']
                                tags = stream['Tags']
                                break
                        else:
                            print(fingerprint)
                            print('  not found')
                            continue
                    
                        if fingerprint.mod == 'syn':
                            mark_name = f'generated/p0f: os={fingerprint.extra["os"]}'
                        elif fingerprint.mod == 'mtu':
                            mark_name = f'generated/p0f: {fingerprint.extra["link"]} mtu={fingerprint.extra["raw_mtu"]}'
                        else:
                            print(fingerprint)
                            print(f'  stream_id={stream_id}')
                            print(f'  tags={tags}')
                            continue

                        if mark_name not in tags:
                            # print(stream_id, tags)
                            if mark_name not in marks_to_add:
                                marks_to_add[mark_name] = []
                            marks_to_add[mark_name].append(stream_id)
                            added_streams += 1
                    if marks_to_add:
                        elapsed += max(await asyncio.gather(*[client.add_mark(mark_name, stream_ids) for mark_name, stream_ids in marks_to_add.items()]))
                print(f'  added {added_streams} streams to generated marks ({elapsed:.02f}s)')

            except Pkappa2ClientException as ex:
                print(f'  {ex}')
                break
    print(f'Done ({asyncio.get_event_loop().time() - start:.02f}s)')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <filename.pcap>')
        sys.exit(1)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
