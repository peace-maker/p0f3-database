#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2023  Jannik Hartung
# Tool to import p0f fingerprints into pkappa2.
# Usage: ./p0f.py <pcap file>
from types import SimpleNamespace
import aiohttp
from aiofile import async_open
import argparse
import asyncio
import dataclasses
import json
import os
import tempfile
from datetime import datetime, timedelta
from typing import AsyncIterator, Any, Dict, List, Set, Union

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

    def as_query(self) -> str:
        timestamp_start = datetime.strptime(self.timestamp, '%Y/%m/%d %H:%M:%S')
        timestamp_end = timestamp_start + timedelta(seconds=1)
        timestamp = timestamp_start.strftime('%Y-%m-%d %H%M%S') + ":" + timestamp_end.strftime('%Y-%m-%d %H%M%S')
        return f'time:"{timestamp}" chost:{self.client_ip} cport:{self.client_port} shost:{self.server_ip} sport:{self.server_port}'

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
        query = f'protocol:tcp ({" OR ".join(f"({fingerprint.as_query()})" for fingerprint in fingerprints)})'

        timing_context = RequestContext()
        async with self.session.post(f"{self.base_url}/api/search.json", params={"page": "0"}, data=query, trace_request_ctx=timing_context) as response:
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
        async with self.session.get(f"{self.base_url}/api/tags") as response:
            if response.status != 200:
                error = await response.text()
                raise Pkappa2ClientException(f"get tags failed: {response.status} {error}")
            tags = await response.json()
            return set([tag['Name'] for tag in tags])

    async def add_mark(self, mark_name: str, stream_ids: List[int]) -> float:
        timing_context = RequestContext()
        if mark_name not in self.tags:
            stream_id_str = ','.join([str(stream_id) for stream_id in stream_ids])
            async with self.session.put(f"{self.base_url}/api/tags", params={"name": mark_name, "color": "#a366ff"}, data=f"id:{stream_id_str}", trace_request_ctx=timing_context) as response:
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
            async with self.session.patch(f"{self.base_url}/api/tags", params={"name": mark_name, "method": "mark_add", "stream": list(map(str, stream_ids))}, trace_request_ctx=timing_context) as response:
                if response.status != 200:
                    error = await response.text()
                    raise Pkappa2ClientException(f"update tag failed: {response.status} {error}")
                return timing_context.end - timing_context.start

async def get_fingerprints(p0f_path: str , p0f_database_path: str, filename: str) -> AsyncIterator[Fingerprint]:
    # run p0f to get the fingerprints
    with tempfile.NamedTemporaryFile('r') as tf:
        proc = await asyncio.create_subprocess_exec(p0f_path, '-f', p0f_database_path, '-r', filename, '-o', tf.name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        # read the fingerprints
        async with async_open(tf, 'r') as f:
            full_line = ''
            while True:
                # Keep reading while there's still stuff left in the file or the process is still running
                line = await f.readline()
                if not line and proc.returncode is not None:
                    break
                full_line += line
                # We're racing p0f and this line is not complete yet
                if not line.endswith('\n'):
                    continue
                line = full_line
                full_line = ''

                # Parse the p0f log line
                try:
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
                    yield fingerprint
                except IndexError as ex:
                    print(f"failed to parse line: {line}")
                    raise ex

        # wait for p0f to finish
        exit_code = await proc.wait()
        if exit_code != 0:
            stderr = await proc.stderr.read() if proc.stderr else b''
            print(f'p0f failed (exit={exit_code}): {stderr.decode()}')
            exit(1)


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

def get_stream_timestamps(stream):
    def strip_timezone(timestamp):
        if '.' in timestamp:
            return timestamp[:timestamp.index('.')]
        return timestamp
    first_packet = strip_timezone(stream['FirstPacket'])
    last_packet = strip_timezone(stream['LastPacket'])
    return datetime.strptime(first_packet, '%Y-%m-%dT%H:%M:%S'), datetime.strptime(last_packet, '%Y-%m-%dT%H:%M:%S')# + timedelta(seconds=1)

async def main(args: SimpleNamespace):
    start = asyncio.get_event_loop().time()

    # check if the pcap was parsed already
    if os.path.exists('parsed_pcaps.json'):
        with open('parsed_pcaps.json', 'r') as f:
            try:
                parsed_pcaps = json.load(f)
            except json.decoder.JSONDecodeError:
                parsed_pcaps = []
            if args.pcap_path in parsed_pcaps:
                print(f'{args.pcap_path} already parsed, skipping...')
                return

    # keep track of the time it takes to send the requests
    trace_config = aiohttp.TraceConfig()
    trace_config.on_request_start.append(on_request_start)
    trace_config.on_request_end.append(on_request_end)

    auth = None
    if args.pkappa_password:
        auth = aiohttp.BasicAuth(login='admin', password=args.pkappa_password)

    async with aiohttp.ClientSession(trace_configs=[trace_config], auth=auth) as session:
        client = Pkappa2Client(session, args.pkappa_url)
        await client.init()

        print(f'Processing fingerprints of packets in {args.pcap_path}...')
        all_fingerprints = get_fingerprints(args.p0f_path, args.p0f_database_path, args.pcap_path)
        mod_blocklist = ['http request', 'http response', 'host change', 'ip sharing', 'uptime']

        fingerprint_count = 0
        client_fingerprint_count = 0

        while True:
            p0f_start = asyncio.get_event_loop().time()
            client_fingerprints: List[Fingerprint] = []

            async for fingerprint in all_fingerprints:
                fingerprint_count += 1
                if fingerprint.subject != 'cli' or fingerprint.mod in mod_blocklist:
                    continue
                client_fingerprints.append(fingerprint)
                client_fingerprint_count += 1
                if len(client_fingerprints) == FINGERPRINT_CHUNK_SIZE * FINGERPRINT_CHUNK_COUNT:
                    break

            if not client_fingerprints:
                break

            p0f_end = asyncio.get_event_loop().time()
            print(f'Processing fingerprints {client_fingerprint_count-len(client_fingerprints)}-{client_fingerprint_count} (p0f {p0f_end-p0f_start:.02f}s)...')

            fingerprint_groups = [client_fingerprints[idx:idx + FINGERPRINT_CHUNK_SIZE] for idx in range(0, len(client_fingerprints), FINGERPRINT_CHUNK_SIZE)]
            streams_groups: List[Union[StreamResult, None]] = await asyncio.gather(*[client.search_streams(fingerprint) for fingerprint in fingerprint_groups if fingerprint])
            try:
                marking_elapsed = 0.0
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
                            print(fingerprint.as_query())
                            print('  not found')
                            continue
                    
                        if fingerprint.mod == 'syn':
                            if 'os' not in fingerprint.extra:
                                print(fingerprint)
                                print(f'  stream_id={stream_id}')
                                print('  no os in syn fingerprint')
                                continue
                            mark_name = f'generated/p0f: os={fingerprint.extra["os"]}'
                        elif fingerprint.mod == 'mtu':
                            if 'link' not in fingerprint.extra or 'raw_mtu' not in fingerprint.extra:
                                print(fingerprint)
                                print(f'  stream_id={stream_id}')
                                print('  no link or raw_mtu in mtu fingerprint')
                                continue
                            mark_name = f'generated/p0f: {fingerprint.extra["link"]} mtu={fingerprint.extra["raw_mtu"]}'
                        else:
                            print(fingerprint)
                            print(f'  stream_id={stream_id}')
                            print(f'  tags={tags}')
                            continue

                        if mark_name not in tags:
                            if mark_name not in marks_to_add:
                                marks_to_add[mark_name] = []
                            marks_to_add[mark_name].append(stream_id)
                            added_streams += 1
                    if marks_to_add:
                        marking_elapsed += max(await asyncio.gather(*[client.add_mark(mark_name, stream_ids) for mark_name, stream_ids in marks_to_add.items()]))
                query_elapsed = max([stream.elapsed for stream in streams_groups if stream is not None])
                print(f'  added {added_streams} streams to generated marks (searchquery {query_elapsed:.02f}s) (mark {marking_elapsed:.02f}s)')

                # save the parsed pcap so we don't parse it again
                parsed_pcaps = []
                if os.path.exists('parsed_pcaps.json'):
                    with open('parsed_pcaps.json', 'r') as f:
                        try:
                            parsed_pcaps = json.load(f)
                        except json.decoder.JSONDecodeError:
                            pass
                parsed_pcaps.append(args.pcap_path)
                with open('parsed_pcaps.json', 'w') as f:
                    json.dump(parsed_pcaps, f)

            except Pkappa2ClientException as ex:
                print(f'  {ex}')
                break
    print(f'Fingerprints: {fingerprint_count}, filtered client fingerprints: {client_fingerprint_count} ({asyncio.get_event_loop().time() - start:.02f}s))')

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Process p0f fingerprints and add them to pkappa2')
    parser.add_argument('--pkappa-url', default='http://localhost:8080', help='URL of pkappa2', type=str)
    parser.add_argument('--pkappa-password', default='', help='Password of pkappa2 basic auth', type=str)
    parser.add_argument('--p0f-path', default='./p0f', help='Path to the p0f binary', type=str)
    parser.add_argument('--p0f-database-path', default='./p0f.fp', help='Path to the p0f database', type=str)
    parser.add_argument('pcap_path', help='Path to the pcap file to process', type=str)
    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main(args))
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
