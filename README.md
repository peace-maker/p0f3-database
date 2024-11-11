# p0f3-database

Updated p0f3 signatures.

https://lcamtuf.coredump.cx/p0f3/

## Usage

```
usage: p0f.py [-h] [--port PORT] [--pkappa-url PKAPPA_URL] [--pkappa-password PKAPPA_PASSWORD] [--p0f-path P0F_PATH] [--p0f-database-path P0F_DATABASE_PATH] [--listen] [--pcap-path PCAP_PATH]

Process p0f fingerprints and add them to pkappa2

options:
  -h, --help            show this help message and exit
  --port PORT           Port to listen on
  --pkappa-url PKAPPA_URL
                        URL of pkappa2
  --pkappa-password PKAPPA_PASSWORD
                        Password of pkappa2 basic auth
  --p0f-path P0F_PATH   Path to the p0f binary
  --p0f-database-path P0F_DATABASE_PATH
                        Path to the p0f database
  --listen              Listen for incoming requests
  --pcap-path PCAP_PATH
                        Path to the pcap file to process
```

## Import p0f analysis into [pkappa2](https://github.com/spq/pkappa2)

- Install `libpcap-dev` headers
  - `apt install libpcap-dev`
- [Download](https://lcamtuf.coredump.cx/p0f3/releases/p0f-3.09b.tgz) and compile p0f
    - `./setup.sh`
- *Manually:* Analyze a single .pcap `./run.sh some.pcap`
    - The .pcap has to be imported into pkappa2 beforehand.
    - Import all pcaps pkappa2 has seen: `for f in /tmp/pkappa2/*.pcap; do ./run.sh $f; done`
- *Automatically:* Start HTTP server and add it to pcap processed webhooks in pkappa2
  - Use `--listen` to start the server or `./listen.sh --pkappa-url http://localhost:8080 --pkappa-password pkappa2 --port 8082`
  - Add webhook url to pkappa2
    - `curl -X PUT -u 'pkappa2:pkappa2' 'http://localhost:8080/api/webhooks?url=http://localhost:8082/pcaps'`

```
./setup.sh
# import single pcap
./p0f.py --pcap-path path/to/some.pcap
# or
./run.sh path/to/some.pcap

# start http server on http://localhost:8082/ with /pcaps endpoint
./listen.sh
```
