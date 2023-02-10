# p0f3-database

Updated p0f3 signatures.

https://lcamtuf.coredump.cx/p0f3/

## Usage

```
usage: p0f.py [-h] [--pkappa-url PKAPPA_URL] [--pkappa-password PKAPPA_PASSWORD] [--p0f-path P0F_PATH] [--p0f-database-path P0F_DATABASE_PATH]
              pcap_path

Process p0f fingerprints and add them to pkappa2

positional arguments:
  pcap_path             Path to the pcap file to process

optional arguments:
  -h, --help            show this help message and exit
  --pkappa-url PKAPPA_URL
                        URL of pkappa2
  --pkappa-password PKAPPA_PASSWORD
                        Password of pkappa2 basic auth
  --p0f-path P0F_PATH   Path to the p0f binary
  --p0f-database-path P0F_DATABASE_PATH
                        Path to the p0f database
```

## Import p0f analysis into [pkappa2](https://github.com/spq/pkappa2)

- [Download](https://lcamtuf.coredump.cx/p0f3/releases/p0f-3.09b.tgz) and compile p0f
    - `./build.sh`
- Analyze a .pcap `python p0f.py some.pcap`
    - The .pcap has to be imported into pkappa2 beforehand.
    - Import all pcaps pkappa2 has seen: `for f in /tmp/pkappa2/*.pcap; do ./run.sh $f; done`

```
pip install -r requirements.txt
wget https://lcamtuf.coredump.cx/p0f3/releases/p0f-3.09b.tgz
tar xfz p0f-3.09b.tgz
cd p0f-3.09b
./build.sh
cd ..
./p0f.py --p0f-path ./p0f-3.09b/p0f path/to/some.pcap
# or
./run.sh path/to/some.pcap
```
