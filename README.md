# p0f3-database

Updated p0f3 signatures.

https://lcamtuf.coredump.cx/p0f3/

## Import p0f analysis into [pkappa2](https://github.com/spq/pkappa2)

- [Download](https://lcamtuf.coredump.cx/p0f3/releases/p0f-3.09b.tgz) and compile p0f
    - `./build.sh`
- Copy `p0f.fp` and `p0f.py` into `p0f-3.09b` build directory
- Analyze a .pcap `python p0f.py some.pcap`
    - The .pcap has to be imported into pkappa2 beforehand.
    - Import all pcaps pkappa2 has seen: `for f in /tmp/pkappa2/*.pcap; do python p0f.py $f; done`

```
pip install -r requirements.txt
wget https://lcamtuf.coredump.cx/p0f3/releases/p0f-3.09b.tgz
tar xfz p0f-3.09b.tgz
cp p0f.fp p0f.py p0f-3.09b
cd p0f-3.09b
./build.sh
python ./p0f.py path/to/some.pcap
```
