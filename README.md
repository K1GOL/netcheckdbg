# netcheckdbg

netcheckdbg is a tool for checking and debugging netowrk connectivity. It checks for possible points of failure that may lead to connectivity issues. It can also generate route traces and then test each hop as part of network testing.

```
$ python3 netcheckdbg.py -n -r wikipedia.org
--- netcheckdbg ---
v 1.0.0
2025-05-01 17:13:00.289144
kali
---

╭ Checking interfaces
├ Found interface lo:
│   Address 127.0.0.1/255.0.0.0
│   Address 127.0.0.1/255.0.0.0
├ Found interface eth0:
│   Address 192.168.0.244/255.255.255.0
│   Address 192.168.0.244/255.255.255.0
╰ ✓ Success
╭ Checking gateway configuration
├ For interface eth0:
│   192.168.0.1 (Default)
╰ ✓ Success

...

╭ Checking DNS name resolution
├ Testing name resolution for wikipedia.org
│   Resolved with host 185.15.59.224
╰ ✓ Success
╭ Checking internet reachability
├ Testing wikipedia.org reachability
│   ICMP reachable
│   Testing TCP
│     Socket has local address 192.168.0.244:52294
│     TCP port 80 reachable
│   HTTP reachable
╰ ✓ Success
```

## Installation

Install from the provided Python wheel:

`python3 -m pip install netcheckdbg-*.whl`

[Releases](https://github.com/K1GOL/netcheckdbg/releases)

## Usage

Note ICMP ping based tests will only work with elevated privileges!

Start

`python3 netcheckdbg.py`

Skip default test hosts, use `example.com`

`python3 netcheckdbg.py -n -r example.com`

Generate a route trace to example.com

`python3 netcheckdbg.py -g example.com > trace.txt`

Test a specific route trace

`python3 netcheckdbg.py -t trace.txt`

Help page:
```
options:
  -h, --help            show this help message and exit
  -r, --test-remote TEST_REMOTE
                        Test connection to specific remote host
  -n, --no-default      Do not use default test hosts
  -t, --trace-file TRACE_FILE
                        Test a specific traced route to a remote host using a trace file
  -g, --gen-trace GEN_TRACE
                        Generate a new trace file for a given remote host, skips network checks
```

## Development

Install dependencies

`python3 -m pip install -r requirements.txt`

Build

`./build.sh` or `python3 -m build --wheel`