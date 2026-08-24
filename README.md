# tcpsweep

A netcat-style TCP connect sweep in a single, dependency-free Python file.

`tcpsweep` sends the same probe as `nc -z` (a full TCP connect) to every
host/port in a target spec and reports which ports are open. It uses the
standard library only, so it can be dropped onto any box with a Python 3
interpreter and run directly (`./tcpsweep.py ...`) or as a module
(`python3 -m tcpsweep ...`).

Discovered open ports stream to **stdout** (one `IP PORT` line each) so the
tool composes in a pipeline; progress and the summary go to **stderr**.
Results are also written to `NAME.json` and `NAME.gnmap` plus a resumable
`NAME.state.json` — all written atomically and owner-readable only (`0600`),
since a scan result is sensitive reconnaissance data.

> **Authorized use only.** Only scan hosts and networks you own or have
> explicit permission to test.

## Install

```sh
pipx install tcpsweep      # isolated, recommended for a CLI tool
pip install tcpsweep       # or a plain pip install
```

Both provide a `tcpsweep` command on your `PATH`. The tool has no third-party
dependencies, so you can also just copy `tcpsweep.py` onto a host and run it.

## Requirements

- Python 3.8+ (standard library only — no third-party packages)

## Usage

```sh
tcpsweep 192.168.1.1 22 80 443
tcpsweep 192.168.1.0/24 -p 22,80,443 -t 16
tcpsweep 10.0.0.{1-10,254} -p 1-1024 -r -o office
tcpsweep 192.168.1.1 -p 1-65535 -w 2 -P 0.2        # rate-limited, 0.2s gap
tcpsweep 10.0.0.0/24 -p 22 -b                        # grab banners
```

Run `tcpsweep --help` for the full option list, including target selection
(CIDR / dash ranges / brace notation / `-iL` target files / `--exclude`),
threading, rate limiting, link-health auto-pause, and the various output
formats (`-oJ` / `-oX` / `-oT` / `-oC` / `-oA`).

## Running through proxychains

A TCP connect scan is exactly the kind of scan that survives a SOCKS proxy, so
`proxychains4 tcpsweep ...` works — with two caveats the tool now warns about.

```sh
proxychains4 -q tcpsweep 10.0.0.0/24 -p 22,80,443 -t 4
```

**`-w/--timeout` is advisory.** proxychains performs the SOCKS handshake inside
its hooked `connect()`, so *its* `tcp_connect_time_out` and `tcp_read_time_out`
(in `/etc/proxychains4.conf`, milliseconds) decide how long a dead target
costs. Set them at or below your `-w`, or a silently-dropped port stalls for
their duration instead of yours.

**`closed` is inferred from timing, not just errno.** When a target is dropped,
proxychains gives up on its own timeout and reports `ECONNREFUSED` — identical,
by errno, to a real refusal. `tcpsweep` therefore treats a refusal that took
longer than the whole connect budget as `filtered` rather than `closed`, since
a RST arrives in about one round trip. Without that, firewalled ports get
recorded as definitively closed, which is the worst error a port scanner can
make.

Two more things worth knowing:

- With `proxy_dns` enabled, a **hostname** target resolves to a synthetic
  `224.0.0.x` placeholder. The scan reaches the right host, but results are
  labelled with that placeholder — scan a literal IP if the report needs real
  addresses. `tcpsweep` warns when it sees one.
- Keep `-t` low (1–4). proxychains' hooks serialise on a single chain, so more
  threads add contention rather than speed.

## Output files

By default the scanner writes working files named after the target (or the
`-o NAME` base):

| File               | Contents                                  |
| ------------------ | ----------------------------------------- |
| `NAME.json`        | Structured results for this scan          |
| `NAME.gnmap`       | Greppable, nmap-style summary             |
| `NAME.state.json`  | Resume state for an interrupted scan      |

These files hold reconnaissance data and are excluded from version control via
`.gitignore`.

**Only an unfinished scan is resumed.** If a previous run completed, its state
file is left in place but not replayed — every port is probed again, and a
warning says so. Resuming a finished scan would report ports as open without
sending a packet, which is indistinguishable from a live result. A scan that
was Ctrl+C'd, crashed, or was killed still resumes; `--fresh` discards the
state file entirely.

Every reported figure — the `.json`, the `.gnmap`, the exported reports and
the summary counts — covers only the hosts and ports of the run that produced
it, even when a state file carries results from a wider earlier scan.

## Development

Run the test suite with:

```sh
python3 -m pytest test_scan.py -q     # or: python3 -m unittest test_scan
```
