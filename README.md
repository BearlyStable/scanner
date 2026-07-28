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

## Output files

By default the scanner writes working files named after the target (or the
`-o NAME` base):

| File               | Contents                                  |
| ------------------ | ----------------------------------------- |
| `NAME.json`        | Full structured results                   |
| `NAME.gnmap`       | Greppable, nmap-style summary             |
| `NAME.state.json`  | Resume state for an interrupted scan      |

These files hold reconnaissance data and are excluded from version control via
`.gitignore`.

## Development

Run the test suite with:

```sh
python3 -m pytest test_scan.py -q     # or: python3 -m unittest test_scan
```
