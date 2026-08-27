# tcpsweep

A TCP connect sweep built for **proxychains**, in a single dependency-free
Python file.

```sh
proxychains4 tcpsweep 10.0.0.0/24 -p 22,80,443
```

A connect scan is the only kind of scan that survives a SOCKS proxy — no raw
sockets, no SYN, no ICMP — so it is the right primitive. But a connect scan
*through* a proxy behaves nothing like a direct one, and most scanners report
confidently wrong results because of it. This tool is designed around the
difference.

> **Authorized use only.** Only scan hosts and networks you own or have
> explicit permission to test.

## What running through a chain actually does

These are measured against a fault-injecting SOCKS5 server, not assumed:

| SOCKS outcome | what Python sees | elapsed |
| ------------- | ---------------- | ------- |
| success | connected | 0.01s |
| refused (0x05) | `ECONNREFUSED` | 0.00s |
| host unreachable (0x04) | `ECONNREFUSED` | 0.00s |
| network unreachable (0x03) | `ECONNREFUSED` | 0.00s |
| denied by ruleset (0x02) | `ECONNREFUSED` | 0.00s |
| general failure (0x01) | `ECONNREFUSED` | 0.00s |
| proxy hung | `ECONNREFUSED` | **= `tcp_read_time_out`** |
| **proxy dead** | `ECONNREFUSED` | 0.00s |

Three consequences drive the whole design:

**`errno` carries no information.** Everything is `ECONNREFUSED`. Only *elapsed
time* separates a definitive answer from a black hole, so every classification
here is time-based. A negative that came back instantly is the chain's real
answer; one that consumed half the read timeout or more is a stall, and is
reported `filtered` rather than `closed`.

**Your timeout is inert.** The SOCKS handshake happens inside proxychains'
hooked `connect()`, so `settimeout()` does not bound a probe — the config's
`tcp_read_time_out` does. tcpsweep reads the live config and shows the real
budget instead of pretending `-w` applies. Raise `-c` to go faster, not
lower `-w`.

**A dead proxy is identical to "everything closed."** Both are an instant
`ECONNREFUSED`. Without a control target a sweep cannot tell a clean negative
result from a broken chain, so tcpsweep keeps a canary — the first open port
it finds, or one you name with `--canary` — and re-probes it after a long run
of negatives. If it has stopped answering, every unverified result is
**withdrawn and re-run**, and if the chain never returns the tool exits `3`
rather than reporting a tidy, wrong, empty result.

**A proxy can also lie.** A canary proves the chain is *alive*; it cannot
prove it is *honest*. Some SOCKS servers answer every `CONNECT` with success
regardless of the target — every port on every host then reads as open, the
canary passes trivially, and the scan looks perfect while being entirely
fabricated. Observed on a real chain: `192.0.2.1`, an RFC 5737 address that
cannot be routed, came back open on 22, 80 and 12345 alike.

So tcpsweep probes an address that must never be connectable, in parallel with
the sweep. If it answers, the run stops and exits `3` with every result marked
untrustworthy. `--no-sanity` skips it. This is the failure mode behind the
classic "the scanner said port 80 was open but curl times out" — `-b` exposes
it for protocols that speak first, like SSH, but HTTP never speaks first.

## Efficiency

Through a chain the cost model is lopsided: an open port and a fast negative
are nearly free, while a stalled probe costs the entire read timeout. Sweep
time is therefore dominated by stalls.

So a multi-host sweep runs a short **discovery pass** first. Hosts that answer
anything — open *or* a fast negative — are kept, because sweeping them is
cheap. Hosts where every discovery probe stalled are skipped, because those are
exactly the ones that would burn the full timeout on every port. Discovery
results are reused, never re-probed.

Measured against 8 hosts where 4 black-hole everything: **4.1s with discovery,
8.1s without**, identical findings. The gap widens with more ports per host.

Concurrency is the one lever that matters, and it scales linearly (16 stalling
probes: 64.1s serial → 4.0s at `-c 16`).

## Install

```sh
pipx install tcpsweep      # isolated, recommended
pip install tcpsweep
```

No third-party dependencies, so you can also just copy `tcpsweep.py` onto a
host. It identifies itself by whatever name you invoke it under.

## Usage

```sh
proxychains4 tcpsweep 10.0.0.0/24                  # top 20 ports, discovery on
proxychains4 tcpsweep 10.0.0.0/16 -p 445 -c 64     # one port, wide, fast
proxychains4 tcpsweep 10.0.0.5 -p 1-1024 --no-discover
proxychains4 tcpsweep -iL targets.txt -p 22,80 --canary 10.0.0.1:22
tcpsweep 10.0.0.0/24 -p 80 --json out.json         # direct, no proxy
```

Targets accept `10.0.0.1`, `10.0.0.0/24`, `10.0.0.1-20`, `10.0.0.{1,5-9}`,
hostnames, `-iL FILE` (`-` for stdin) and `--exclude`. Run `--help` for the
full option list.

Open ports stream to **stdout** as `host port`, flushed, so the tool pipes:

```sh
proxychains4 tcpsweep 10.0.0.0/24 -p 445 | tee found.txt | while read ip port; do
  echo "hit $ip:$port"
done
```

Progress, warnings and the summary go to **stderr**, so they never contaminate
the pipeline. An open port is never withdrawn, so anything that reaches stdout
is final even if the run is interrupted.

## Resuming an interrupted sweep

With a 30s `tcp_read_time_out`, a wide sweep runs for hours, so losing it to
one Ctrl+C is not acceptable. `--resume FILE` journals every probe as it
completes and, on a re-run, skips what the file already holds:

```sh
proxychains4 tcpsweep 10.0.0.0/16 -p 445 --resume sweep.jsonl
# ^C, or the box reboots, or the chain dies
proxychains4 tcpsweep 10.0.0.0/16 -p 445 --resume sweep.jsonl   # picks up where it stopped
```

Each line is flushed as it is written, so an interruption loses at most the
probes that were in flight. Open ports are re-emitted to stdout on a resumed
run, so a pipeline still sees the complete finding set.

Resume is **never automatic** — there is no default path and no
auto-discovery. An earlier version resumed whatever state file sat next to the
output name, which meant a *finished* scan's results were replayed as though
they were live, reporting ports open with no packet sent. Here you name the
file, and the number of carried results is printed where you cannot miss it.

Carried results are scoped to the current run (a journal from a wider sweep
cannot smuggle in hosts you did not ask about), a journal over a day old draws
a warning, and carried results never count as proof the chain works — that has
to be earned by a live probe.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | completed, at least one open port |
| `1` | completed, nothing open |
| `2` | bad arguments |
| `3` | the chain failed and never came back — results are not trustworthy |
| `130` | interrupted |

`0`/`1` are grep-style, so `if tcpsweep ...; then` branches on "found
something". `3` is the one that matters for automation: it means *don't
believe this run*.

## Notes

- **IPv4 only**, deliberately: proxychains handles IPv4 TCP, and silently
  scanning something else would be worse than refusing.
- With `proxy_dns`, a hostname resolves to a synthetic `224.0.0.x` placeholder.
  The sweep reaches the right host but results are labelled with that address;
  tcpsweep warns when it sees one. Scan literal IPs if the output matters.
- Through a chain, `closed` only means the proxy answered fast — it cannot be
  told apart from host-unreachable or a ruleset denial. The summary says so.
- `--json` output is written atomically and `0600`, since scan results are
  sensitive.
- Banners (`-b`) are reduced to printable ASCII before they touch your terminal
  or the JSON.

## Development

```sh
python3 -m pytest test_scan.py -q
```
