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
of negatives, and once more when the sweep ends, so the last stretch of results
is not believed on no evidence — provided there is a control target to ask (an
open port found along the way, or yours). If it has stopped answering, every unverified
result is **withdrawn and re-run**, and if the chain never returns the tool
exits `3` rather than reporting a tidy, wrong, empty result. A control target
that keeps dropping without anything being proven in between (ten times
running) ends the run the same way instead of going round for ever.

This is chain policing, so it applies under a proxy — or whenever you name a
`--canary`. A direct scan has no chain to police: a refusal is the target's own,
and treating a service that stops answering as "chain down" would only turn a
one-shot listener or an IPS ban into a two-minute wait. Direct results are
trusted, and journalled, as they arrive.

**A proxy can also lie.** A canary proves the chain is *alive*; it cannot
prove it is *honest*. Some SOCKS servers answer every `CONNECT` with success
regardless of the target — every port on every host then reads as open, the
canary passes trivially, and the scan looks perfect while being entirely
fabricated. Observed on a real chain: `192.0.2.1`, an RFC 5737 address that
cannot be routed, came back open on 22, 80 and 12345 alike.

So tcpsweep probes an address that must never be connectable, in parallel with
the sweep. If it answers, the run stops and exits `3` with every result marked
untrustworthy. This is the failure mode behind the classic "the scanner said
port 80 was open but curl times out" — `-b` exposes it for protocols that speak
first, like SSH, but HTTP never speaks first.

Nothing is written to stdout or to the `--resume` journal until that probe has
concluded, so a `| while read` pipeline never acts on a fabricated hit and a
later resume never replays one. The price is that, on an honest chain, output is
released the moment the probe concludes — about one `tcp_read_time_out` after
the start — instead of at once. If the probe never concludes, open ports are
shown with a warning but nothing is journalled, since a journal is replayed
without being probed again. Ctrl+C, SIGTERM and SIGHUP flush what is held; a
`kill -9` inside that window loses it. `--no-sanity` skips the probe and
streams immediately; the `chain_sanity` field of `--json` records how the check
ended (`passed`, `failed`, `unconfirmed` or `skipped`).

## Efficiency

Through a chain the cost model is lopsided: an open port and a fast negative
are nearly free, while a stalled probe costs the entire read timeout. Sweep
time is therefore dominated by stalls.

So a multi-host sweep runs a short **discovery pass** first. Hosts that answer
anything — open *or* a fast negative — are kept, because sweeping them is
cheap. Hosts where every discovery probe stalled are skipped, because those are
exactly the ones that would burn the full timeout on every port. Discovery
results are reused, never re-probed, and discovery only uses ports you asked
for: `-p 445` costs one probe per host, not six. The liveness ports default to
`80,443,22,3389,445,8080` where `-p` includes them, and to the first few of your
list where it does not; `--discover-ports` names them explicitly.

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
is final even if the run is interrupted. Under a proxy, open ports are held back
until the honesty probe has concluded (see above).

## Scanning over `ssh -D`

A dynamic forward is a SOCKS5 proxy, so it works with proxychains as is
(`socks5 127.0.0.1 1080` in `proxychains.conf`):

```sh
ssh -fN -D 1080 pivot
proxychains4 tcpsweep 10.0.0.0/24 -p 22,80,443
```

**Quieting the log flood.** Every closed port makes ssh log `channel N: open
failed: connect failed: Connection refused`, and proxychains prints a
`[proxychains] ... <--socket error or timeout!` line for every failed connect.
On a /24 that buries the results. They are only messages — a loopback test gave
identical results with them muted:

```sh
ssh -fN -D 1080 -o LogLevel=ERROR pivot        # no "channel N: open failed" lines
proxychains4 -q tcpsweep 10.0.0.0/24           # or `quiet_mode` in proxychains.conf
```

`ssh -D` reports what the remote `connect()` really did, so it is an honest
chain: if you trust the tunnel, `--no-sanity` skips the fabrication probe and
lets open ports stream at once instead of after about one read timeout.

**Or scan from the pivot.** tcpsweep is a single, dependency-free file, so ssh
can feed it straight to the pivot's Python — nothing to install or copy:

```sh
ssh pivot python3 - 10.0.0.0/24 -p 22,80,443 -w 1 -c 128 < tcpsweep.py | tee found.txt
```

Open ports stream back on stdout, progress and the summary on stderr, and the
exit code passes through (`0` found, `1` nothing open; `255` is ssh itself
failing). Nothing is forwarded, so there is nothing to log and no per-probe
round trip through the tunnel. The scan also runs *direct*: `-w` applies, and
closed versus filtered comes from the real `errno` rather than from timing
alone — through a tunnel, refused, unreachable and denied all look alike — and
with no chain to police, results are trusted and journalled as they arrive. The
targets see the same thing either way, connects from the pivot, so this changes
where the noise lands and how fast the sweep goes, not what is sent; use
`--rate` if your rules of engagement cap it.

- Needs python3 (3.8+) and command execution on the pivot. A forwarding-only
  account will not do; use the quiet tunnel above.
- stdin carries the script, so `-iL -` cannot be used. Pass CIDRs as arguments,
  or `-iL FILE` with a file that is on the pivot.
- If the SSH session drops, the run carries on: writes to the vanished stdout
  and stderr are ignored, a SIGHUP is treated like Ctrl+C (it stops the sweep and
  writes the report), and `--json` and `--resume` files are still written. With
  neither of them the findings have nowhere to go, so add one to long sweeps.
  Both files live on the pivot and hold scan results: `scp` them back and delete
  them.
- With `| tee`, `$?` is tee's. Read the tool's status from `${PIPESTATUS[0]}`
  (bash; `$pipestatus[1]` in zsh) or use `set -o pipefail`.

**Saving results.** stdout is the finding list, so `| tee found.txt` keeps it.
`--json out.json` writes the full structured report (atomically, `0600`), and
`--resume sweep.jsonl` journals as it goes.

## Resuming an interrupted sweep

With a 30s `tcp_read_time_out`, a wide sweep runs for hours, so losing it to
one Ctrl+C is not acceptable. `--resume FILE` journals the sweep as it goes
and, on a re-run, skips what the file already holds:

```sh
proxychains4 tcpsweep 10.0.0.0/16 -p 445 --resume sweep.jsonl
# ^C, or the box reboots, or the chain dies
proxychains4 tcpsweep 10.0.0.0/16 -p 445 --resume sweep.jsonl   # picks up where it stopped
```

Each line is flushed as it is written. The journal holds only what the chain
has **vouched for**: an open port goes in as soon as the honesty check allows
(at once when scanning direct or with `--no-sanity`), because it is its own
proof, but a negative is written only once a later open port or control-target probe
shows the chain was alive after it. So an interruption — or a chain that died a
moment before one — costs the negatives since the last proof (fewer than
`--canary-after` of them) and they are probed again, instead of being carried
forward as fake "closed" results. The other side of that: a sweep with no
canary and no open port has proven nothing and journals no negatives, so pass
`--canary` for long sweeps. Like stdout, the journal is not written until the
honesty probe has concluded, so a fabricating proxy leaves nothing to replay.
Open ports are re-emitted to stdout on a resumed run, so a pipeline still sees
the complete finding set.

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
| `3` | the run cannot be trusted: the chain failed and never came back, the proxy fabricates connections, probes could not be sent, or the tool itself crashed |
| `130` | interrupted (Ctrl+C, SIGTERM or SIGHUP; a second Ctrl+C aborts at once, without the report) |

`0`/`1` are grep-style, so `if tcpsweep ...; then` branches on "found
something". `3` is the one that matters for automation: it means *don't
believe this run*.

## Notes

- **IPv4 only**, deliberately: proxychains handles IPv4 TCP, and silently
  scanning something else would be worse than refusing.
- With `proxy_dns`, a hostname resolves to a synthetic placeholder — `224.0.0.x`
  by default, or an address in the `remote_dns_subnet` the config names. The
  sweep reaches the right host but results are labelled with that address;
  tcpsweep warns when it sees one. Scan literal IPs if the output matters.
- Through a chain, `closed` only means the proxy answered fast — it cannot be
  told apart from host-unreachable or a ruleset denial. The summary says so.
- `--json` output is written atomically and `0600`, since scan results are
  sensitive, and the path is checked before the sweep starts rather than after
  it (a directory is refused). A link to a regular file is replaced, not followed, so a symlink planted
  where the report goes cannot make the tool overwrite something else; a pipe,
  a tty or a device is written into, and nothing directly under `/dev` is ever
  replaced.
- The proxy is detected by the hook itself (`LD_PRELOAD`, or the library being
  mapped into the process), not by `PROXYCHAINS_CONF_FILE` alone: a stale
  exported variable with no hook runs direct, and says so, instead of having
  direct connects classified as proxied.
- A target the resolver would read as a *different* address is refused rather
  than resolved: `010.0.0.1` is octal for 8.0.0.1 and `192.168.1` is
  192.168.0.1 — so an address must be written out in full, without leading
  zeros, whichever Python you run (older `ipaddress` versions accept them).
  Under `proxy_dns`, `--exclude` by hostname is refused too — the name resolves
  to a placeholder that can never match a real target, so the exclusion would
  silently do nothing — and so is any `--exclude` while a *target* is a hostname:
  its placeholder cannot be matched by an address either. Give addresses.
- Ctrl+C, SIGTERM and SIGHUP stop the sweep and write the report. A signal that
  is already set to be ignored stays ignored: `nohup` does that to SIGHUP, so a
  `nohup` sweep still outlives its terminal.
- `-c` beyond the file-descriptor limit raises the limit as far as the hard
  limit allows and otherwise lowers `-c` with a warning. Under proxychains each
  in-flight probe holds *two* descriptors (it dials the chain on a second
  socket), and running short makes the hook's own `socket()` fail — which the
  scanner sees as an instant refusal, a fake "closed" — so the budget counts
  both. A probe that cannot even get a socket is retried, then reported missing
  and the run exits `3`; it is never recorded as a stall, and a run of them
  stops the sweep.
- A crash exits `3`, not Python's `1` (which here means "nothing open"), and a
  closed stdout no longer changes the exit status either.
- Banners (`-b`) are reduced to printable ASCII before they touch your terminal
  or the JSON.

## Development

```sh
python3 -m pytest test_scan.py -q
```

The suite needs no root and no network beyond loopback, and it never writes
under `/dev`. Run it as an ordinary user.
