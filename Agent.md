# tcpsweep — design notes

Single file, standard library only, IPv4 TCP connect sweep built for
proxychains. `tcpsweep.py` is the whole tool; `test_scan.py` is the suite.

The point of this document is the *why*. The code says what it does.

---

## The measurements everything rests on

Taken against a SOCKS5 server that can produce every failure mode on demand
(`tcp_read_time_out 4000`, `tcp_connect_time_out 3000`, app-level
`settimeout(1.0)`):

| SOCKS outcome | Python sees | elapsed |
| --- | --- | --- |
| success | connected | 0.01s |
| 0x05 refused | `ECONNREFUSED` | 0.00s |
| 0x04 host unreachable | `ECONNREFUSED` | 0.00s |
| 0x03 network unreachable | `ECONNREFUSED` | 0.00s |
| 0x02 denied by ruleset | `ECONNREFUSED` | 0.00s |
| 0x01 general failure | `ECONNREFUSED` | 0.00s |
| proxy accepts then closes | `ECONNREFUSED` | 0.00s |
| proxy hangs | `ECONNREFUSED` | 4.00s |
| proxy process dead | `ECONNREFUSED` | 0.00s |

Concurrency, 16 stalling probes: 1 worker 64.07s, 4 workers 16.02s, 16 workers
4.01s — linear, no serialisation inside the hook.

Three conclusions:

1. **errno is information-free.** Only elapsed time distinguishes outcomes.
2. **`settimeout()` never fired.** 4.00s is exactly `tcp_read_time_out`; the
   chain owns the budget.
3. **A dead proxy is byte-identical to a closed port.** Nothing local can tell
   them apart without an external reference.

---

## Architecture

```
Proxy.detect()  read LD_PRELOAD / PROXYCHAINS_CONF_FILE, parse the config
     |          -> chain mode, proxy count, proxy_dns, the real timeouts
     v
collect_targets()  CIDR / dash / brace / hostname / -iL, minus --exclude
     v
Prober             one connect() -> open | closed | filtered, by timing
     v
Sweep.run()        worker pool, rate limit, pause gate, canary, epochs
     v
Report / Stream / Progress
```

### `Proxy`

`tcp_read_time_out` is read, not guessed, because it *is* the probe budget.
`stall_threshold = read_ms / 2` splits the two populations: definitive answers
arrive in microseconds, stalls land on `read_ms` exactly. Half leaves a wide
margin even on a slow multi-hop chain. `budget = connect_ms + read_ms` is the
worst case a probe can occupy a worker, and sets the socket-level ceiling
(`budget * 1.5`) — high enough never to pre-empt a real answer, low enough to
catch a genuinely wedged connection.

### `Prober`

Pure function of `(exception, elapsed)`. Proxied: everything is
`ECONNREFUSED`, so timing decides. Direct: errno is meaningful again and is
used, with the timing rule kept as a backstop. It is a callable class so the
tests can substitute a scripted one and dictate chain behaviour exactly instead
of racing a real proxy.

### `Sweep` — the trust model

Negatives are believed only as far as the last proof the chain works.

- The first open port **arms the canary** automatically; `--canary` supplies
  one up front for sweeps that may legitimately find nothing.
- After `--canary-after` consecutive non-open results, the canary is re-probed.
- If it fails: every negative since the last confirmation is **revoked** from
  the report and re-queued, workers pause, and the chain is retried with
  backoff up to `--chain-wait`.
- If it never returns: `chain_broken`, the sweep stops, exit `3`. Continuing
  would record every remaining probe as `closed` and produce a clean-looking
  empty result — the worst possible failure for this tool.

**Epochs.** `_guarded` captures `self.epoch` before probing; an outage bumps
it. A result whose epoch no longer matches spanned the outage and is re-queued
rather than recorded. Without this, connects already inside the hook when the
proxy died would land as `closed` after recovery.

Only open ports reach stdout, and an open port is never revoked — so stdout is
append-only and final even mid-outage. Revocation only ever touches negatives.

### Discovery / `triage`

The cost model is lopsided: open and fast-negative are ~free, a stall costs the
whole read timeout. So sweep time ≈ stalls × timeout ÷ concurrency, and the
optimisation is to issue fewer stalls.

Triage rule, chosen to match that:

- any **open** → sweep the host
- any **fast negative** → sweep it; the chain answers cheaply for this host
- **all stalls** → skip; every port would cost the full timeout

Note what this deliberately does *not* do: it never treats a fast negative as
proof the host is up. Through a chain it may be the proxy refusing, not the
host. The summary says "responsive", not "up".

Discovery results are recorded as real results and excluded from the sweep
phase via `Report.probed()` — no pair is ever probed twice.

Measured, 8 hosts / 4 black-holed / 3 ports: 4.1s with discovery vs 8.1s
without, identical findings.

---

## Deliberate omissions

Removed in the 0.3.0 rewrite, and why:

- **Resume / state files.** The single largest source of bugs in 0.1.x: a
  completed scan left its state behind and the next run replayed it, reporting
  ports open without sending a packet. Streaming stdout gives durability
  (`| tee`) with none of the staleness surface.
- **XML / CSV / txt / gnmap renderers.** Four serialisers for one dataset.
  stdout is the greppable format; `--json` is the structured one.
- **Alternate-screen dashboard.** It discarded its own contents at exit,
  including warnings, which is how a silent resume went unnoticed for so long.
  Progress is now one `\r` line on stderr, or periodic lines when piped.
- **Per-host pacing, dual gap flags.** `--rate` covers the real need; through a
  chain the global rate is what the proxy notices.

---

## Invariants worth preserving

- `Report`/`Stream`/`Progress` are touched only from the main thread — results
  are consumed in `Sweep.run`'s loop — so none of them need locks. Keep it that
  way rather than adding them back.
- `RateLimiter.take` and the pause gate both take `stop`, so Ctrl+C is
  immediate; a connect already inside the hook cannot be cancelled and runs to
  the chain's timeout, which `run`'s teardown reports rather than hiding.
- `clean()` is a security control, not cosmetics: banners are attacker
  controlled and reach both a terminal and the JSON.
- `--json` is written atomically at `0600`.
- IPv4 only, enforced with a clear error. proxychains is IPv4 TCP.

## Tests

`test_scan.py`, 68 tests, no network required beyond loopback. The proxy paths
are covered by scripting `ScriptedProber` rather than standing up a proxy, so
chain death, revocation, epoch invalidation and the `--chain-wait` deadline are
deterministic. Run with `python3 -m pytest test_scan.py -q`.
