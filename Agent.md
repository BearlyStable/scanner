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
Proxy.detect()  is the hook loaded? (LD_PRELOAD / mapped library), parse the config
     |          -> chain mode, proxy count, proxy_dns, the real timeouts
     v
collect_targets()  CIDR / dash / brace / hostname / -iL, minus --exclude
     v
Prober             one connect() -> open | closed | filtered, by timing
     v
Sweep.run()        worker pool, rate limit, Gate (pause + epoch), canary,
     |             proof of the tail
     v
Report / Holdback -> Stream + Journal / Progress
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

Failing to get a socket (out of file descriptors) is deliberately *not* caught
here. It says nothing about the target, so it has to reach `Sweep` as an error
rather than be dressed up as a result -- see "A probe that never happened".

### `Sweep` — the trust model

Negatives are believed only as far as the last proof the chain works.

- `--canary`/`--ct` is **authoritative**: it is probed once at startup (a dead
  one is a usage error, not a mid-sweep surprise) and is never displaced by a
  discovered port. The previous design picked `known_open or check_targets`, so
  the first open port it stumbled on replaced the operator's target -- and a
  random junk service ended up deciding whether the chain was alive, then hung
  the run when it stopped answering.
- With no explicit target, open ports auto-arm as canaries, up to
  `AUTO_CANARY_LIMIT`, so one flaky host cannot convince the sweep that a
  healthy chain has died.
- After `--canary-after` consecutive non-open results, the canary is re-probed.
- **And once more when the queue drains** (`_prove_tail`). The periodic check
  only fires on a full streak, so whatever trailed the last proof -- up to
  `canary_after - 1` negatives, or the whole run if it is short -- was believed
  with nothing behind it; a default one-host run never checked at all. A chain
  that died just before the last probe answers exactly like a closed port, and
  `--canary`'s startup probe used to make the run claim `chain_verified`
  whatever happened afterwards. The check is skipped when the last result was
  an open port (its own proof) and when there is nothing to ask (no canary).
- If it fails: every negative since the last confirmation is **revoked** from
  the report and re-queued, workers pause, and the chain is retried with
  backoff up to `--chain-wait`.
- If it never returns: `chain_broken`, the sweep stops, exit `3`. Continuing
  would record every remaining probe as `closed` and produce a clean-looking
  empty result — the worst possible failure for this tool.
- **Outages must make progress.** A control target that answers just long enough
  to be let back in, then stops again, proves nothing and used to send the sweep
  round for ever (one connect per few seconds is enough to do it). More than
  `OUTAGE_PATIENCE` (ten) outages in a row with nothing proven in between end the
  run as broken. A flaky tunnel that recovers and then proves something resets the
  count, so a long sweep over a bad link is not punished for being long. Three
  was tried first and was too twitchy: a control target that merely dropped a
  quarter of its checks aborted 16 of 40 long, perfectly healthy sweeps. Ten
  still ends the rate-limited-canary loop, in about ten cycles.
- **Direct scans are not policed.** All of the above is chain policing, and a
  direct scan has no chain. A refusal is the target's own, and treating a
  service that stops answering -- a one-shot listener, an IPS that starts
  dropping the scanner, a crash -- as "chain down" turned a clean 0.1 s scan into
  a two-minute wait and exit `3` (auto-armed canaries are just open ports found
  along the way). `Sweep(police=proxy.active)`: without it, results are trusted
  and vouched the moment they arrive, so the journal is written as the scan goes.
  An explicit `--canary` is a request for the machinery and switches it on.

Each time the chain proves itself (an open port, a passed canary probe) the
engine hands the negatives since the last proof to a `vouch` callback before
clearing them. That callback is how the journal learns what it may believe.

**A probe that never happened.** An exception out of the prober -- no socket,
a bug -- produced no answer, so none may be recorded. The old fallback wrote it
down as a zero-second `filtered` result: journalled, and if it was a host's only
discovery probe, enough for triage to skip the whole host as black-holed. Now
the probe is retried (`PROBE_ATTEMPTS`) and then put on `sweep.lost`; the
summary says so and the run exits `3`, because a negative result with holes in
it must not read as clean. The retry backs off on a *worker* -- sleeping on the
main thread froze every other result behind one failing probe -- and
`LOST_LIMIT` unsendable probes stop the sweep, because every probe failing is
not bad luck and grinding through the rest would take hours to say so.

**What "verified" means.** `chain_verified` says the chain answered live at some
point (the caveat under a proxy keys on it); an abandoned run is reported
beside it as `chain_broken`, and the JSON's `chain_verified` is only true when
both hold.

**Descriptors.** `fit_concurrency` makes all this rare, and it has to count
right: under proxychains each in-flight probe holds *two* sockets (the hook dials
the chain on a second one and dup2s it over the first), and when the hook's own
`socket()` fails the scanner sees an instant ECONNREFUSED -- a fast, definitive
"closed" that nothing flags, that the canary check cannot catch (the canary probe
has descriptors to spare) and that gets vouched and journalled. Measured: soft
limit 1024, `-c 800`, 800 real listeners -> ten journalled `closed`. So the
budget is `open fds + reserve + probes x per-probe`, with the soft limit raised
as far as the hard one allows and `-c` clamped with a warning where it cannot be.

### Chain honesty

The canary answers "is the chain alive". It cannot answer "is the chain
truthful", and a proxy that returns success for every `CONNECT` passes it
trivially while making every port look open. Measured on a real chain:
`192.0.2.1:22`, `:80` and `:12345` all reported open, and only a banner grab
(`-b`) told a real SSH host from a fabricated one -- which does not help for
HTTP, since it never speaks first.

`start_sanity_probe` therefore probes RFC 5737 TEST-NET-1, which must never be
routable. A success there is proof of fabrication, so the sweep stops and exits
`3`. It runs on its own threads so a long sweep pays nothing for it -- one per
target, side by side, so the verdict is one probe budget away rather than one
per target. `verdict["checked"]` is true only if every probe was actually asked
and answered without a success; a probe that raised leaves it false, and the
JSON says `unconfirmed` rather than `passed`.

**`Holdback`: nothing is reported before the verdict.** `await_sanity` used to
gate only the summary and the JSON. Open ports were streamed to stdout, and every
result journalled, the moment they arrived -- so a `| while read` pipeline
could act on a fabricated hit before the run ever exited `3`, and a later
`--resume` replayed the fiction without probing it again. The `Holdback` sits
between the engine and the two outputs that outlive the process. Results wait in
it in arrival order and are released when the verdict is in and honest, or
discarded for good if the chain is fabricating. Edge cases, each chosen on
purpose:

- **Unknown is shown, not journalled.** If the probe never concludes, holding
  on would lose real findings to a slow probe, which is the worse error, so open
  ports are shown with the "unconfirmed" warning. Nothing is *journalled*: a
  journal is replayed on resume without being probed again, and a chain that
  fabricates slowly (and an early Ctrl+C) would otherwise have its fiction
  replayed by an honest run.
- **Carried opens are held too.** A resumed run's stdout is only complete, and
  only trustworthy, once the chain has been judged, so `carry_over` emits
  through the gate.
- **Release is event-driven.** The sweep only calls into the gate when it has
  something to report and can go a whole read timeout -- or an outage -- between
  results, so a lone open port used to sit held until the sweep ended (and was
  lost outright to a SIGTERM). A watcher thread settles the gate the moment the
  verdict lands. That makes `Holdback` the one object shared with a thread: its
  lock guards the state, and every write to stdout or the journal goes through
  it, so held output is delivered in order before anything newer.
- **The wait is bounded and interruptible.** `await_sanity` gives the probes
  `budget + SANITY_GRACE` -- a probe stalls for one budget at most -- and
  shrinks to a second once `stop` is set, wherever in the wait Ctrl+C lands.
- **The price is latency.** Output appears about one read timeout after the
  start instead of at once, and a `kill -9` inside that window loses what was
  held. `--no-sanity` skips the probe (and so the wait); `ssh -D` is honest, so
  that is a reasonable choice for it.

**The gate and the epoch.** A worker stamps the epoch before probing; an outage
bumps it, and a result whose stamp no longer matches spanned the outage and is
re-queued rather than recorded. Without this, connects already inside the hook
when the proxy died would land as `closed` after recovery. The *order* of the
two halves is the whole trick, so they live together in `Gate`: a worker stamps
before it waits at the pause gate, and an outage closes the gate before it moves
the epoch. Stamp after the gate and bump before the close, and a probe can slip
between the two carrying the *new* epoch onto the dead chain -- 12 times in 1200
runs of a 16-worker stress test with a 1 µs thread-switch interval, invisible at
the default. Two ordering tests pin it (one drives the exact interleaving).

**Completion order.** A batch of finished probes is handled in the order they
*finished*, not submitted and not in the arbitrary order a set yields them. An
open port proves the chain was alive when it answered, so it may vouch only for
negatives that came back before it; handled in submission order, an open could
vouch a negative that returned after the chain had died, and the tail proof
would then be skipped as unnecessary.

Only open ports reach stdout, and an open port is never revoked — so stdout is
append-only and final even mid-outage. Revocation only ever touches negatives.

### The journal

`--resume` used to journal every result the moment it landed and journal the
revocations after it. That left two holes: the negatives recorded just before a
Ctrl+C -- or just before the chain died, which is often *why* the operator hit
Ctrl+C -- were carried into the next run as final, and a fabricating chain's
results outlived the run. The journal is now **write-behind**:

- an open port is written as soon as the honesty check allows (it is its own
  proof, and never withdrawn);
- a negative is written only when `vouch` says the chain proved itself after it;
- a negative that is withdrawn was never written, so there is nothing to undo;
- everything goes through `Holdback`, so nothing is written before the honesty
  verdict.

The cost is stated in the README: a sweep with no canary and no open port has
proven nothing, so it journals no negatives. Journals from earlier versions
still load -- including their `x` revocation lines -- and every line is
validated on the way in (wrong types and unknown states are dropped, banners
pass through `clean()`), because `--resume` may be pointed at anything.

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

**Discovery never leaves `-p`.** The pass reports what it finds, so it used to
widen the scan: `-p 445` on a /16 probed six ports per host and printed any of
80, 443, 22, 3389 or 8080 that were open -- six times the traffic and output
nobody asked for, which matters when a rules-of-engagement list names ports.
`default_discovery` now takes the liveness ports from the requested ones (the
familiar six where `-p` includes them, else the first few of the list). A list
given with `--discover-ports` is the operator's own decision and is used as
written.

Measured, 8 hosts / 4 black-holed / 3 ports: 4.1s with discovery vs 8.1s
without, identical findings.

### Getting out alive

- **A crash is not a result.** Python exits `1` on an uncaught exception, and `1`
  is "completed, nothing open"; `main()` wraps `_main()` and exits `3` ("do not
  believe this run") with the traceback and a warning.
- **stderr can vanish.** A dropped ssh session closes it, and the next warning,
  progress line or summary raised -- ending the run with no `--json` report and
  status 120. `Tolerant` wraps stderr for the run, `Stream.emit` ignores a dead
  stdout, and `_flush_quietly` -- run on *both* streams, because a failed write
  leaves its data in the buffer to fail again -- stops Python's exit-time flush
  from replacing the exit status (measured: exit 120 after a dropped reader,
  0 now). A scan whose stdout is gone and that has neither `--json` nor
  `--resume` still runs to the end (see Known limits).
- **Signals.** Ctrl+C, SIGTERM (`timeout`, service managers) and SIGHUP (a
  dropped ssh session with a terminal) all mean "stop and report what you have";
  the run exits `130` with its report. A signal the caller set to be ignored
  stays ignored: `nohup` does that to SIGHUP so that a sweep outlives its
  terminal, and handling it anyway turned "survive the logout" into "stop" (found
  by review; round one survived it). A second Ctrl+C is `os._exit`: a connect
  inside the hook cannot be cancelled and can take a whole read timeout to
  return, and the operator should not have to sit through it.

### Input you cannot trust

- **Numeric shorthand.** Anything that is not a plain dotted quad falls through
  to `getaddrinfo`, which follows `inet_aton`: `010.0.0.1` is octal for 8.0.0.1,
  `192.168.1` is 192.168.0.1, `0x7f.1` is 127.0.0.1. Scanning a different host
  from the one typed, silently, is refused (`_refuse_shorthand`). Only the
  canonical spelling of an address is trusted (`_is_canonical`): before Python
  3.8.12 and 3.9.5 `ipaddress` accepted leading zeros as decimal
  (CVE-2021-29921) while the connect that follows reads them as octal.
- **`--exclude` by hostname under `proxy_dns`** resolves to a placeholder that
  can never match a real target, so the exclusion did nothing and the excluded
  host was scanned. It is refused instead -- and so is *any* `--exclude` while a
  target is itself a hostname under `proxy_dns`, since that target is a
  placeholder no address can match. Which names are placeholders is recorded when
  they resolve, not guessed from the address, so a literal 10.x target stays
  excludable even with `remote_dns_subnet 10`. It fails closed even where a
  `remote_dns_subnet` guess could be wrong about a real address: for an
  exclusion, "cannot be sure it works" means "do not proceed".
- **The proxy is the hook, not the variable.** A stale exported
  `PROXYCHAINS_CONF_FILE` on a run without proxychains made the tool believe it
  was proxied: unreachable hosts read `closed`, and every stall waited out the
  budget (67 s on Kali's defaults). `hook_loaded` looks at the preload
  variables and at the mapped libraries (which also catches `ld.so.preload`); a
  variable without a hook is a warning and a direct run.
- **Journals are input.** `--resume` may be pointed at anything, so every line is
  validated (dict, `str` host, a real `int` port in range -- `true` is not one --
  a known state), deeply nested JSON is a damaged line rather than a
  `RecursionError`, and the header timestamp goes through `journal_age`, which
  turns a non-finite, huge or non-numeric value into "unknown" instead of a
  crash.
- **Report paths.** `write_private` replaces only a plain file. What is at the far
  end of a link is what counts: a link to a regular file is replaced, not
  followed, because following a symlink planted where the report goes overwrote
  whatever it pointed at, non-atomically and with its old mode; a pipe, tty or
  device is written into, opened non-blocking so a fifo nobody reads fails at
  once instead of hanging the end of a run and swallowing Ctrl+C; a directory is
  refused up front; and nothing
  directly under `/dev` is ever replaced, because `/dev/stdout` is a link to
  whatever stdout is and, as root, replacing it breaks it for the whole box. The
  path is checked before the sweep, not after it.

---

## Deliberate omissions

Removed in the 0.3.0 rewrite, and why:

- **Implicit resume / state files.** The single largest source of bugs in
  0.1.x: a completed scan left its state behind and the next run replayed it,
  reporting ports open without sending a packet. Resume itself came back in
  0.3.1 as `--resume FILE` -- opt-in, explicitly named, scoped to the current
  run, journalling only what the chain has vouched for, and loudly reported.
  What is gone for good is the *automatic* variant.
- **XML / CSV / txt / gnmap renderers.** Four serialisers for one dataset.
  stdout is the greppable format; `--json` is the structured one.
- **Alternate-screen dashboard.** It discarded its own contents at exit,
  including warnings, which is how a silent resume went unnoticed for so long.
  Progress is now one `\r` line on stderr, or periodic lines when piped.
- **Per-host pacing, dual gap flags.** `--rate` covers the real need; through a
  chain the global rate is what the proxy notices.

---

## Invariants worth preserving

- `Report`/`Stream`/`Progress`/`Journal` are touched only from the main thread —
  results are consumed in `Sweep.run`'s loop — so none of them need locks. The
  one exception is `Holdback`, shared with its watcher thread: its lock guards
  the state, and nothing else may write to stdout or the journal except
  through it. The sanity threads talk to it through the verdict dict and nothing
  else.
- `Sweep.run` handles a batch of finished probes in *completion* order (see
  "Completion order"), which is also deterministic for single-worker tests.
- A worker stamps the epoch before it waits at the gate; an outage closes the
  gate before it moves the epoch. Keep them in `Gate`.
- A crash exits `3`, never `1`.
- An exception out of a probe is never recorded as a result (see "A probe that
  never happened").
- `RateLimiter.take` and the pause gate both take `stop`, so Ctrl+C is
  immediate; a connect already inside the hook cannot be cancelled and runs to
  the chain's timeout, which `run`'s teardown reports rather than hiding.
- `clean()` is a security control, not cosmetics: banners are attacker
  controlled and reach both a terminal and the JSON.
- `--json` is written atomically at `0600`, but only where replacing is safe: see
  "Report paths". As root, the rename once replaced `/dev/null` with a regular
  file.
- IPv4 only, enforced with a clear error. proxychains is IPv4 TCP.

## Known limits

- With stdout gone and neither `--json` nor `--resume` given, a scan has nowhere
  to put its findings and still runs to the end. Stopping would be right, but it
  is a new behaviour to decide on, not a bug fix.
- `remote_dns_subnet` placeholders are recognised by their first octet when
  `proxy_dns` is on. A real address from `/etc/hosts` in that subnet looks the
  same (a warning for a target, a refusal for an `--exclude`).
- Results held back by the honesty probe are in memory: a `kill -9` before the
  verdict loses them.
- The release workflow's actions are pinned by tag, not by commit SHA; pinning
  needs SHAs that have been checked against the upstream repos. CI runs the suite
  on one Python (`3.x`) only, although `requires-python` is `>=3.8`.

## Tests

`test_scan.py`, no network beyond loopback and no root. The proxy paths are
covered by scripting `ScriptedProber` rather than standing up a proxy, so chain
death, revocation, the tail proof, epoch invalidation and the `--chain-wait`
deadline are deterministic. `run_main` runs `main()` in-process with the hook
*named* in the environment (`LD_PRELOAD`, plus `PROXYCHAINS_CONF_FILE` for the
config), which makes the tool believe it is proxied while it connects to
loopback, and points the sanity probe at a loopback listener: that is how the
honesty gate is tested end to end without a proxy. Run with
`python3 -m pytest test_scan.py -q` (or `python3 -m unittest test_scan`, which
is what CI runs).

Rules for changing them. Tests never write under `/dev` -- as root, a regression
would replace the node -- and the single test that names a `/dev` path mocks the
write. Nothing may depend on machine state (a listener on port 22, a route).
And a test is only worth having if it goes red when its fix is removed: the
suite was checked by breaking each fix in a scratch copy, more than fifty breaks
in all (no tail proof, no epoch check, stamp after the gate, no holdback, journal
at once, submission-order batches, direct mode policed, ...), and confirming a
test named for it fails. That check found the suite's own weaknesses, twice:
several of the original tests passed vacuously (one guarded its assertion with
`if sink.revoked:`, another asserted the defaults of an unrelated object), and
a test of mine was flaky because it assumed an order the engine did not
guarantee.

Real-proxy checks are worth repeating after touching the engine, because none
of the above exercises proxychains itself: a loopback `sshd` with `ssh -D`, and a
twenty-line SOCKS5 server that answers success to everything, are enough to
reproduce the fabricating proxy, a chain that dies near the end of a short
sweep, and the held-output timing.
