# Project: TCP Sweep (`scan.py`)

## Purpose
A netcat-style TCP **connect** sweep. Sends the same probe as `nc -z` (a full TCP
connect) to every host/port in a target spec and reports which ports are open.
Standard-library only, single file.

Discovered open ports **stream to stdout** (one `IP PORT` line each) so the tool
composes in a shell pipeline; progress and the summary go to **stderr**. Results
are also written to `NAME.json`, `NAME.gnmap`, and a resumable `NAME.state.json`.

## Files
| File           | Lines | Role |
|----------------|-------|------|
| `scan.py`      | ~1597 | All code: IP/port expansion, scanning, `Scanner`, `Display`, reports, CLI |
| `test_scan.py` | ~1478 | 215 tests, all passing, no skips |

Run tests: `python3 -m pytest test_scan.py -v`

**Single-file by design.** This is a portable pentest tool meant to be dropped
onto any box with Python 3 — so it stays one stdlib-only file, not a package.
"Modularity" here means clean internal separation (sectioned helpers, small
methods), not multiple modules. `import scan` and `python3 -m scan` are both
load-bearing for the suite.

Note: the executable file **must** be named `scan.py` (not bare `scan`) — both
`import scan` in the test suite and `python3 -m scan` in `TestCliExit`/manual
runs depend on the `.py` extension for module resolution. It's still directly
runnable as `./scan.py ...` via its shebang.

---

## CLI Flags

Flags are grouped into `argparse` argument groups by usecase (shown as
separate sections in `--help`), not a flat list:

**Target selection** — what to scan
| Short | Long           | Type       | Default | Description |
|-------|----------------|------------|---------|-------------|
|       | `ip`           | positional | —       | IP spec (single, CIDR, dash-range, braces) **or hostname**. Optional if `-iL` given (`nargs="?"`). |
|       | `PORT ...`     | positional | —       | Port numbers / ranges (also `-p`) |
| `-p`  | `--ports`      | `[PORT …]` | —       | Ports (comma/space-sep, ranges `22-25` or `22:25`) |
|       | `--top-ports`  | int        | —       | Also scan the N most common ports (nmap frequency order, `_TOP_PORTS`, max 100) |
| `-iL` | `--target-file`| `FILE`     | —       | Read target specs from FILE (`-` = stdin); one per line, `#` comments. Repeatable. |
|       | `--exclude`    | `SPEC`     | —       | Remove these hosts from the sweep (same grammar, incl. hostnames). Repeatable. |

**Multiple ranges positionally:** leading positionals are split by `_classify_positionals()`
into target specs vs port tokens — a token made only of `0-9,-:` is a port, anything with a
dot/slash/brace/letter is a target. So `scan 192.168.0.0/24 192.168.4.0/24 -p 22` scans both
ranges; the classic `scan 10.0.0.1 22 80` form still works. `-iL` files add more targets.

**Report export** (write a formatted report at end of scan, also on Ctrl+C):
| Short | Long           | Arg    | Format |
|-------|----------------|--------|--------|
| `-oJ` | `--json-report`| `FILE` | JSON (metadata + open/filtered per host) |
| `-oX` | `--xml`        | `FILE` | XML (`<scanreport>`, nmap-ish, via ElementTree) |
| `-oT` | `--txt`/`-oN`  | `FILE` | Human-readable text |
| `-oC` | `--csv`        | `FILE` | CSV (`ip,port,protocol,status,service`) |
| `-oA` | `--export-all` | `BASE` | All four: `BASE.json/.xml/.txt/.csv` |

A space before the filename is required (`-oX out.xml`), matching nmap; argparse resolves
`-oX`/`-oJ`/… against `-o` by exact option-string match.

**Scan behavior** — how the sweep runs
| Short | Long              | Type  | Default | Description |
|-------|-------------------|-------|---------|--------------|
| `-t`  | `--threads`       | int   | `1`     | Parallel workers, for speed on large sweeps. Errors if combined with `-P/--pgap`. |
| `-w`  | `--timeout`       | int   | `6`     | TCP connect timeout per port (seconds). Mimics `nc -w`. |
| `-r`  | `--random`        | bool  | False   | Scan in random order, to avoid an obvious sequential footprint |
| `-b`  | `--banner`        | bool  | False   | Read a short banner from each open port |
| `-F`  | `--show-filtered` | bool  | False   | Also list filtered ports, not just open ones |

**Rate limiting** — stay under the radar or off a fragile link
| Short | Long     | Type    | Default | Description |
|-------|----------|---------|---------|--------------|
| `-P`  | `--pgap` | `N[,N]` | `0`     | Delay between packets (single value or MIN,MAX). Single-thread only. |
|       | `--rate` | `PPS`   | —       | Send-rate cap in packets/sec; convenience for `-P 1/PPS`. Conflicts with `-P`. Single-thread only. |
| `-H`  | `--hgap` | `N[,N]` | `0`     | Delay between packets to the same host. |

**Link health** — auto-pause on a flaky connection
| Short  | Long             | Type      | Default | Description |
|--------|------------------|-----------|---------|--------------|
| `--cf` | `--check-fails`  | int       | `0`     | Consecutive non-open results before a link health probe. `0` = disabled. |
| `--ct` | `--check-target` | `IP:PORT` | —       | Known-good probe target(s). Repeatable. |

**Output & resume**
| Short | Long         | Type   | Default | Description |
|-------|--------------|--------|---------|--------------|
| `-o`  | `--output`   | `NAME` | derived | Output base name → `.json`, `.gnmap`, `.state.json` |
|       | `--fresh`    | bool   | False   | Discard any existing state file and start clean |
|       | `--interval` | float  | `0.25`  | Display refresh interval (seconds) in threaded mode |

**Constraint:** `-t N` (N>1) + `-P/--pgap` (non-zero) → error. `--hgap` is always allowed.

**Auto-resume:** an existing `.state.json` is always resumed by default. `--fresh` deletes it
first. **Flags are never persisted in the state file** — only `ips`/`ports`/`results`/
`random_order` (for the record) are — so a resumed run always uses *this* invocation's
CLI flags. You can freely change `-t`, `-w`, `-r`, `-b`, gaps, etc. between runs of the
same target. `_load()` no longer forces `random_order` to stick from a prior run.

Every run prints an announcement to stderr before scanning starts: `Starting scan. ...`
or, when resuming, `Resuming NAME — N check(s) already done. <effective flags>` (also
shown as a banner above the live status line in TTY mode) — this is the "does resume
actually work / did my new flags take" signal the user watches for.

---

## IP Specification Formats

`expand_ips(spec)` handles, with **validation** (invalid octets/ranges exit cleanly, no traceback):

| Format                 | Example                 | Result |
|------------------------|-------------------------|--------|
| Single IP              | `192.168.1.1`           | 1 host |
| CIDR                   | `192.168.1.0/24`        | 254 hosts |
| Comma-separated        | `10.0.0.1,10.0.0.2`     | 2 hosts |
| Last-octet dash range  | `192.168.1.1-10`        | 10 hosts |
| Nmap-style braces      | `192.168.1.{1-5,254}`   | 6 hosts |
| Mixed (outside braces) | `10.0.0.{1,2},10.0.0.3` | 3 hosts |
| **Hostname**           | `example.com`, `localhost` | resolved to its IPv4(s) |

`_split_respecting_braces()` splits on commas only at brace depth 0. `_brace_expand()` /
`_expand_dash()` route numeric ranges through `_octet_range()`, which rejects
non-numeric tokens, reversed ranges, and out-of-range octets via `_valid_ip()`.

**Hostnames:** a part that isn't a literal IP/CIDR/range but contains a letter is treated
as a DNS name and resolved via `_resolve_host()` (`getaddrinfo`, `AF_INET`, deduped);
an unresolvable name exits cleanly (`Could not resolve host`). A non-IP with **no** letter
is still an invalid-IP error. `_try_ip()` is the non-fatal "is this an IP?" test that makes
this branch possible without changing `_valid_ip()`'s die-on-invalid contract (still used
by the brace/octet paths).

`resolve_targets(specs, exclude=())` unions every spec's expansion into a sorted, unique
IPv4 list and subtracts the `--exclude` specs. `_read_target_file(path)` reads `-iL`
targets (one spec per line, `#` comments, `-`=stdin). `top_ports(n)` returns the first
`n` of `_TOP_PORTS` (nmap top-100). `main()` assembles targets from the positional spec +
`-iL` files, applies `--exclude`, then unions explicit ports with `--top-ports`.

`parse_ports(spec)` accepts comma/space-separated values and `lo-hi` / `lo:hi` ranges,
and rejects non-numeric tokens and anything outside 1..65535 (`_port()`).

---

## Architecture

### `scan_port(ip, port, timeout)`
Standard connect scan (matches `nc -z`), using a `with socket.socket(...)` context
manager so the fd is always closed (no leak). Returns `"open"` (connect),
`"closed"` (ConnectionRefusedError), `"filtered"` (timeout / OSError).

`probe_banner(ip, port, timeout)` connects once and reads up to 256 bytes → `(status, text|None)`.
`service_name(port)` is a best-effort `/etc/services` lookup for the summary.

### `Scanner` (main class)

**Constructor:**
```python
Scanner(ips, ports, *, timeout=6, random_order=False,
        gap_min=0, gap_max=0, hgap_min=0, hgap_max=0,
        threads=1, output_name=None, spec=None, interval=0.25,
        check_fails=0, check_targets=None, show_filtered=False, banner=False)
```

**State dict** (persisted to `NAME.state.json`):
```json
{
  "ips": ["10.0.0.1"],
  "ports": [22, 80, 443],
  "results": {"10.0.0.1": {"22": "open", "80": "closed"}},
  "pending": [["10.0.0.1", 443]],
  "interrupted": false,
  "start_time": 1719072000.0,
  "end_time": null,
  "random_order": false
}
```
JSON serialises int port keys as strings; `_load()` converts them back to `int`.

**Shared mutables (thread-safe):**
- `task_queue` — a `collections.deque` of `(ip, port)`, drained via `popleft()` (O(1)).
- `results_lock` — guards `state["results"]`, `task_queue`, and the health-check counters.
- `wait_lock` / `host_lock` — guard the global / per-host rate-limit clocks.
- `shutdown` (Event) — set on SIGINT.
- `_resume_event` (Event) — set = workers run; cleared = paused (during a link drop).

### `_worker()`
Daemon thread loop:
1. `_resume_event.wait()` (pauses during a health-check outage), break on shutdown.
2. Pop a task under `results_lock`; break if empty.
3. `--hgap` sleep (always), then `--pgap` sleep (single-thread only). Sleeps are
   interruptible (`shutdown.wait`) so Ctrl+C is immediate. On shutdown mid-wait the
   task is put back so resume re-runs it.
4. `scan_port` / `probe_banner`.
5. Record result, update display, run health-check bookkeeping (`_on_result`).
6. Emit open ports to stdout (`_emit_open`, only when stdout is piped).
7. Run the health check if the fail-streak tripped (one worker at a time, `_check_lock`).
8. Redraw (single-thread) and time-throttled persist (`_maybe_persist`).

### Rate limiting
`_wait_global()` / `_wait_host(ip)` reserve the next send slot against a monotonic
"next allowed" timestamp and return the seconds to sleep. First packet is free; the
gap applies before subsequent packets. Thread-safe via `wait_lock` / `host_lock`.

### Persistence
`_persist()` snapshots results under `results_lock`, derives `pending` from the
precomputed `_all_tasks` set, and writes `.state.json` + `.json` + `.gnmap`.
`_maybe_persist()` throttles this to at most once per `_persist_interval` (1 s)
**and** takes `_persist_lock` non-blocking so two threads never persist at once;
`run()` always does a final unthrottled persist, and persists on interrupt.

**All three files are written via `_atomic_write()`** — a unique `mkstemp` temp
in the same dir, `fsync`, then `os.replace()` (atomic on POSIX) — so a kill
mid-write can never leave a truncated/corrupt file (critical for resume). Files
are created **0600** (owner-only): scan results are sensitive recon data.
`load_state()` treats a corrupt/unreadable state file as "no state" (warns,
starts fresh) instead of crashing on `json.load`.

---

## Connection health check (`--cf` / `--ct`)

**Problem:** on a flaky link, network drops turn open ports into false closed/filtered.

**Mechanism (opt-in, `--cf 0` disables — the default):**
1. Track `fail_streak` (consecutive non-open results) and `since_good` (the tasks
   scanned during the current streak). Any **open** result resets both and records
   the port as a known-good target (`known_open`).
2. When `fail_streak >= check_fails`, one worker runs `_run_health_check()`:
   - Pick a probe target (random known-open, else a `--ct` target). None → just reset.
   - **Probe open** → the link is fine (a dense closed region); reset and continue.
   - **Probe fails** → confirmed drop: clear `_resume_event` to pause **all** workers,
     re-probe with backoff (`_recovery_delay` → `_recovery_max`) until it recovers or
     the user Ctrl+C's. On recovery, `_requeue_since_good()` deletes the suspect
     results and re-queues those ports, then sets `_resume_event` to resume.

This is fully automatic and works in single- and multi-thread mode. There is **no**
interactive prompt, no rollback state machine, and no unattended cycling — the
scanner simply pauses during an outage and re-scans the ports checked while it was down.

---

## Output

Default base name derived from the spec via `_make_default_name()`:

| Input spec       | File name              |
|------------------|------------------------|
| `192.168.1.1`    | `192.168.1.1`          |
| `192.168.1.0/24` | `192.168.1.0_24`       |
| `10.0.0.{1-10}`  | `10.0.0.1-10.0.0.10`   |

Override with `-o NAME`. Three files, all written on every (throttled) save so
partial results survive a kill:

| File              | Format |
|-------------------|--------|
| `name.json`       | `{ip: {port: status}}`, IPs version-sorted, ports **numeric**-sorted |
| `name.gnmap`      | `Host: IP [port/status, ...]`, hosts version-sorted, ports numeric-sorted |
| `name.state.json` | Full state dict for auto-resume |

All three are written atomically and 0600 (see Persistence above).

**Report export** (separate from the always-on working files): `build_report_data()` assembles
a serialisation-agnostic dict (scan metadata — targets/timing/totals — plus the *actionable*
open+filtered ports per host, with service names; closed ports stay in the raw `.json`).
`render_report(fmt, data)` dispatches to `_report_json/_xml/_txt/_csv` (`REPORT_FORMATS`);
XML is built with `xml.etree.ElementTree` (proper escaping), CSV with the `csv` module.
`write_report()` writes atomically at 0600. `main()` runs exports after `scanner.run()`, so a
report is produced for **completed and interrupted** scans alike.

**stdout stream** (when stdout is not a TTY): one `IP PORT` line per open port, live,
optionally `\t`-suffixed with the (sanitised) banner under `-b`. This is the pipeable
machine output. Guarded by `_stdout_lock` so threaded writes never interleave. Banner
bytes pass through `_sanitize()` (printable-ASCII only) to defuse ANSI/escape injection
from a hostile service.

**Final report / Ctrl+C report** (stderr, `_print_summary()` / `_print_interrupt()`):
only ever list **open** ports, grouped by host, each prefixed with the `●` switch glyph
(plus service name via `service_name()`). Closed/filtered ports are never enumerated;
filtered ports only appear (in a separate labeled block, `◐` glyph) when `-F` is passed.
`_print_interrupt()` reuses the same `_print_open_ports()` helper as the completion
summary, so what you see on Ctrl+C is exactly "the open ports found so far" plus a
one-line interrupted/resume notice — no checks-done breakdown, no closed/filtered noise.

---

## Display (`Display` class) — alt-screen live dashboard

Writes to **stderr**, active only when `sys.stderr.isatty()` (`_COLORS_ON`). It draws a
single, continuously-updated **dashboard on the terminal's alternate screen buffer**
(`\033[?1049h` on `start()`, `\033[?1049l` on `finish()`). The live frame therefore never
enters scrollback: on completion or Ctrl+C the alt screen is torn down, the dashboard
vanishes, and `Scanner` prints a concise summary/interrupt notice onto the *normal*
screen. When stderr is **not** a TTY (piped/redirected/tests) every render method is a
no-op and the scanner falls back to its plain line output (stdout stream + one-shot
`_announce()` line).

Methods:
- `start()` — enter alt screen, hide cursor, first paint.
- `render()` — full-frame repaint: `\033[H` home + per-line `\033[K` + trailing `\033[J`.
  Frame = title, **`target` line (the range(s) being scanned)**, effective-flags `scan`
  line, optional `↻ resuming` note, progress bar (`█/░`, %, done/total, rate), elapsed·ETA,
  a live **`▸ scanning ip:port`** line (the probe currently in flight), counters
  (`● open  ○ closed  ◐ filtered`), a red `⚠ link check` line when a health-check streak is
  active, and a **recent-open-ports** panel (ring buffer, adapts to terminal height).
  Called after each task in single-thread mode, on `--interval` in threaded mode.
- `set_current(ip, port)` — the worker calls this before each probe; stored as a plain
  attribute (atomic assignment, lock-free) and shown as the `▸ scanning` line. `Scanner`
  passes the target-range string via `display.target = self.target_spec`.
- `finish()` — leave alt screen, restore cursor, set `finished`.
- `record()`/`unrecord()`/`_sync_state()` — thread-safe result bookkeeping that also
  maintains **incremental** `done` + `counts{open,closed,filtered}` so a repaint is
  O(recent), not O(hosts×ports). `_sync_state()` seeds them from prior results on resume.
- `add_open(ip, port, banner)` — push an open discovery (with service name or sanitised
  banner) to the recent panel.

Layout is computed on plain text then coloured, and `_fit()` truncates to width with `…`,
so ANSI codes never skew alignment. The progress bar has a fixed (width-adaptive) cell
count so its visible width is known regardless of colour. Port state shows as a literal
switch (`_SWITCH_OPEN="●"`, `_SWITCH_CLOSED="○"`, `_SWITCH_FILTERED="◐"`).

> **Note:** the instance start-time attribute is `self._start` (not `self.start`) —
> `start()` is a method, and an attribute of the same name would shadow it (was a live
> bug caught in verification; see Bugs Fixed).

---

## Ctrl+C Handling

The SIGINT handler is **async-signal-safe**: it only flips events
(`shutdown`, `_resume_event`) and sets `interrupted` — it never takes a lock or prints
(this fixes a deadlock where the old handler acquired `results_lock` from signal
context). The run loop and workers notice `shutdown` and stop; the `run()` `finally`
tears down the alt screen (`display.finish()`) so the live dashboard **disappears and
leaves nothing in scrollback**, then the main thread persists state with
`interrupted=True`, prints the open-ports-so-far report via `_print_interrupt()` onto the
now-restored normal screen, and `main()` exits 130. The in-flight task is re-queued so
resume re-runs it. Re-run the same command to resume — flags may be changed (see CLI
Flags above); this is confirmed by the `Resuming ...` banner at the start of the next run.

---

## Test Organisation (`test_scan.py`, 215 pass, 0 skip)

| Class | Covers |
|-------|--------|
| `TestSplitBraces` / `TestBraceExpand` / `TestExpandIps` | Brace splitting & IP expansion |
| `TestExpandIpsInvalid` | Out-of-range / reversed / non-numeric ranges exit cleanly |
| `TestParseGap` / `TestParsePorts` | Gap & port parsing incl. invalid-input rejection |
| `TestScanPort` | open/closed/filtered + **no-fd-leak** regression |
| `TestBanner` | `probe_banner` open (no data) / closed |
| `TestStatePersistence` / `TestOutputFiles` | save/load, JSON/gnmap content, **numeric port sort** |
| `TestDisplayTime` / `TestDisplay` | `_fmt_time`, record/unrecord/sync/finish |
| `TestBuildTasks` / `TestScannerInit` / `TestScannerTasks` | Task matrix, defaults, rate-limit pacing, queue building |
| `TestScannerPersist` / `TestScannerLoad` | pending rebuild, thread-safe snapshot, resume load, **random_order not sticky** |
| `TestSingleThreadEndToEnd` | Full scans: open, closed, files, **stdout stream** |
| `TestMultiThread` / `TestResumeEndToEnd` / `TestThreadsWithGapConflict` | Threading, resume incl. **changed flags on resume** and **resume-announce banner**, `-t`+`-P` error |
| `TestOpenPortsOnlyOutput` | Final/interrupt report only lists open ports, never closed/filtered |
| `TestParser` / `TestDie` / `TestCliExit` | CLI args incl. **`--output` long flag**, error exits (invalid IP/port/target, thread+pgap) |
| `TestInterruptSignal` | SIGINT mid-scan saves state with `interrupted=True` |
| `TestConnectionCheck` | streak, since_good, probe target, requeue, health-check recovery |
| `TestAtomicWrite` | atomic content, no temp left behind, **0600** perms on all output files |
| `TestCorruptState` | corrupt `.state.json` → `load_state` returns None, scan starts fresh (no crash) |
| `TestSanitize` | `_sanitize` strips ESC/control bytes; banner grab is sanitised end-to-end |
| `TestDisplayCounters` | incremental `done`/`counts`, re-record no double-count, recent panel bound, `_fit`, **`start()`/`render()`/`finish()` are callable (shadowing regression)** |
| `TestTopPorts` | `top_ports()` frequency order, caps at 100, unique/valid, `0` exits |
| `TestResolve` | `localhost` resolves, hostname dedup + IP mix, unresolvable exits |
| `TestResolveTargets` | union/sort, `--exclude` removal, exclude-to-empty |
| `TestTargetFile` | `-iL` parsing (comments/blanks), missing file exits, feeds `resolve_targets` |
| `TestNewCliFlags` | `--top-ports`/`-iL`/`--exclude`/`--rate` parse, `ip` optional, positional split intact |
| `TestNewCliExit` | no-targets, `--rate`+`-P` conflict, all-excluded, `--top-ports`-only scan |
| `TestClassifyPositionals` | multi-range positionals split from port tokens; hostname/brace = target |
| `TestReport` | `build_report_data` totals/host-filtering, JSON/XML/CSV/TXT render, interrupted flag, atomic 0600 |
| `TestExportFlags` | `-oJ/-oX/-oT/-oN/-oC/-oA` + long aliases parse, coexist with `-o` |
| `TestReportExportCli` | end-to-end `-oA`/`-oX` write valid files; **multi-range positional scan** |

---

## Standing Rules
1. **After every code change:** update `AGENT.md` to reflect the new state.
2. **After every feature or bug fix:** update `test_scan.py` to match.
3. **Run the full suite** after changes: `python3 -m pytest test_scan.py -v`. All must pass.
4. Only stdlib packages.

## Git Workflow
After a completed feature (tests pass, AGENT.md updated): `git add scan.py test_scan.py AGENT.md`
then `git commit -m "<concise, specific message>"`. Do not commit unless asked or the
feature is fully done with tests passing.

## Bugs Fixed (dashboard refactor)
- **`Display.start` shadowed by an attribute** — the instance start-time was stored as
  `self.start`, colliding with the new `start()` method, so `display.start()` raised
  `TypeError: 'float' object is not callable`. Invisible to the suite (start() only runs
  under a TTY); caught by a live pty run. Attribute renamed `self._start`; a headless
  `callable()` regression test added.
- **Non-atomic output writes** — a kill mid-write could leave a truncated `.state.json`,
  crashing the next resume. Now write-temp-`fsync`-`os.replace()` (`_atomic_write`).
- **Corrupt state file crashed resume** — `load_state` had no guard around `json.load`;
  now catches and degrades to a fresh scan with a warning.
- **Dead `pending_event`** — created and set but never awaited; removed.
- **Concurrent-persist temp collision** (introduced then fixed) — `mkstemp` unique names
  plus a non-blocking `_persist_lock` so threaded workers don't stomp each other's writes.

## OPSEC Review (findings + hardening)
- **World-readable results** — scan output (open ports, banners) is sensitive recon;
  default umask made files 0644. Now created **0600** (owner-only).
- **Terminal-escape injection via banners** — untrusted remote banner bytes reach the
  terminal and the output files; `_sanitize()` reduces them to printable ASCII on every
  surfacing path (dashboard, stdout stream). This is a security control, kept named/reused.
- **No secrets/credentials** are handled by the tool; error messages echo only
  user-supplied specs, not internal paths, and there is no debug/verbose leak path.

## Bugs Fixed (earlier refactor)
- **IP/port validation crashes** — out-of-range dash/brace octet ranges (e.g.
  `192.168.1.250-260`) and non-numeric / out-of-range ports used to raise raw
  `ValueError` tracebacks or silently accept bad input; now they exit cleanly via `_die`.
- **Socket fd leak** — `scan_port` didn't close the socket on the connect-failure path;
  now uses a `with` context manager.
- **Grepable port order** — ports were sorted lexically (`1023 < 22`); now numeric.
- **Signal-handler deadlock** — the SIGINT handler acquired `results_lock` and called
  into the display; now it only sets events.
- **Persist storm** — the old code wrote all three output files on *every* task
  (rebuilding the full host×port set each time); now throttled to ≤ once/sec, with a
  precomputed task set and a `deque` queue (O(1) pops).
- **Dead code / unused imports** removed (`math`, `datetime`, `OrderedDict`,
  `_pick_next_ip`, unused color constants, etc.).

## Removed (over-engineered / fragile subsystems)
- Interactive `[R]ollback / [C]ontinue` prompt and the `checkpoint_seq` / `next_seq` /
  `doubtful_tasks` rewind machinery → replaced by the automatic pause-and-rescan health check.
- `--unattended` / `--unattended-interval` reconnection cycling.
- Arrow-key scrolling of the host list and all raw-tty (`termios`/`tty`/`fcntl`/`select`)
  stdin handling → the display is now read-only.

## Added (live dashboard, multi-range, report export)
- **Live target + current-probe on the dashboard** — a `target` line shows the range(s)
  being swept and a `▸ scanning ip:port` line shows the probe in flight, updating as the
  sweep runs (`Display.set_current`, `Scanner` sets `display.target`).
- **Multiple ranges in one run** — list them positionally
  (`scan 192.168.0.0/24 192.168.4.0/24 -p 22`) via `_classify_positionals`, or from `-iL`.
- **Report export** `-oJ/-oX/-oT(-oN)/-oC/-oA` — JSON / XML / text / CSV / all-at-once,
  with scan metadata + service names; written for completed *and* interrupted scans.

## Added (targeting & convenience — researched against nmap/rustscan/naabu)
- **Hostname targets** — accept DNS names anywhere an IP goes; resolved to IPv4 and
  deduped (so several names for one box = one target). `example.com`, `localhost`, or a
  whole `-iL` list of hosts.
- **`--top-ports N`** — sweep the N most common TCP ports (nmap frequency order, top 100)
  without typing them; unions with any explicit `-p`.
- **`-iL/--target-file FILE`** — read targets from a file or stdin (`-`); `#` comments,
  one spec per line. Makes the tool a drop-in for `subfinder | ... | scan -iL -` pipelines.
- **`--exclude SPEC`** — carve hosts out of a range (skip the gateway / your own box).
- **`--rate PPS`** — express pacing as packets/second instead of raw gap seconds.

## Added (usefulness)
- Live `IP PORT` **stdout stream** for piping (netcat/masscan style).
- `-b/--banner` short banner grab; **service names** in the summary.
- Interruptible rate-limit sleeps; version/numeric sorting everywhere.
- CLI flags grouped by usecase in `--help` (target / scan behavior / rate limiting /
  link health / output & resume) instead of one flat list; `-o` gained a `--output`
  long form for consistency.
- Port state shown as a literal switch glyph (`●` open, `◐` filtered) in both the
  live log and the final report.
- Live display is a full **alt-screen dashboard** (progress bar, live counters,
  elapsed/ETA, recent-open panel, link-health line) that continuously repaints in place
  and is torn down on exit — so Ctrl+C leaves a clean message and nothing in scrollback,
  and the final summary replaces the dashboard entirely. (Supersedes the earlier
  scrolling-log + pinned-status-line design.)
- Resumed runs always use the current invocation's flags (nothing from the old state
  file overrides them — including `random_order`, previously sticky) and print an
  explicit `Resuming NAME — N done. <flags>` banner so resume is visibly verifiable.
- Final report and Ctrl+C report now list **only open ports** (grouped by host, with
  service names); closed/filtered are dropped from the default output entirely, and
  filtered only reappears under explicit `-F`.
