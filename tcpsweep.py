#!/usr/bin/env python3
"""A TCP connect sweep built for proxychains.

Run it as ``proxychains4 tcpsweep 10.0.0.0/24 -p 22,80,443``.

Three measured facts about life inside proxychains' hooked ``connect()`` shape
everything in this file:

1. **errno carries no information.**  A refused port, an unreachable host, a
   network-unreachable, a ruleset denial, a general SOCKS failure and a proxy
   that closes without replying all surface as ``ECONNREFUSED``.  The only
   thing separating a definitive answer from a black hole is how long the call
   took, so every classification here is time-based.

2. **The application timeout is inert.**  The SOCKS handshake happens inside
   the hook, so ``settimeout()`` does not bound a probe -- ``tcp_read_time_out``
   from the proxychains config does.  That budget is read from the config
   rather than guessed, and because a stalled probe costs all of it, the sweep
   is built to issue as few stalls as possible.

3. **A dead proxy looks exactly like "everything is closed."**  Both are an
   instant ``ECONNREFUSED``.  A sweep with no control target cannot tell a
   clean negative result from a broken chain, so the canary is part of the
   design rather than an option.

Open ports stream to stdout as ``host port`` lines; progress and the summary go
to stderr, so the tool composes in a pipeline.  Standard library only.
"""

import argparse
import collections
import concurrent.futures as futures
import contextlib
import ipaddress
import json
import os
import random
import re
import signal
import socket
import sys
import tempfile
import threading
import time

__version__ = "0.3.1"

# ── Defaults ──────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 6.0           # direct-mode connect budget, seconds
DEFAULT_CONCURRENCY = 16        # stalls cost the full budget; overlap them
DEFAULT_TOP_PORTS = 20
DEFAULT_DISCOVER_PORTS = (80, 443, 22, 3389, 445, 8080)
DEFAULT_CANARY_AFTER = 40       # consecutive non-open results before a check
DEFAULT_CHAIN_WAIT = 120.0      # seconds to wait for a dead chain before quitting
AUTO_CANARY_LIMIT = 3           # open ports kept as fallback control targets
BANNER_BYTES = 256
PROGRESS_LOG_EVERY = 15.0       # seconds, when stderr is not a terminal

EXIT_FOUND = 0                  # completed, at least one open port
EXIT_NONE = 1                   # completed, nothing open
EXIT_USAGE = 2                  # bad arguments
EXIT_PROXY = 3                  # the chain failed and never came back
EXIT_INTERRUPT = 130            # Ctrl+C

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"

# The 100 most common TCP ports in nmap's frequency order (nmap-services).
TOP_PORTS = (
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
    6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
    49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153,
    8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357,
    427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070,
    5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873,
    1755, 2717, 4899, 9100, 119, 37,
)

# ── Terminal output ───────────────────────────────────────────────────

_TTY = sys.stderr.isatty()
_STYLES = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "cyan": "\033[36m",
}
_COLOR = _TTY and os.environ.get("NO_COLOR") is None


def paint(text, *styles):
    if not _COLOR or not styles:
        return text
    return "".join(_STYLES[s] for s in styles) + text + _STYLES["reset"]


def note(msg):
    sys.stderr.write(f"  {paint('·', 'dim')} {msg}\n")
    sys.stderr.flush()


def warn(msg):
    sys.stderr.write(f"  {paint('!', 'yellow')} {msg}\n")
    sys.stderr.flush()


def die(msg):
    sys.stderr.write(f"  {paint('x', 'red')} {msg}\n")
    sys.exit(EXIT_USAGE)


def human_time(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def clean(text):
    """Printable ASCII only.

    Banners come from hosts we do not trust; passing them through verbatim
    would let a hostile service inject ANSI escapes into the terminal or
    control characters into the JSON. This is a security control.
    """
    if not text:
        return ""
    return "".join(c if 32 <= ord(c) < 127 else "." for c in text).strip()


def write_private(path, data):
    """Write atomically, owner-readable only -- scan results are sensitive."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    handle, tmp = tempfile.mkstemp(dir=directory, prefix=".tcpsweep-")
    try:
        with os.fdopen(handle, "w") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ── Proxy environment ─────────────────────────────────────────────────

CONF_CANDIDATES = (
    "./proxychains.conf",
    "~/.proxychains/proxychains.conf",
    "/etc/proxychains4.conf",
    "/etc/proxychains.conf",
)
CHAIN_MODES = ("strict_chain", "dynamic_chain", "random_chain", "round_robin_chain")


class Proxy:
    """What proxychains is doing to us, read from its own configuration.

    The probe budget is not ours to choose under a proxy, so it is read rather
    than assumed. ``stall_threshold`` is the line between "the chain gave a
    definitive answer" -- microseconds, in practice -- and "the target
    black-holed and the chain gave up", which lands on ``tcp_read_time_out``
    exactly. Half the read timeout separates those two populations with a wide
    margin even on a slow multi-hop chain.
    """

    def __init__(self):
        self.active = False
        self.conf_path = None
        self.connect_ms = 8000          # proxychains' own defaults
        self.read_ms = 15000
        self.chain = "dynamic_chain"
        self.proxy_count = 0
        self.proxy_dns = False

    @classmethod
    def detect(cls):
        self = cls()
        preload = os.environ.get("LD_PRELOAD", "").lower()
        self.active = ("proxychains" in preload
                       or bool(os.environ.get("PROXYCHAINS_CONF_FILE")))
        if self.active:
            self.conf_path = self._find_conf()
            if self.conf_path:
                self._parse(self.conf_path)
        return self

    @staticmethod
    def _find_conf():
        env = os.environ.get("PROXYCHAINS_CONF_FILE")
        if env and os.path.isfile(env):
            return env
        for candidate in CONF_CANDIDATES:
            path = os.path.expanduser(candidate)
            if os.path.isfile(path):
                return path
        return None

    def _parse(self, path):
        try:
            with open(path, "r", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return
        in_proxy_list = False
        for raw in lines:
            line = raw.split("#", 1)[0].strip().lower()
            if not line:
                continue
            if line.startswith("[proxylist]"):
                in_proxy_list = True
            elif in_proxy_list:
                self.proxy_count += 1
            elif line in CHAIN_MODES:
                self.chain = line
            elif line.startswith("proxy_dns"):
                self.proxy_dns = True
            else:
                match = re.match(r"tcp_(read|connect)_time_out\s+(\d+)$", line)
                if match:
                    setattr(self, f"{match.group(1)}_ms", int(match.group(2)))

    @property
    def budget(self):
        """Worst-case seconds one probe can occupy a worker."""
        return (self.connect_ms + self.read_ms) / 1000.0

    @property
    def stall_threshold(self):
        return (self.read_ms / 1000.0) * 0.5

    def describe(self):
        proxies = f"{self.proxy_count} prox{'y' if self.proxy_count == 1 else 'ies'}"
        bits = [self.chain, proxies]
        if self.proxy_dns:
            bits.append("proxy_dns")
        bits.append(f"stall after {self.stall_threshold:.1f}s")
        return " / ".join(bits)


# ── Targets ───────────────────────────────────────────────────────────

def expand_target(spec, proxy):
    """Expand one spec into IPv4 addresses.

    Accepts ``10.0.0.1``, ``10.0.0.0/24``, ``10.0.0.1-20``, ``10.0.0.{1,5-7}``
    and hostnames.
    """
    spec = spec.strip()
    if not spec:
        return []
    if "{" in spec and "}" in spec:
        return _expand_braces(spec, proxy)
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            die(f"bad network {spec!r}: {exc}")
        if net.version != 4:
            die(f"{spec!r} is IPv6; a proxychains connect scan is IPv4 only")
        hosts = list(net.hosts()) or [net.network_address]
        return [str(host) for host in hosts]
    if _looks_like_range(spec):
        return _expand_range(spec)
    try:
        ipaddress.IPv4Address(spec)
    except ValueError:
        return resolve(spec, proxy)
    return [spec]


def _looks_like_range(spec):
    dot = spec.rfind(".")
    if dot < 0:
        return False
    dash = spec.find("-", dot)
    return 0 < dash < len(spec) - 1 and spec[dot + 1:dash].isdigit()


def _expand_range(spec):
    dot = spec.rfind(".")
    dash = spec.find("-", dot)
    return _octet_span(spec[:dot + 1], spec[dot + 1:dash], spec[dash + 1:], "", spec)


def _expand_braces(spec, proxy):
    start, end = spec.index("{"), spec.index("}")
    prefix, suffix = spec[:start], spec[end + 1:]
    out = []
    for token in spec[start + 1:end].replace(" ", "").split(","):
        if not token:
            continue
        if "-" in token:
            lo, hi = token.split("-", 1)
            out.extend(_octet_span(prefix, lo, hi, suffix, spec))
        else:
            out.extend(expand_target(f"{prefix}{token}{suffix}", proxy))
    return out


def _octet_span(prefix, lo, hi, suffix, spec):
    if not (lo.isdigit() and hi.isdigit()):
        die(f"bad range {lo}-{hi} in {spec!r}")
    if int(lo) > int(hi):
        die(f"reversed range {lo}-{hi} in {spec!r}")
    out = []
    for value in range(int(lo), int(hi) + 1):
        candidate = f"{prefix}{value}{suffix}"
        try:
            ipaddress.IPv4Address(candidate)
        except ValueError:
            die(f"{candidate!r} from {spec!r} is not a valid address")
        out.append(candidate)
    return out


def resolve(name, proxy):
    """Resolve a hostname to IPv4, flagging proxychains DNS placeholders."""
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        die(f"cannot resolve {name!r}")
    addrs = sorted({info[4][0] for info in infos})
    if proxy.active:
        # proxy_dns hands back a synthetic address that the chain maps back to
        # the name inside connect(). The sweep reaches the right host, but the
        # results are labelled with an address that does not exist.
        fake = [a for a in addrs if ipaddress.ip_address(a).is_multicast
                or ipaddress.ip_address(a).is_reserved]
        if fake:
            warn(f"{name} resolved to {', '.join(fake)}, a proxychains DNS "
                 f"placeholder rather than a real address -- results will be "
                 f"labelled with it")
    return addrs


def collect_targets(specs, excludes, proxy):
    keep, ordered = set(), []
    for spec in specs:
        for ip in expand_target(spec, proxy):
            if ip not in keep:
                keep.add(ip)
                ordered.append(ip)
    for spec in excludes:
        for ip in expand_target(spec, proxy):
            keep.discard(ip)
    return [ip for ip in ordered if ip in keep]


def read_target_file(path):
    try:
        if path == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(path, "r") as fh:
                lines = fh.read().splitlines()
    except OSError as exc:
        die(f"cannot read targets from {path!r}: {exc}")
    return [stripped for stripped in
            (line.split("#", 1)[0].strip() for line in lines) if stripped]


# ── Ports ─────────────────────────────────────────────────────────────

def parse_ports(tokens):
    ports = set()
    for token in tokens:
        for part in str(token).split(","):
            part = part.strip()
            if not part:
                continue
            separator = ":" if ":" in part else ("-" if "-" in part else None)
            if separator:
                lo, _, hi = part.partition(separator)
                ports.update(range(one_port(lo), one_port(hi) + 1))
            else:
                ports.add(one_port(part))
    return sorted(ports)


def one_port(token):
    token = token.strip()
    if not token.isdigit():
        die(f"bad port {token!r}")
    value = int(token)
    if not 1 <= value <= 65535:
        die(f"port out of range 1-65535: {value}")
    return value


# ── Probing ───────────────────────────────────────────────────────────

Result = collections.namedtuple("Result", "host port state elapsed banner")


class Prober:
    """Turns one connect() into a state, using elapsed time as the signal.

    Under a proxy the exception type says nothing, so the split is purely
    temporal: a negative that returned fast is the chain's definitive answer, a
    negative that consumed most of the read timeout is a stall. Running direct,
    the errno is meaningful again and is used, with the timing rule kept as a
    backstop for a refusal that somehow outlived the whole budget.
    """

    def __init__(self, timeout, stall_threshold, proxied, banner=False):
        self.timeout = timeout
        self.stall_threshold = stall_threshold
        self.proxied = proxied
        self.banner = banner

    def __call__(self, task):
        host, port = task
        started = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            return self._negative(host, port, time.monotonic() - started)
        except (socket.timeout, TimeoutError):
            return Result(host, port, FILTERED, time.monotonic() - started, None)
        except OSError:
            # Direct: unreachable/unroutable, which is not a closed port.
            # Proxied: unreachable never gets this far, it arrives as
            # ECONNREFUSED, so this branch stays honest in both modes.
            if self.proxied:
                return self._negative(host, port, time.monotonic() - started)
            return Result(host, port, FILTERED, time.monotonic() - started, None)
        else:
            banner = self._read_banner(sock) if self.banner else None
            return Result(host, port, OPEN, time.monotonic() - started, banner)
        finally:
            sock.close()

    def _negative(self, host, port, elapsed):
        state = FILTERED if elapsed >= self.stall_threshold else CLOSED
        return Result(host, port, state, elapsed, None)

    def _read_banner(self, sock):
        sock.settimeout(min(self.timeout, 2.0))
        try:
            data = sock.recv(BANNER_BYTES)
        except OSError:
            return None
        return clean(data.decode("latin-1", "replace"))[:120] or None


# ── Pacing ────────────────────────────────────────────────────────────

class RateLimiter:
    """Global connects-per-second cap; a no-op when rate is 0."""

    def __init__(self, rate):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._next_slot = 0.0
        self._lock = threading.Lock()

    def take(self, stop):
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self.interval
        delay = slot - time.monotonic()
        if delay > 0:
            stop.wait(delay)


# ── Sweep engine ──────────────────────────────────────────────────────

class Sweep:
    """Runs probes over a worker pool while watching the chain.

    Negative results are trusted only as far as the last proof that the chain
    works. After a long run of them the control target is re-probed; if it has
    stopped answering, every negative recorded since the last confirmation is
    revoked and re-queued, because a dead proxy produces exactly the same
    instant ECONNREFUSED as a closed port.
    """

    def __init__(self, prober, concurrency, limiter, canaries, canary_after,
                 chain_wait):
        self.prober = prober
        self.concurrency = concurrency
        self.limiter = limiter
        self.canaries = list(canaries)
        self.explicit_canaries = bool(canaries)
        self.canary_after = canary_after
        self.chain_wait = chain_wait

        self.stop = threading.Event()
        self.go = threading.Event()
        self.go.set()

        self.epoch = 0                          # bumped on every outage
        self.miss_streak = 0
        self.unverified = collections.deque()   # negatives since last proof
        self.outages = 0
        self.chain_verified = False
        self.chain_broken = False

    def _guarded(self, task):
        """One probe, respecting the pause gate and the rate limit.

        The epoch is captured before the probe so a result that spanned a
        chain outage can be recognised and thrown away: a connect already
        inside the hook when the proxy died returns the same instant
        ECONNREFUSED as a closed port.
        """
        self.go.wait()
        if self.stop.is_set():
            return None
        epoch = self.epoch
        self.limiter.take(self.stop)
        if self.stop.is_set():
            return None
        return epoch, self.prober(task)

    def run(self, tasks, record, revoke):
        """Drive *tasks* through the pool.

        ``record(result)`` accepts a result; ``revoke(host, port)`` withdraws
        one that the chain turned out to have invented.
        """
        queue = collections.deque(tasks)
        if not queue:
            return
        inflight = {}
        pool = futures.ThreadPoolExecutor(max_workers=self.concurrency)
        try:
            while (queue or inflight) and not self.stop.is_set():
                while queue and len(inflight) < self.concurrency * 2:
                    task = queue.popleft()
                    inflight[pool.submit(self._guarded, task)] = task
                if not inflight:
                    break
                done, _ = futures.wait(set(inflight),
                                       return_when=futures.FIRST_COMPLETED)
                for future in done:
                    task = inflight.pop(future)
                    try:
                        payload = future.result()
                    except Exception:
                        # One bad probe must never take the sweep down.
                        payload = (self.epoch,
                                   Result(task[0], task[1], FILTERED, 0.0, None))
                    if payload is None:         # returned during shutdown
                        continue
                    epoch, result = payload
                    if epoch != self.epoch:
                        queue.append(task)      # spanned an outage; meaningless
                        continue
                    queue.extend(self._observe(result, record, revoke))
        finally:
            still_running = [f for f in inflight if not f.cancel()]
            if still_running and self.stop.is_set():
                # A connect already inside the hook cannot be cancelled; it
                # runs until the chain's timeout. Say so rather than looking
                # wedged for the length of the budget.
                note(f"waiting for {len(still_running)} in-flight probe(s) to "
                     f"time out")
            pool.shutdown(wait=True)

    def _observe(self, result, record, revoke):
        """Record a result and return any probes that need re-running."""
        if result.state == OPEN:
            self._confirm_chain(result)
            record(result)
            return ()

        record(result)
        self.miss_streak += 1
        self.unverified.append((result.host, result.port))
        if not self.canaries or self.miss_streak < self.canary_after:
            return ()

        if self._canary_answers():
            self._reset_streak()
            return ()
        return self._await_chain(revoke)

    def _confirm_chain(self, result):
        self.chain_verified = True
        self._reset_streak()
        if self.explicit_canaries:
            # An operator-supplied control target is authoritative and is never
            # displaced by something the sweep happened to find. Preferring
            # discovered ports over --canary is how the previous design ended
            # up health-checking a random junk service and hanging on it.
            return
        target = (result.host, result.port)
        if target not in self.canaries and len(self.canaries) < AUTO_CANARY_LIMIT:
            # Open ports double as control targets: live proof the chain works,
            # and re-probing them is how a dead chain is later told apart from
            # a genuinely quiet network. Keep a few, so one flaky host cannot
            # convince the sweep that a healthy chain has died.
            self.canaries.append(target)

    def _reset_streak(self):
        self.miss_streak = 0
        self.unverified.clear()

    def _canary_answers(self):
        return any(self.prober(target).state == OPEN for target in self.canaries)

    def _await_chain(self, revoke):
        """Pause, wait for the chain, then hand back the suspect probes."""
        self.outages += 1
        self.epoch += 1          # invalidate everything already in flight
        self.go.clear()
        host, port = self.canaries[0]
        suspect = list(dict.fromkeys(self.unverified))
        for probe in suspect:
            revoke(*probe)
        warn(f"chain down -- control target {host}:{port} stopped answering. "
             f"Pausing; {len(suspect)} unverified result(s) withdrawn.")

        deadline = time.monotonic() + self.chain_wait if self.chain_wait else None
        delay, gave_up = 2.0, False
        while not self.stop.is_set():
            wait = delay
            if deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    gave_up = True
                    break
                wait = min(delay, remaining)    # never overshoot the deadline
            if self.stop.wait(wait):
                break
            if self._canary_answers():
                self._reset_streak()
                self.go.set()
                note(f"chain back -- re-running {len(suspect)} probe(s)")
                return suspect
            delay = min(delay * 1.5, 30.0)

        # Giving up beats hanging: with the chain down every remaining probe
        # returns an instant ECONNREFUSED and would be recorded as "closed",
        # turning a broken run into a clean-looking empty result.
        self.chain_broken = True
        self.stop.set()
        self.go.set()
        if gave_up:
            warn(f"chain did not return within {human_time(self.chain_wait)} -- "
                 f"abandoning the sweep, because every remaining probe would "
                 f"look closed")
        return ()


# ── Progress ──────────────────────────────────────────────────────────

class Progress:
    """A single self-updating status line on stderr.

    Deliberately not an alternate-screen dashboard: a proxied sweep is slow,
    the operator wants to keep whatever else is on screen, and anything drawn
    on the alternate buffer is discarded at exit -- including warnings.
    """

    def __init__(self, total, enabled):
        self.total = max(0, total)
        self.enabled = enabled
        self.done = 0
        self.open_count = 0
        self.stalls = 0
        self.started = time.monotonic()
        self._last_paint = self.started
        self._painted = 0

    def update(self, result):
        self.done += 1
        if result.state == OPEN:
            self.open_count += 1
        elif result.state == FILTERED:
            self.stalls += 1
        if not self.enabled:
            return
        now = time.monotonic()
        if now - self._last_paint < (0.2 if _TTY else PROGRESS_LOG_EVERY):
            return
        self._last_paint = now
        self._paint()

    def withdraw(self, count):
        self.done = max(0, self.done - count)

    def _line(self):
        elapsed = time.monotonic() - self.started
        rate = self.done / elapsed if elapsed > 0.5 else 0.0
        eta = human_time((self.total - self.done) / rate) if rate > 0.1 else "?"
        pct = 100.0 * self.done / self.total if self.total else 100.0
        return (f"  {paint('sweep', 'cyan')} {pct:5.1f}%  {self.done}/{self.total}"
                f"  {paint(f'{self.open_count} open', 'green')}"
                f"  {self.stalls} stalled  {rate:.0f}/s  eta {eta}")

    def _paint(self):
        line = self._line()
        if not _TTY:
            sys.stderr.write(line + "\n")
            sys.stderr.flush()
            return
        width = _visible_width(line)
        sys.stderr.write("\r" + line + " " * max(0, self._painted - width))
        sys.stderr.flush()
        self._painted = width

    def clear(self):
        if self.enabled and _TTY and self._painted:
            sys.stderr.write("\r" + " " * self._painted + "\r")
            sys.stderr.flush()
            self._painted = 0


def _visible_width(text):
    return len(re.sub(r"\033\[[0-9;]*m", "", text))


# ── Results ───────────────────────────────────────────────────────────

class Report:
    def __init__(self):
        self.hosts = {}            # host -> {port: (state, banner)}
        self.skipped = []          # hosts dropped by the discovery pass
        self.started = time.time()

    def record(self, result):
        self.hosts.setdefault(result.host, {})[result.port] = (
            result.state, result.banner)

    def revoke(self, host, port):
        self.hosts.get(host, {}).pop(port, None)

    def probed(self):
        return {(host, port) for host, ports in self.hosts.items() for port in ports}

    def open_ports(self):
        found = {}
        for host, ports in self.hosts.items():
            hits = sorted(p for p, (state, _) in ports.items() if state == OPEN)
            if hits:
                found[host] = hits
        return found

    def counts(self):
        tally = {OPEN: 0, CLOSED: 0, FILTERED: 0}
        for ports in self.hosts.values():
            for state, _ in ports.values():
                tally[state] = tally.get(state, 0) + 1
        return tally

    def responsive(self):
        """Hosts that answered anything other than a stall.

        Through a proxy this is not proof the *host* is up -- the chain itself
        may be refusing -- which is why the summary says "responsive".
        """
        return [host for host, ports in self.hosts.items()
                if any(state != FILTERED for state, _ in ports.values())]

    def as_dict(self, meta):
        hosts = []
        for host in sorted(self.hosts, key=ipaddress.ip_address):
            entries = []
            for port in sorted(self.hosts[host]):
                state, banner = self.hosts[host][port]
                if state == FILTERED:
                    continue
                entry = {"port": port, "state": state}
                if banner:
                    entry["banner"] = banner
                entries.append(entry)
            if entries:
                hosts.append({"host": host, "ports": entries})
        return {
            "tool": "tcpsweep",
            "version": __version__,
            "started": self.started,
            "ended": time.time(),
            **meta,
            "summary": self.counts(),
            "skipped_hosts": self.skipped,
            "hosts": hosts,
        }


class Stream:
    """Open ports to stdout, one per line, flushed -- safe to pipe or tee.

    Only open ports are streamed, and an open port is never revoked, so
    anything that reaches stdout is final even if the run is interrupted.
    """

    def __init__(self, with_banner):
        self.with_banner = with_banner

    def emit(self, result):
        line = f"{result.host} {result.port}"
        if self.with_banner and result.banner:
            line += f"\t{result.banner}"
        try:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except OSError:
            pass


class Journal:
    """Durable append-only record of completed probes, enabling --resume.

    Written and flushed as each result lands, so an interrupted sweep loses at
    most the probes that were in flight. Through a chain with a 30s read
    timeout a wide sweep runs for hours, and losing all of it to one Ctrl+C is
    not acceptable.

    Resume is deliberately explicit. The predecessor auto-resumed whatever
    state file sat next to the output name, so a *finished* scan's results were
    replayed as if live -- ports reported open with no packet sent, and no
    visible sign it had happened. Here the operator names the file, asks for
    it, and is told how many results were carried over.

    Revocations are journalled too. A chain outage withdraws the negatives it
    produced, and without a matching record they would come back on the next
    resume as though they had been real.
    """

    def __init__(self, path):
        self.path = path
        self._handle = None

    def load(self):
        """Return ``({(host, port): (state, banner)}, header_metadata)``."""
        results, meta = {}, {}
        if not os.path.exists(self.path):
            return results, meta
        try:
            with open(self.path, "r", errors="replace") as handle:
                lines = handle.read().splitlines()
        except OSError as exc:
            die(f"cannot read resume journal {self.path!r}: {exc}")
        damaged = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                damaged += 1          # a kill mid-write can truncate the tail
                continue
            if "tcpsweep" in entry:
                meta = entry
            elif entry.get("x"):
                results.pop((entry.get("h"), entry.get("p")), None)
            elif "s" in entry and "h" in entry and "p" in entry:
                results[(entry["h"], entry["p"])] = (entry["s"], entry.get("b"))
            else:
                damaged += 1
        if damaged:
            warn(f"{self.path}: ignored {damaged} unreadable line(s)")
        return results, meta

    def open(self, meta):
        try:
            descriptor = os.open(self.path,
                                 os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        except OSError as exc:
            die(f"cannot write resume journal {self.path!r}: {exc}")
        fresh = os.fstat(descriptor).st_size == 0
        self._handle = os.fdopen(descriptor, "a")
        if fresh:
            self._append({"tcpsweep": __version__, **meta})

    def _append(self, entry):
        if self._handle is None:
            return
        try:
            self._handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
            # flush, not fsync: this survives Ctrl+C and a crashed process,
            # which is what resume is for, without an fsync per probe.
            self._handle.flush()
        except OSError:
            pass

    def record(self, result):
        entry = {"h": result.host, "p": result.port, "s": result.state}
        if result.banner:
            entry["b"] = result.banner
        self._append(entry)

    def revoke(self, host, port):
        self._append({"h": host, "p": port, "x": 1})

    def close(self):
        if self._handle is not None:
            with contextlib.suppress(OSError):
                self._handle.close()
            self._handle = None


def carry_over(journal, report, stream, hosts, ports):
    """Seed the report from a journal, restricted to this run's scope.

    Scope matters: a journal from a wider sweep must not smuggle hosts or
    ports the current invocation never asked about into its results.

    Carried entries deliberately bypass the sweep engine. They are not proof
    the chain works *now*, so they must not arm the canary or mark the chain
    verified -- that has to be earned by a live probe.
    """
    stored, meta = journal.load()
    if not stored:
        return 0, meta
    in_scope_hosts, in_scope_ports = set(hosts), set(ports)
    carried = 0
    for (host, port), (state, banner) in stored.items():
        if host not in in_scope_hosts or port not in in_scope_ports:
            continue
        report.record(Result(host, port, state, 0.0, banner))
        if state == OPEN:
            # Re-emit so a resumed run's stdout is the complete finding set.
            stream.emit(Result(host, port, state, 0.0, banner))
        carried += 1
    return carried, meta


# ── Presentation ──────────────────────────────────────────────────────

def print_header(proxy, hosts, ports, args):
    out = sys.stderr.write
    out("\n" + paint(f"  tcpsweep {__version__}", "bold") + "\n")
    if proxy.active:
        out(f"  {paint('chain', 'cyan')}    {proxy.describe()}\n")
        if proxy.conf_path:
            out(paint(f"           {proxy.conf_path}\n", "dim"))
    else:
        out(f"  {paint('chain', 'cyan')}    none, running direct "
            f"(timeout {args.timeout:g}s)\n")
    out(f"  {paint('targets', 'cyan')}  {len(hosts)} host(s) x {len(ports)} "
        f"port(s) = {len(hosts) * len(ports)} probes\n")
    mode = "discovery on" if args.discover else "discovery off"
    extra = f" / {args.rate:g}/s" if args.rate else ""
    out(f"  {paint('sweep', 'cyan')}    {mode} / concurrency "
        f"{args.concurrency}{extra}\n\n")


def print_summary(report, proxy, sweep, elapsed, caveat):
    counts = report.counts()
    found = report.open_ports()
    out = sys.stderr.write

    out("\n" + paint("  results", "bold") + "\n")
    if found:
        width = max(len(host) for host in found)
        for host in sorted(found, key=ipaddress.ip_address):
            ports = report.hosts[host]
            shown = []
            for port in found[host]:
                banner = ports[port][1]
                shown.append(f"{port}" + (f" [{banner[:40]}]" if banner else ""))
            out(f"    {paint('+', 'green')} {host:<{width}}  "
                f"{paint(', '.join(shown), 'green')}\n")
    else:
        out(paint("    no open ports\n", "dim"))

    parts = [f"{counts[OPEN]} open", f"{counts[CLOSED]} closed",
             f"{counts[FILTERED]} stalled",
             f"{len(report.responsive())} responsive host(s)"]
    if report.skipped:
        parts.append(f"{len(report.skipped)} skipped")
    out(paint(f"\n  {' / '.join(parts)}  in {human_time(elapsed)}\n", "dim"))

    if proxy.active:
        out(paint("  note: through a chain, 'closed' only means the proxy "
                  "answered fast; that is\n        indistinguishable from "
                  "host-unreachable or a ruleset denial.\n", "dim"))
    if sweep.outages:
        warn(f"the chain dropped {sweep.outages} time(s); affected probes were "
             f"re-run")
    if caveat:
        warn(caveat)


# ── CLI ───────────────────────────────────────────────────────────────

def program_name():
    name = os.path.basename(sys.argv[0] or "") or "tcpsweep"
    return name[:-3] if name.endswith(".py") else name


def build_parser():
    prog = program_name()
    discover_default = ",".join(str(p) for p in DEFAULT_DISCOVER_PORTS)
    parser = argparse.ArgumentParser(
        prog=prog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="TCP connect sweep designed to run through proxychains.",
        epilog=f"""\
examples:
  proxychains4 {prog} 10.0.0.0/24                  top {DEFAULT_TOP_PORTS} ports, discovery on
  proxychains4 {prog} 10.0.0.0/16 -p 445 -c 64     one port, wide, high concurrency
  proxychains4 {prog} 10.0.0.5 -p 1-1024 --no-discover
  proxychains4 {prog} -iL targets.txt -p 22,80 --canary 10.0.0.1:22
  proxychains4 {prog} 10.0.0.0/16 -p 445 --resume sweep.jsonl   resumable
  {prog} 10.0.0.0/24 -p 80 --json out.json         direct, no proxy

exit codes:
  {EXIT_FOUND}  open ports found        {EXIT_USAGE}  bad arguments
  {EXIT_NONE}  nothing open            {EXIT_PROXY}  chain failed and stayed down
  {EXIT_INTERRUPT}  interrupted

under proxychains:
  -w/--timeout cannot be enforced. The SOCKS handshake happens inside the
  hooked connect(), so tcp_read_time_out from the proxychains config is the
  real budget; it is read automatically and shown above the sweep. Raise -c
  rather than lowering -w to go faster, because a stalled probe always costs
  the full timeout.
""")
    parser.add_argument("targets", nargs="*", metavar="TARGET",
                        help="IP, CIDR, 10.0.0.1-20, 10.0.0.{1,5-9}, or "
                             "hostname. Bare numbers are read as ports, so "
                             "'10.0.0.1 22 80' works like '-p 22,80'")
    parser.add_argument("-iL", "--target-file", metavar="FILE", action="append",
                        default=[], help="read targets from FILE ('-' for stdin)")
    parser.add_argument("--exclude", metavar="SPEC", action="append", default=[],
                        help="exclude these targets (repeatable)")

    group = parser.add_argument_group("ports")
    group.add_argument("-p", "--ports", metavar="LIST", action="append", default=[],
                       help=f"22,80,443 or 1-1024 (default: top {DEFAULT_TOP_PORTS})")
    group.add_argument("--top", type=int, metavar="N",
                       help=f"the N most common TCP ports (max {len(TOP_PORTS)})")

    group = parser.add_argument_group("sweep")
    group.add_argument("-c", "--concurrency", "-t", "--threads", type=int,
                       metavar="N", default=DEFAULT_CONCURRENCY,
                       help=f"parallel connects (default: {DEFAULT_CONCURRENCY}); "
                            "the main speed control, since stalls cost the full "
                            "proxy timeout")
    group.add_argument("-w", "--timeout", type=float, metavar="S",
                       default=DEFAULT_TIMEOUT,
                       help=f"connect budget when direct (default: "
                            f"{DEFAULT_TIMEOUT:g}s); advisory under a proxy")
    group.add_argument("--rate", type=float, metavar="N", default=0,
                       help="cap at N connects/second (default: unlimited)")
    group.add_argument("--shuffle", "-r", "--random", action="store_true",
                       help="randomise probe order")
    group.add_argument("-b", "--banner", action="store_true",
                       help="read a short banner from each open port")

    group = parser.add_argument_group("discovery")
    group.add_argument("--no-discover", dest="discover", action="store_false",
                       help="skip the liveness pass and probe every port on "
                            "every host")
    group.add_argument("--discover-ports", metavar="LIST", default=discover_default,
                       help=f"liveness-pass ports (default: {discover_default})")

    group = parser.add_argument_group("chain health")
    group.add_argument("--canary", "--ct", metavar="HOST:PORT",
                       action="append", default=[],
                       help="known-open control target, checked at startup and "
                            "never displaced by a discovered port. Without one "
                            "the sweep cannot tell a dead proxy from an "
                            "all-closed result")
    group.add_argument("--canary-after", type=int, metavar="N",
                       default=DEFAULT_CANARY_AFTER,
                       help=f"re-check the control target after N consecutive "
                            f"non-open results (default: {DEFAULT_CANARY_AFTER})")
    group.add_argument("--chain-wait", type=float, metavar="S",
                       default=DEFAULT_CHAIN_WAIT,
                       help=f"how long to wait for a dead chain before giving "
                            f"up and exiting {EXIT_PROXY} (default: "
                            f"{DEFAULT_CHAIN_WAIT:g}s, 0 waits forever)")

    group = parser.add_argument_group("output")
    group.add_argument("--json", metavar="FILE", help="write structured results")
    group.add_argument("--resume", metavar="FILE",
                       help="journal every probe to FILE as it completes, and "
                            "on a re-run skip what FILE already holds. Never "
                            "automatic: name the file to opt in")
    group.add_argument("-q", "--quiet", action="store_true",
                       help="suppress progress and the summary")
    group.add_argument("--no-progress", dest="progress", action="store_false",
                       help="keep the summary, drop the live progress line")
    group.add_argument("--version", action="version",
                       version=f"%(prog)s {__version__}")
    return parser


def verify_canaries(prober, canaries):
    """Prove a supplied control target is open before trusting its verdict.

    The canary decides whether the chain is alive, so a mistyped or dead one
    fails every health check and would declare a perfectly good chain dead
    partway through the sweep -- pausing every worker to wait for a target that
    was never going to answer. Checking now turns that into an immediate,
    obvious error.
    """
    for host, port in canaries:
        if prober((host, port)).state == OPEN:
            return host, port
    return None


def parse_canaries(values):
    targets = []
    for value in values:
        host, sep, port = value.rpartition(":")
        if not sep or not host or not port.isdigit():
            die(f"bad canary {value!r}, expected HOST:PORT")
        targets.append((host, one_port(port)))
    return targets


PORT_TOKEN_CHARS = set("0123456789,-:")


def split_positionals(values):
    """Separate positional targets from positional ports.

    A token built only from digits and range punctuation is a port list, so the
    familiar ``sweep HOST 22 80 443`` form keeps working alongside ``-p``. No
    address can be digits-only, and every other form carries a dot, slash,
    brace or letter, so the split is unambiguous.
    """
    targets, ports = [], []
    for value in values:
        token = value.strip()
        if not token:
            continue
        if set(token) <= PORT_TOKEN_CHARS and any(c.isdigit() for c in token):
            ports.append(token)
        else:
            targets.append(token)
    return targets, ports


def resolve_scope(args, proxy):
    specs, positional_ports = split_positionals(args.targets)
    for path in args.target_file:
        specs.extend(read_target_file(path))
    if not specs:
        die("no targets given (try --help)")
    hosts = collect_targets(specs, args.exclude, proxy)
    if not hosts:
        die("no targets left after exclusions")

    ports = parse_ports(positional_ports + args.ports)
    if args.top is not None:
        if args.top < 1:
            die("--top must be >= 1")
        ports = sorted(set(ports) | set(TOP_PORTS[:args.top]))
    if not ports:
        ports = sorted(TOP_PORTS[:DEFAULT_TOP_PORTS])
    return hosts, ports


def validate(args):
    if args.concurrency < 1:
        die("--concurrency must be >= 1")
    if args.canary_after < 1:
        die("--canary-after must be >= 1")
    if args.rate < 0:
        die("--rate cannot be negative")
    if args.chain_wait < 0:
        die("--chain-wait cannot be negative")
    if args.timeout < 0:
        die(f"--timeout cannot be negative (got {args.timeout:g})")
    if args.timeout == 0:
        # settimeout(0) is non-blocking mode, not "no timeout": connect()
        # raises immediately and every port, live listeners included, reads as
        # unreachable. Scripts in the wild pass -w 0, so degrade loudly rather
        # than breaking a working command line.
        warn(f"-w 0 is not 'no timeout' -- a zero timeout makes the socket "
             f"non-blocking and reports every port, even open ones, as "
             f"unreachable. Using {DEFAULT_TIMEOUT:g}s instead.")
        args.timeout = DEFAULT_TIMEOUT


def tune(args, proxy):
    """Pick the socket timeout and the stall threshold for this environment."""
    if not proxy.active:
        return args.timeout, max(0.1, args.timeout * 0.9)
    # The chain's own budget governs, so keep a socket ceiling well above it:
    # low enough to catch a truly wedged connection, high enough that it never
    # pre-empts a real answer from the proxy.
    return proxy.budget * 1.5, proxy.stall_threshold


def sweep_all(sweep, report, stream, progress, hosts, ports, args,
              discover_ports, journal=None):
    """Discovery pass, then the full sweep across hosts worth probing."""

    def record(result):
        report.record(result)
        if journal:
            journal.record(result)
        if result.state == OPEN:
            stream.emit(result)
        progress.update(result)

    def revoke(host, port):
        report.revoke(host, port)
        if journal:
            journal.revoke(host, port)
        progress.withdraw(1)

    live = hosts
    use_discovery = bool(discover_ports) and len(hosts) > 1
    # Upper bound: the discovery pass plus a full sweep of everything it does
    # not already cover. Corrected downward once triage has run.
    extra = len(set(discover_ports) - set(ports)) if use_discovery else 0
    progress.total = max(0, len(hosts) * (len(ports) + extra)
                         - len(report.probed()))

    if use_discovery:
        resumed = report.probed()
        tasks = [(host, port) for host in hosts for port in discover_ports
                 if (host, port) not in resumed]
        if args.shuffle:
            random.shuffle(tasks)
        sweep.run(tasks, record, revoke)
        if sweep.stop.is_set():
            return
        live, report.skipped = triage(hosts, report)
        if report.skipped:
            progress.clear()
            note(f"{len(report.skipped)} host(s) stalled on every discovery "
                 f"port and were skipped -- each would have cost the full "
                 f"proxy timeout per port")

    # Discovery results are real results: never re-probe a pair already done.
    already = report.probed()
    tasks = [(host, port) for host in live for port in ports
             if (host, port) not in already]
    progress.total = progress.done + len(tasks)
    if args.shuffle:
        random.shuffle(tasks)
    sweep.run(tasks, record, revoke)


def triage(hosts, report):
    """Split hosts into worth-sweeping and black-holed.

    A host that answered anything fast is cheap to sweep, so it stays. A host
    where every discovery probe stalled costs the full proxy timeout on every
    port, which is where a wide sweep burns its time -- drop it.
    """
    live, skipped = [], []
    for host in hosts:
        states = [state for state, _ in report.hosts.get(host, {}).values()]
        if states and all(state == FILTERED for state in states):
            skipped.append(host)
        else:
            live.append(host)
    return live, skipped


def install_sigint(sweep):
    hit = {"value": False}

    def handler(_signum, _frame):
        hit["value"] = True
        sweep.stop.set()
        sweep.go.set()          # release anything parked on the pause gate

    with contextlib.suppress(ValueError, OSError):
        signal.signal(signal.SIGINT, handler)
    return hit


def main():
    args = build_parser().parse_args()
    validate(args)
    proxy = Proxy.detect()
    hosts, ports = resolve_scope(args, proxy)
    timeout, stall_threshold = tune(args, proxy)

    if not args.quiet:
        print_header(proxy, hosts, ports, args)

    prober = Prober(timeout, stall_threshold, proxy.active, args.banner)

    canaries = parse_canaries(args.canary)
    if canaries:
        confirmed = verify_canaries(prober, canaries)
        if confirmed is None:
            listed = ", ".join(f"{host}:{port}" for host, port in canaries)
            die(f"control target {listed} did not answer open. It has to be a "
                f"host:port reachable through this chain, because every health "
                f"check asks it whether the chain is still alive -- a dead one "
                f"would stall the sweep waiting for it to come back.")
        if not args.quiet:
            note(f"control target {confirmed[0]}:{confirmed[1]} confirmed open")

    sweep = Sweep(prober, args.concurrency, RateLimiter(args.rate),
                  canaries, args.canary_after, args.chain_wait)
    if canaries:
        # The preflight probe above is itself live proof the chain works, so a
        # run that finds nothing (or resumes everything) must not also claim
        # the chain was never confirmed.
        sweep.chain_verified = True
    report = Report()
    stream = Stream(args.banner)
    progress = Progress(len(hosts) * len(ports),
                        args.progress and not args.quiet)
    discover_ports = parse_ports([args.discover_ports]) if args.discover else []

    journal = carried = None
    if args.resume:
        journal = Journal(args.resume)
        carried, meta = carry_over(journal, report, stream, hosts,
                                   set(ports) | set(discover_ports))
        if carried and not args.quiet:
            note(f"resumed {carried} probe(s) from {args.resume}; those ports "
                 f"are not re-probed")
            age = time.time() - meta.get("started", time.time())
            if age > 86400:
                warn(f"that journal is {human_time(age)} old -- the carried "
                     f"results describe the network as it was then")
        journal.open({"started": time.time(), "targets": len(hosts),
                      "ports": len(ports)})

    interrupted = install_sigint(sweep)
    started = time.monotonic()
    try:
        sweep_all(sweep, report, stream, progress, hosts, ports, args,
                  discover_ports, journal)
    finally:
        progress.clear()
        if journal:
            journal.close()
    elapsed = time.monotonic() - started

    caveat = None
    if proxy.active and not sweep.chain_verified:
        caveat = ("no open port was seen, so the chain was never confirmed "
                  "working -- an all-negative result through a proxy is "
                  "indistinguishable from a dead one. Re-run with "
                  "--canary HOST:PORT to make this conclusive.")

    if args.json:
        meta = {
            "targets": len(hosts),
            "ports_per_host": len(ports),
            "proxied": proxy.active,
            "proxy": proxy.describe() if proxy.active else None,
            "chain_outages": sweep.outages,
            "chain_verified": sweep.chain_verified,
            "interrupted": interrupted["value"],
            "resumed_from": args.resume,
            "resumed_probes": carried or 0,
        }
        try:
            write_private(args.json,
                          json.dumps(report.as_dict(meta), indent=2) + "\n")
        except OSError as exc:
            warn(f"could not write {args.json}: {exc}")

    if not args.quiet:
        print_summary(report, proxy, sweep, elapsed, caveat)

    if interrupted["value"]:
        if not args.quiet:
            warn("interrupted -- the results above are partial")
        return EXIT_INTERRUPT
    if sweep.chain_broken:
        return EXIT_PROXY
    return EXIT_FOUND if report.counts()[OPEN] else EXIT_NONE


if __name__ == "__main__":
    sys.exit(main())
