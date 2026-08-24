#!/usr/bin/env python3
"""A netcat-style TCP connect sweep.

Sends the same probe as ``nc -z`` (a full TCP connect) to every host/port in a
target spec and reports which ports are open.  Standard library only, single
file — so it can be dropped onto any box with a Python 3 interpreter and run
directly (``./tcpsweep.py ...``) or as a module (``python3 -m tcpsweep ...``).

Discovered open ports are streamed to **stdout** (one ``IP PORT`` line each) so
the tool composes in a pipeline; progress and the summary go to **stderr**.
Results are also written to ``NAME.json`` and ``NAME.gnmap`` and a resumable
``NAME.state.json`` — all written atomically and owner-readable only (0600),
since a scan result is sensitive reconnaissance data.

Examples::

    tcpsweep 192.168.1.1 22 80 443
    tcpsweep 192.168.1.0/24 -p 22,80,443 -t 16
    tcpsweep 10.0.0.{1-10,254} -p 1-1024 -r -o office
    tcpsweep 192.168.1.1 -p 1-65535 -w 2 -P 0.2        # rate-limited, 0.2s gap
    tcpsweep 10.0.0.0/24 -p 22 -b                        # grab banners
"""

import argparse
import collections
import contextlib
import csv
import hashlib
import io
import ipaddress
import json
import os
import random
import signal
import socket
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

__version__ = "0.2.0"

# ── ANSI helpers ──────────────────────────────────────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[2m"

CURSOR_SHOW = "\033[?25h"
CURSOR_HIDE = "\033[?25l"
_ALT_ON = "\033[?1049h"      # switch to the alternate screen buffer
_ALT_OFF = "\033[?1049l"     # …and back, discarding everything drawn on it
_HOME = "\033[H"             # cursor to top-left
_CLR_SCREEN = "\033[2J"     # clear whole screen
_CLR_EOL = "\033[K"         # clear to end of line
_CLR_EOS = "\033[J"         # clear to end of screen

# Port state shown as a literal switch: filled = on (open), ring = off
# (closed), half = uncertain (filtered).  Matches the open/closed usecase
# instead of a plain word.
_SWITCH_OPEN = "●"
_SWITCH_CLOSED = "○"
_SWITCH_FILTERED = "◐"

# Live dashboard only when stderr is a terminal.
_COLORS_ON = sys.stderr.isatty()


def c(text, color):
    """Wrap *text* in an ANSI *color* when the terminal supports it."""
    return f"{color}{text}{_RESET}" if _COLORS_ON else str(text)


def _die(msg):
    """Print a clean one-line error to stderr and exit non-zero."""
    print(c(f"Error: {msg}", _RED), file=sys.stderr)
    sys.exit(1)


def _warn(msg):
    """Print a non-fatal warning to stderr."""
    sys.stderr.write("\n" + c(f"  ! {msg}", _YELLOW) + "\n")
    sys.stderr.flush()


def _sanitize(text):
    """Reduce *text* to stripped, printable ASCII.

    Banners are read from untrusted remote hosts.  Writing them to a terminal
    verbatim would let a hostile service inject ANSI escape sequences (cursor
    moves, screen clears, title rewriting, even some terminal exploits) or
    smuggle control characters into the output files.  Collapsing everything
    outside printable ASCII to ``.`` neutralises that.  This is a security
    control, not cosmetics — keep it on every path that surfaces banner bytes.
    """
    if not text:
        return ""
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text).strip()


# ── Atomic, private file writes ───────────────────────────────────────

def _atomic_write(path, data, *, mode=0o600):
    """Write *data* to *path* atomically, owner-readable only.

    A scan is long-running and routinely killed (Ctrl+C, disk full, power
    loss); the resumable ``.state.json`` must never be left half-written, or
    the next run would crash trying to parse it.  Writing to a unique temp
    file in the same directory and then ``os.replace``-ing it into place makes
    the swap atomic on POSIX — readers see either the old file or the new one,
    never a truncated mix.  ``mkstemp`` also gives each concurrent writer a
    distinct temp name, and the 0600 mode keeps the (sensitive) results out of
    other users' reach on a shared host.
    """
    path = Path(path)
    directory = path.parent if str(path.parent) else Path(".")
    fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=f".{path.name}.",
                               suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ── IP expansion ──────────────────────────────────────────────────────

def expand_ips(spec):
    """Expand *spec* into a version-sorted list of dotted-quad strings.

    Supported formats:
      - Single IP:             192.168.1.1
      - CIDR:                  192.168.1.0/24
      - Comma-separated:       10.0.0.1,10.0.0.2,10.0.0.3
      - Last-octet dash range: 192.168.1.1-10
      - Nmap-style braces:     192.168.1.{1-5,254}

    Any component that produces an invalid address exits with a clear error
    instead of crashing later.
    """
    ips = set()
    for part in _split_respecting_braces(spec):
        part = part.strip()
        if not part:
            continue
        if "{" in part:
            ips.update(_brace_expand(part, spec))
        elif "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                _die(f"Invalid CIDR: {part} ({exc})")
            ips.update(str(h) for h in net.hosts())
        elif _dash_range(part):
            ips.update(_expand_dash(part, spec))
        else:
            ip = _try_ip(part)
            if ip is not None:
                ips.add(ip)
            elif any(ch.isalpha() for ch in part):
                ips.update(_resolve_host(part, spec))   # DNS name → IPv4(s)
            else:
                _die(f"Invalid IP: {part!r} in {spec!r}")
    return sorted(ips, key=ipaddress.ip_address)


def _try_ip(part):
    """Return the normalised address if *part* is a literal IP, else None."""
    try:
        return str(ipaddress.ip_address(part))
    except ValueError:
        return None


def _valid_ip(part, spec):
    ip = _try_ip(part)
    if ip is None:
        _die(f"Invalid IP: {part!r} in {spec!r}")
    return ip


def _resolve_host(name, spec):
    """Resolve a DNS name to its (de-duplicated) IPv4 addresses.

    Accepting hostnames — and folding several names that point at the same box
    into one scan target — is a big convenience for real recon (scan
    ``example.com`` or a whole subdomain list, not just literal IPs). We stay
    IPv4-only to match the connect scanner's ``AF_INET`` socket.
    """
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        _die(f"Could not resolve host: {name!r} in {spec!r}")
    addrs = {info[4][0] for info in infos}
    if _under_proxychains():
        # With proxy_dns, proxychains hooks getaddrinfo() and hands back a
        # synthetic address (224.0.0.x by default) that it maps back to the
        # hostname inside connect().  The scan is correct, but every result is
        # then *labelled* with an address that does not exist — useless in a
        # report and easy to mistake for a finding.
        fake = sorted(a for a in addrs
                      if ipaddress.ip_address(a).is_multicast
                      or ipaddress.ip_address(a).is_reserved)
        if fake:
            _warn(f"{name} resolved to {', '.join(fake)} — a proxychains DNS "
                  f"placeholder, not a real address. The scan still reaches the "
                  f"right host (proxychains maps it back when it connects), but "
                  f"results are labelled with the placeholder. Scan a literal IP "
                  f"if the report needs real addresses.")
    return addrs


def resolve_targets(specs, exclude=()):
    """Expand every spec (IP/CIDR/range/brace/hostname) into a sorted, unique
    IPv4 list, then subtract anything matched by *exclude* specs."""
    ips = set()
    for spec in specs:
        ips.update(expand_ips(spec))
    for spec in exclude:
        ips.difference_update(expand_ips(spec))
    return sorted(ips, key=ipaddress.ip_address)


def _read_target_file(path):
    """Read target specs from *path* (or stdin when path is '-').

    One spec per line; blank lines and ``#`` comments are ignored. Each line
    may itself be any accepted spec (IP, CIDR, range, brace set, hostname, or a
    comma-separated mix)."""
    try:
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path) as f:
                text = f.read()
    except OSError as exc:
        _die(f"Cannot read target file {path!r}: {exc}")
    specs = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            specs.append(line)
    return specs


def _classify_positionals(ip, pos_ports):
    """Split leading positional args into (target specs, port tokens).

    A token is a *port* token when it is built only from digits and the range
    punctuation ``,-:`` (22, 80-90, 22,443); anything with a dot, slash, brace
    or letter is a *target* spec.  This lets several ranges be listed
    positionally — ``scan 10.0.0.0/24 10.0.1.0/24 -p 22`` — while still
    accepting the classic ``scan 10.0.0.1 22 80`` form."""
    targets, ports = [], []
    port_chars = set("0123456789,-:")
    for tok in ([ip] if ip else []) + list(pos_ports):
        tok = tok.strip()
        if not tok:
            continue
        if set(tok) <= port_chars and any(ch.isdigit() for ch in tok):
            ports.append(tok)
        else:
            targets.append(tok)
    return targets, ports


def _dash_range(part):
    """True if *part* looks like a last-octet dash range (e.g. 10.0.0.1-20)."""
    dot = part.rfind(".")
    if dot < 0:
        return False
    dash = part.find("-", dot)
    return 0 < dash < len(part) - 1 and part[dot + 1:dash].isdigit()


def _expand_dash(part, spec):
    dot = part.rfind(".")
    dash = part.find("-", dot)
    prefix = part[:dot + 1]
    lo, hi = part[dot + 1:dash], part[dash + 1:]
    return _octet_range(prefix, lo, hi, "", spec)


def _brace_expand(spec, whole=None):
    whole = whole if whole is not None else spec
    lo_b, hi_b = spec.index("{"), spec.index("}")
    prefix, suffix = spec[:lo_b], spec[hi_b + 1:]
    inner = spec[lo_b + 1:hi_b].replace(" ", "")
    out = []
    for token in inner.split(","):
        if not token:
            continue
        if "-" in token:
            lo, hi = token.split("-", 1)
            out.extend(_octet_range(prefix, lo, hi, suffix, whole))
        else:
            out.append(_valid_ip(f"{prefix}{token}{suffix}", whole))
    return out


def _octet_range(prefix, lo, hi, suffix, spec):
    if not (lo.isdigit() and hi.isdigit()):
        _die(f"Invalid range {lo}-{hi} in {spec!r}")
    lo_i, hi_i = int(lo), int(hi)
    if lo_i > hi_i:
        _die(f"Reversed range {lo}-{hi} in {spec!r}")
    return [_valid_ip(f"{prefix}{n}{suffix}", spec) for n in range(lo_i, hi_i + 1)]


def _split_respecting_braces(spec):
    """Split on commas, but not commas nested inside ``{...}``."""
    if not spec:
        return [""]
    parts, cur, depth = [], [], 0
    for ch in spec:
        if ch == "{":
            depth += 1
            cur.append(ch)
        elif ch == "}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


# ── Port parsing ──────────────────────────────────────────────────────

def parse_ports(raw_list):
    """Turn CLI port tokens into a sorted, de-duplicated list of ints.

    Accepts comma- or space-separated values and ``lo-hi`` / ``lo:hi`` ranges.
    Rejects non-numeric tokens and anything outside 1..65535.
    """
    ports = set()
    for item in raw_list:
        for part in str(item).split(","):
            part = part.strip()
            if not part:
                continue
            sep = ":" if ":" in part else ("-" if "-" in part else None)
            if sep:
                lo, _, hi = part.partition(sep)
                ports.update(range(_port(lo), _port(hi) + 1))
            else:
                ports.add(_port(part))
    return sorted(ports)


def _port(tok):
    tok = tok.strip()
    if not tok.isdigit():
        _die(f"Invalid port: {tok!r}")
    n = int(tok)
    if not 1 <= n <= 65535:
        _die(f"Port out of range (1-65535): {n}")
    return n


# The 100 most-common TCP ports, in nmap's frequency order (nmap-services
# data).  Lets ``--top-ports N`` sweep "the ports that actually matter" without
# typing them out; the first 100 cover ~78% of services seen in the wild.
_TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
    6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
    49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153,
    8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357,
    427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070,
    5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873,
    1755, 2717, 4899, 9100, 119, 37,
]


def top_ports(n):
    """Return the *n* most common TCP ports (frequency order, capped at 100)."""
    if n < 1:
        _die(f"--top-ports must be >= 1 (got {n})")
    return _TOP_PORTS[:min(n, len(_TOP_PORTS))]


# ── Gap parsing ───────────────────────────────────────────────────────

def parse_gap(raw):
    """Parse a gap spec into ``(min, max)`` floats. Accepts ``N`` or ``MIN,MAX``."""
    parts = [p for p in str(raw).replace(" ", "").split(",") if p != ""]
    try:
        if len(parts) == 1:
            v = float(parts[0])
            return v, v
        if len(parts) == 2:
            return float(parts[0]), float(parts[1])
    except ValueError:
        pass
    _die(f"Invalid gap spec: {raw!r} (use N or MIN,MAX)")


# ── Port scanning (netcat-compatible connect scan) ─────────────────────

def _under_proxychains():
    """True when this process is running inside proxychains(-ng).

    proxychains works by LD_PRELOAD-ing a hooked ``connect()``, so its library
    name is visible in the environment it hands to the child.
    """
    if os.environ.get("PROXYCHAINS_CONF_FILE"):
        return True
    return "proxychains" in os.environ.get("LD_PRELOAD", "").lower()


def _classify_refusal(elapsed, timeout):
    """Decide whether an ECONNREFUSED really means "closed".

    A RST comes back in about one round trip. A refusal that took longer than
    the whole connect budget did not come from a RST, so the port state is
    genuinely unknown and "filtered" is the honest answer.

    This is what makes the scan trustworthy through a proxy. proxychains
    performs the SOCKS handshake inside its hooked ``connect()`` and, when a
    target is silently dropped, gives up on *its own* ``tcp_read_time_out``
    and reports ECONNREFUSED — indistinguishable, by errno alone, from a real
    refusal. Measured against a stalling SOCKS5 proxy: 15s, then ECONNREFUSED.
    Trusting the errno there records a firewalled port as definitively closed,
    which is the worst possible error for a port scanner to make.
    """
    return "filtered" if timeout and elapsed >= timeout else "closed"


def scan_port(ip, port, timeout=6):
    """Return "open", "closed", or "filtered" for a single TCP connect.

    Uses a ``with`` socket so the file descriptor is always released, even on
    the failure paths — a leak here would exhaust the fd table on a big sweep.
    """
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
        return "open"
    except ConnectionRefusedError:
        return _classify_refusal(time.monotonic() - started, timeout)
    except (socket.timeout, TimeoutError, OSError):
        return "filtered"


def probe_banner(ip, port, timeout=6, nbytes=256):
    """Connect once and try to read a short banner.

    Returns ``(status, text|None)`` where *text* is sanitised, printable-ASCII
    only (see :func:`_sanitize`).  A missing/empty banner yields ``None``.
    """
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.settimeout(min(timeout, 2.0) if timeout else 2.0)
            try:
                data = s.recv(nbytes)
            except (socket.timeout, TimeoutError, OSError):
                data = b""
        text = _sanitize(data.decode("latin-1", "replace")) if data else ""
        return "open", (text[:120] or None)
    except ConnectionRefusedError:
        return _classify_refusal(time.monotonic() - started, timeout), None
    except (socket.timeout, TimeoutError, OSError):
        return "filtered", None


def service_name(port):
    """Best-effort /etc/services lookup, or None."""
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, TypeError):
        return None


# ── State persistence ─────────────────────────────────────────────────

def _safe_name(text):
    """Reduce *text* to characters that are safe in a filename."""
    return "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in text)


def _make_default_name(spec):
    """Derive a filename-friendly base name from a target specification."""
    if "/" in spec:
        return _safe_name(spec.replace("/", "_"))
    if any(ch.isalpha() for ch in spec):
        # A hostname. Name the files after the name the user typed — resolving
        # it here would do a second DNS lookup and bake the answer into the
        # filename, so 'my-site.com' (a hyphen, hence the old range branch)
        # became '18.154.63.15-18.154.63.117' and changed whenever DNS did.
        return _safe_name(spec)
    if any(ch in spec for ch in "{,-"):
        hosts = expand_ips(spec)
        if not hosts:
            return "scan"
        return _safe_name(
            hosts[0] if len(hosts) == 1 else f"{hosts[0]}-{hosts[-1]}")
    return _safe_name(spec)


def default_output_name(specs):
    """Base name for a whole invocation's target specs.

    Naming after ``specs[0]`` alone made ``tcpsweep 10.0.0.0/24 10.1.0.0/24``
    and ``tcpsweep 10.0.0.0/24`` share one state file, so two different scans
    silently pooled their results. Extra specs contribute a short digest.
    """
    if not specs:
        return "scan"
    base = _make_default_name(specs[0])
    if len(specs) > 1:
        digest = hashlib.sha256("\n".join(specs).encode()).hexdigest()[:8]
        base = f"{base}+{len(specs) - 1}more-{digest}"
    return base


def _state_path(name):
    return Path(f"{name}.state.json")


def load_state(name):
    """Return the parsed state dict, or None if absent or unreadable.

    A truncated or hand-mangled state file is treated as "no state" (with a
    warning) rather than crashing the run — resume should degrade to a fresh
    scan, never to a traceback.
    """
    p = _state_path(name)
    if not p.exists():
        return None
    try:
        with open(p) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        _warn(f"ignoring unreadable state file {p} ({exc}); starting fresh")
        return None


def save_state(st, name):
    save = json.dumps(st, indent=2) + "\n"
    _atomic_write(_state_path(name), save)


# ── Output helpers ────────────────────────────────────────────────────

def scope_results(results, ips, ports):
    """Restrict *results* to the ``ips x ports`` grid this run actually scanned.

    The state file is keyed by output *name*, so it can legitimately hold
    results for hosts and ports the current invocation never touched — a
    narrower ``-p``, a different target spec that derived the same name, or a
    resumed scan whose scope shrank.  Those entries must never leak into a
    user-facing artefact: a report that lists an open port on a host that was
    never in scope is the kind of error that discredits an engagement.

    ``_open_by_host`` has always filtered by host; this is the same rule
    applied uniformly (and to ports as well) so the ``.json``, the ``.gnmap``,
    the exported reports and the summary counts all describe *this* scan.
    """
    wanted = set(ports)
    scoped = {}
    for ip in ips:
        found = results.get(ip)
        if not found:
            continue
        kept = {p: s for p, s in found.items() if p in wanted}
        if kept:
            scoped[ip] = kept
    return scoped


def _sorted_ips(results):
    return sorted(results, key=ipaddress.ip_address)


def _sorted_ports(ports):
    # ``ports`` keys may be int (internal) or str (loaded/JSON); sort numerically.
    return sorted(ports, key=lambda k: int(k))


def write_json_output(name, results):
    out = {ip: {str(p): results[ip][p] for p in _sorted_ports(results[ip])}
           for ip in _sorted_ips(results)}
    _atomic_write(f"{name}.json", json.dumps(out, indent=2) + "\n")


def write_grepable_output(name, results):
    lines = []
    for ip in _sorted_ips(results):
        ports = results[ip]
        entries = ", ".join(f"{p}/{ports[p]}" for p in _sorted_ports(ports))
        lines.append(f"Host: {ip} [{entries}]")
    _atomic_write(f"{name}.gnmap", "\n".join(lines) + "\n")


# ── Report export (-oJ / -oX / -oT / -oC / -oA) ───────────────────────
#
# The always-on NAME.json/.gnmap are the raw working files.  A *report* is the
# curated, shareable artefact: scan metadata (targets, timing, totals) plus the
# actionable open/filtered ports per host, with service names.  Reports render
# in several formats so they drop straight into whatever you use next — jq,
# a SIEM, a spreadsheet, or a written engagement report.

REPORT_FORMATS = ("json", "xml", "txt", "csv")


def _fmt_ts(ts):
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def build_report_data(targets, ips, ports, results, *,
                      start=None, end=None, interrupted=False):
    """Assemble a serialisation-agnostic report structure.

    Totals count every recorded result; the per-host listing keeps only the
    actionable open/filtered ports (closed ports live in the raw .json).

    *results* is scoped to ``ips x ports`` first. A report is a deliverable, so
    it must never inherit a stray host from a shared state file — this used to
    emit ``Host: 9.9.9.9  80/tcp open`` under ``# targets: 127.0.0.2``.
    """
    results = scope_results(results, ips, ports)
    counts = {"open": 0, "closed": 0, "filtered": 0}
    hosts = []
    for ip in sorted(results, key=ipaddress.ip_address):
        entries = []
        for p in sorted(results[ip], key=int):
            status = results[ip][p]
            counts[status] = counts.get(status, 0) + 1
            if status in ("open", "filtered"):
                entries.append({"port": int(p), "status": status,
                                "service": service_name(int(p))})
        if entries:
            hosts.append({"ip": ip, "ports": entries})
    end = end or time.time()
    return {
        "tool": "tcpsweep",
        "targets": targets,
        "started": start,
        "ended": end,
        "duration_sec": round(end - start, 3) if start else None,
        "hosts_scanned": len(ips),
        "ports_per_host": len(ports),
        "interrupted": interrupted,
        "summary": counts,
        "hosts": hosts,
    }


def render_report(fmt, data):
    try:
        return _REPORT_RENDERERS[fmt](data)
    except KeyError:
        _die(f"Unknown report format: {fmt!r} (use one of {', '.join(REPORT_FORMATS)})")


def _report_json(data):
    return json.dumps(data, indent=2) + "\n"


def _report_xml(data):
    root = ET.Element("scanreport", tool=data["tool"])
    meta = ET.SubElement(root, "scan")
    meta.set("targets", data["targets"] or "")
    meta.set("started", _fmt_ts(data["started"]))
    meta.set("ended", _fmt_ts(data["ended"]))
    meta.set("duration_sec", str(data["duration_sec"] if data["duration_sec"] is not None else ""))
    meta.set("hosts_scanned", str(data["hosts_scanned"]))
    meta.set("ports_per_host", str(data["ports_per_host"]))
    meta.set("interrupted", "true" if data["interrupted"] else "false")
    s = data["summary"]
    ET.SubElement(root, "summary", open=str(s["open"]),
                  closed=str(s["closed"]), filtered=str(s["filtered"]))
    hosts_el = ET.SubElement(root, "hosts")
    for h in data["hosts"]:
        he = ET.SubElement(hosts_el, "host", address=h["ip"])
        ports_el = ET.SubElement(he, "ports")
        for p in h["ports"]:
            pe = ET.SubElement(ports_el, "port", protocol="tcp",
                               portid=str(p["port"]))
            ET.SubElement(pe, "state", state=p["status"])
            if p["service"]:
                ET.SubElement(pe, "service", name=p["service"])
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def _report_csv(data):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "port", "protocol", "status", "service"])
    for h in data["hosts"]:
        for p in h["ports"]:
            w.writerow([h["ip"], p["port"], "tcp", p["status"], p["service"] or ""])
    return buf.getvalue()


def _report_txt(data):
    s = data["summary"]
    flag = " (INTERRUPTED)" if data["interrupted"] else ""
    out = [
        "# tcpsweep report",
        f"# targets      : {data['targets']}",
        f"# started      : {_fmt_ts(data['started'])}",
        f"# duration     : {Display._fmt_time(data['duration_sec'] or 0)}",
        f"# hosts scanned: {data['hosts_scanned']}   ports/host: "
        f"{data['ports_per_host']}{flag}",
        f"# results      : {s['open']} open, {s['closed']} closed, "
        f"{s['filtered']} filtered",
        "",
    ]
    if not data["hosts"]:
        out.append("No open or filtered ports found.")
    for h in data["hosts"]:
        out.append(f"Host: {h['ip']}")
        for p in h["ports"]:
            out.append(f"  {p['port']:>5}/tcp  {p['status']:<8}  "
                       f"{p['service'] or ''}".rstrip())
        out.append("")
    return "\n".join(out).rstrip() + "\n"


_REPORT_RENDERERS = {
    "json": _report_json,
    "xml": _report_xml,
    "txt": _report_txt,
    "csv": _report_csv,
}


def write_report(path, fmt, data):
    """Render *data* in *fmt* and write it atomically (0600)."""
    _atomic_write(path, render_report(fmt, data))


# ── Live dashboard ─────────────────────────────────────────────────────

class Display:
    """A single, continuously-updated status dashboard on stderr.

    When stderr is a TTY the dashboard is drawn on the terminal's *alternate
    screen buffer*: entering it (``start``) hides whatever was there, and
    leaving it (``finish``) restores it verbatim.  The live frame therefore
    never lands in scrollback — on completion or Ctrl+C it simply vanishes and
    the caller prints a concise final summary onto the normal screen.

    When stderr is not a TTY (piped, redirected, or under the test suite),
    every rendering method is a no-op; the scanner then relies on its plain
    line-based output (the stdout stream + one-shot stderr announcements).

    Progress counters are maintained incrementally as results arrive, so a
    repaint is O(recent) rather than O(hosts x ports) — cheap even mid-way
    through a /16 x full-port sweep.
    """

    _MIN_WIDTH = 32
    _MAX_WIDTH = 100
    _BAR_CELLS = 22
    _MAX_RECENT = 8

    def __init__(self, ips, ports, start_time=None):
        self.lock = threading.Lock()
        self.ips = ips
        self.ports = sorted(ports)
        self.results = {}                # ip -> {port: status}
        self.counts = {"open": 0, "closed": 0, "filtered": 0}
        self.done = 0
        self._start = start_time or time.time()
        self.total = len(ips) * len(ports)
        self.finished = False
        self.fail_streak = 0
        self.target = ""                 # the range(s) being scanned
        self.subtitle = ""               # effective-flags line
        self.resume_note = ""            # optional "resuming N done" banner
        self._current = None             # (ip, port) probe currently in flight
        self._recent = collections.deque(maxlen=self._MAX_RECENT)
        self._active = False             # True while the alt screen is up

    # ── data updates (thread-safe; also used headless by the tests) ──

    def record(self, ip, port, status):
        with self.lock:
            bucket = self.results.setdefault(ip, {})
            prev = bucket.get(port)
            if prev is not None:                       # re-recording (rare)
                self.counts[prev] = max(0, self.counts.get(prev, 0) - 1)
                self.done -= 1
            bucket[port] = status
            self.counts[status] = self.counts.get(status, 0) + 1
            self.done += 1

    def unrecord(self, ip, port):
        with self.lock:
            prev = self.results.get(ip, {}).pop(port, None)
            if prev is not None:
                self.counts[prev] = max(0, self.counts.get(prev, 0) - 1)
                self.done -= 1

    def _sync_state(self, state_results):
        """Seed the bar (and counters) from prior results on resume."""
        with self.lock:
            for ip, ports in state_results.items():
                bucket = self.results.setdefault(ip, {})
                for port, status in ports.items():
                    if port not in bucket:
                        self.done += 1
                        self.counts[status] = self.counts.get(status, 0) + 1
                    bucket[port] = status

    def add_open(self, ip, port, banner=None):
        """Record a freshly-found open port for the 'recent' panel."""
        detail = _sanitize(banner) if banner else (service_name(port) or "")
        with self.lock:
            self._recent.append((f"{ip}:{port}", detail))

    def set_current(self, ip, port):
        """Note the probe now in flight (shown live as 'scanning → ip:port').

        A plain attribute assignment is atomic in CPython, so this stays
        lock-free — it's called on every single probe and must be cheap; a
        render seeing a slightly stale value is harmless."""
        self._current = (ip, port)

    # ── lifecycle ────────────────────────────────────────────────────

    def start(self):
        if not _COLORS_ON:
            return
        sys.stderr.write(_ALT_ON + CURSOR_HIDE + _CLR_SCREEN)
        sys.stderr.flush()
        self._active = True
        self.render()

    def finish(self):
        with self.lock:
            self.finished = True
        if _COLORS_ON and self._active:
            sys.stderr.write(_ALT_OFF + CURSOR_SHOW)
            sys.stderr.flush()
            self._active = False

    def render(self):
        if not (_COLORS_ON and self._active):
            return
        with self.lock:
            frame = self._frame()
        sys.stderr.write(frame)
        sys.stderr.flush()

    # ── rendering ────────────────────────────────────────────────────

    @staticmethod
    def _term_size():
        for fd in (sys.stderr, sys.stdout):
            try:
                return os.get_terminal_size(fd.fileno())
            except (OSError, ValueError, AttributeError):
                continue
        return os.terminal_size((80, 24))

    @staticmethod
    def _fit(text, width, color=None):
        """Truncate *text* to *width* display cells (with an ellipsis), then
        optionally colour it.  Layout is computed on the plain text, so the
        added ANSI codes never throw the width off."""
        if width > 0 and len(text) > width:
            text = text[:max(0, width - 1)] + "…"
        return c(text, color) if color else text

    def _frame(self):
        size = self._term_size()
        width = max(self._MIN_WIDTH, min(self._MAX_WIDTH, size.columns - 2))
        lines = self._compose(width, size.lines)
        out = [_HOME]
        for ln in lines:
            out.append(ln + _CLR_EOL + "\n")
        out.append(_CLR_EOS)      # wipe anything left by a taller previous frame
        return "".join(out)

    def _compose(self, width, rows):
        elapsed = time.time() - self._start
        total = self.total or 1
        done = self.done
        pct = min(100.0, done / total * 100)
        rate = done / max(1e-9, elapsed)
        eta = (total - done) / rate if rate > 0 and done < total else 0
        op, cl, fi = (self.counts["open"], self.counts["closed"],
                      self.counts["filtered"])

        rule = c("─" * width, _DIM)
        lines = [c(" ▸ TCP SWEEP", _BOLD + _CYAN), rule]
        if self.target:
            lines.append(self._fit(" target   " + self.target, width, _CYAN))
        if self.subtitle:
            lines.append(self._fit(" scan     " + self.subtitle, width, _DIM))
        if self.resume_note:
            lines.append(self._fit(" ↻ " + self.resume_note, width, _YELLOW))
        lines.append("")

        cells = max(8, min(self._BAR_CELLS, width - 34))
        filled = int(cells * pct / 100)
        bar = c("█" * filled, _GREEN) + c("░" * (cells - filled), _DIM)
        lines.append(f" [{bar}] {pct:5.1f}%  {done}/{total}  {rate:5.1f}/s")
        lines.append(self._fit(f"   elapsed {self._fmt_time(elapsed)}"
                               f"   ·   eta {self._fmt_time(eta)}", width, _DIM))
        lines.append("")

        cur = self._current
        if cur and not self.finished:
            lines.append(self._fit(f" ▸ scanning  {cur[0]}:{cur[1]}",
                                   width, _BOLD + _CYAN))
        else:
            lines.append("")

        lines.append(f"   {c(_SWITCH_OPEN, _GREEN)} {c(op, _GREEN + _BOLD)} open"
                     f"    {c(_SWITCH_CLOSED, _DIM)} {cl} closed"
                     f"    {c(_SWITCH_FILTERED, _YELLOW)} {fi} filtered")
        if self.fail_streak:
            lines.append(self._fit(
                f" ⚠ link check — {self.fail_streak} non-open result(s) in a row",
                width, _RED))
        lines.append("")

        lines.append(self._fit(" recent open ports", width, _DIM))
        recent = list(self._recent)
        room = max(1, rows - len(lines) - 3)
        if recent:
            for label, detail in recent[-room:]:
                text = f"   {_SWITCH_OPEN} {label}" + (f"   {detail}" if detail else "")
                lines.append(self._fit(text, width, _GREEN))
        else:
            lines.append(self._fit("   (none yet)", width, _DIM))
        lines.append("")
        lines.append(rule)
        return lines

    @staticmethod
    def _fmt_time(seconds):
        if seconds < 60:
            return f"{seconds:.0f}s"
        m, s = divmod(seconds, 60)
        if m < 60:
            return f"{int(m)}m {int(s)}s"
        h, m = divmod(m, 60)
        return f"{int(h)}h {int(m)}m"


# ── Task building ──────────────────────────────────────────────────────

def _build_tasks(ips, ports, random_order):
    tasks = [(ip, port) for ip in ips for port in ports]
    if random_order:
        random.shuffle(tasks)
    return tasks


# ── Main scanner ───────────────────────────────────────────────────────

class Scanner:
    def __init__(self, ips, ports, *, timeout=6, random_order=False,
                 gap_min=0, gap_max=0, hgap_min=0, hgap_max=0,
                 threads=1, output_name=None, spec=None, interval=0.25,
                 check_fails=0, check_targets=None, show_filtered=False,
                 banner=False, target_spec=None):
        self.ips = ips
        self.ports = ports
        self.target_spec = target_spec or spec or (
            ips[0] if len(ips) == 1 else f"{len(ips)} hosts")
        self.timeout = timeout
        self.random_order = random_order
        self.gap_min, self.gap_max = gap_min, gap_max
        self.hgap_min, self.hgap_max = hgap_min, hgap_max
        self.threads = max(1, threads)
        self.output_name = (
            output_name
            or (spec is not None and _make_default_name(spec))
            or (ips[0] if len(ips) == 1 else "scan")
        )
        self.interval = interval
        self.show_filtered = show_filtered
        self.banner = banner

        self.state = {
            "ips": ips,
            "ports": ports,
            "results": {},
            "pending": [],
            "interrupted": False,
            "start_time": None,
            "end_time": None,
            "random_order": random_order,
        }

        # Shared, lock-guarded state.
        self.task_queue = collections.deque()
        self.results_lock = threading.Lock()
        self.shutdown = threading.Event()
        self._resume_event = threading.Event()
        self._resume_event.set()  # set = workers may run; cleared = paused
        self.display = None

        # Rate limiting.
        self.wait_lock = threading.Lock()
        self.host_lock = threading.Lock()
        self._global_next = 0.0
        self._host_next = {}

        # Output streaming + persistence throttling.
        self._stdout_lock = threading.Lock()
        self._persist_lock = threading.Lock()
        self._all_tasks = {(ip, port) for ip in ips for port in ports}
        self._last_persist = 0.0
        self._persist_interval = 1.0

        # Set when a *completed* scan's state file was found and declined;
        # reported once so the skipped resume is never silent.
        self._stale_state = False
        # Wall-clock start of *this* invocation. The summary must not measure
        # against a start_time inherited from an earlier run.
        self._run_start = None
        self._resumed = False

        # Connection health check (disabled by default; --cf enables).
        self.check_fails = check_fails
        self.check_targets = list(check_targets or [])
        self.fail_streak = 0
        self.known_open = []   # (ip, port) tuples that answered open this run
        self.since_good = []   # non-open tasks recorded since the last good check
        self._needs_check = False
        self._check_lock = threading.Lock()
        self._pause_gen = 0     # bumped on every confirmed link outage
        self._recovery_delay = 2.0   # initial re-probe delay after a drop
        self._recovery_max = 30.0    # backoff ceiling

        # Stream open ports to stdout only when it is not a terminal (piped).
        self._stream_stdout = not sys.stdout.isatty()

    # ── State loading / saving ──────────────────────────────────────

    def _load(self):
        """Load prior results for resume. Flags (threads, timeout, banner,
        random order, gaps, ...) always come fresh from this run's CLI
        arguments — nothing here overrides them, so a resumed scan can freely
        change them.

        Only an *unfinished* scan is resumed.  ``end_time`` is set exactly
        once, immediately before the final persist, so it is None for a run
        that was Ctrl+C'd, crashed, or killed — every case worth continuing —
        and a timestamp for one that ran to completion.  Replaying a completed
        scan would re-report its ports as open without probing them, which is
        indistinguishable from a live result and silently wrong the moment the
        network changes.  (Gating on ``interrupted`` alone would miss the
        crash/SIGKILL case, since the periodic persist writes it False.)
        """
        st = load_state(self.output_name)
        if st is None:
            return
        if st.get("end_time") is not None:
            self._stale_state = True
            return
        try:
            results = {
                ip: {int(p): s for p, s in ports.items()}
                for ip, ports in st.get("results", {}).items()
            }
        except (AttributeError, TypeError, ValueError) as exc:
            # Structurally valid JSON can still carry a non-numeric port key.
            # load_state() deliberately degrades a corrupt file to "no state";
            # do the same here rather than reintroducing a traceback.
            _warn(f"ignoring malformed results in state file ({exc}); "
                  f"starting fresh")
            return
        self.state["results"] = results
        self.state["start_time"] = st.get("start_time")

    def _persist(self):
        """Snapshot results and write all three output files atomically."""
        with self.results_lock:
            snapshot = {ip: dict(ports)
                        for ip, ports in self.state["results"].items()}
            done = {(ip, p) for ip, ports in snapshot.items() for p in ports}
            pending = [list(t) for t in self._all_tasks if t not in done]
            interrupted = self.state.get("interrupted", False)
        save_state(
            {
                "ips": self.ips,
                "ports": self.ports,
                "results": snapshot,
                "pending": pending,
                "interrupted": interrupted,
                "start_time": self.state.get("start_time"),
                "end_time": self.state.get("end_time"),
                "random_order": self.random_order,
            },
            self.output_name,
        )
        # The state file keeps everything (so a shrunken resume loses nothing),
        # but the working outputs describe only what this run scanned.
        scoped = scope_results(snapshot, self.ips, self.ports)
        write_json_output(self.output_name, scoped)
        write_grepable_output(self.output_name, scoped)
        self._last_persist = time.monotonic()

    def _maybe_persist(self):
        """Persist at most once per interval, and never concurrently."""
        if time.monotonic() - self._last_persist < self._persist_interval:
            return
        if self._persist_lock.acquire(blocking=False):
            try:
                self._persist()
            finally:
                self._persist_lock.release()

    # ── Task building ───────────────────────────────────────────────

    def _init_tasks(self):
        done = {(ip, p) for ip, ports in self.state["results"].items()
                for p in ports}
        tasks = [t for t in _build_tasks(self.ips, self.ports, False)
                 if t not in done]
        if self.random_order:
            random.shuffle(tasks)
        self.task_queue = collections.deque(tasks)

    # ── Rate limiting ───────────────────────────────────────────────

    @staticmethod
    def _random_gap(lo, hi):
        return float(lo) if lo == hi else random.uniform(lo, hi)

    def _wait_global(self):
        """Reserve the next global send slot; return seconds to sleep first."""
        if self.gap_max <= 0:
            return 0.0
        with self.wait_lock:
            now = time.monotonic()
            target = max(now, self._global_next)
            self._global_next = target + self._random_gap(self.gap_min, self.gap_max)
            return target - now

    def _wait_host(self, ip):
        """Reserve the next per-host send slot; return seconds to sleep first."""
        if self.hgap_max <= 0:
            return 0.0
        with self.host_lock:
            now = time.monotonic()
            target = max(now, self._host_next.get(ip, 0.0))
            self._host_next[ip] = target + self._random_gap(self.hgap_min, self.hgap_max)
            return target - now

    def _sleep(self, seconds):
        """Interruptible sleep — wakes immediately on Ctrl+C."""
        if seconds > 0:
            self.shutdown.wait(seconds)

    # ── Connection health check ─────────────────────────────────────

    def probe(self, target):
        return scan_port(target[0], target[1], self.timeout)

    def _pick_probe_target(self):
        pool = self.known_open or self.check_targets
        return random.choice(pool) if pool else None

    def _on_result(self, ip, port, status):
        """Update the fail-streak bookkeeping (called under results_lock)."""
        if self.check_fails <= 0:
            return
        if status == "open":
            self.fail_streak = 0
            self.since_good.clear()
            t = (ip, port)
            if t not in self.known_open:
                self.known_open.append(t)
            if self.display:
                self.display.fail_streak = 0
        else:
            self.fail_streak += 1
            self.since_good.append((ip, port))
            if self.display:
                self.display.fail_streak = self.fail_streak
            if self.fail_streak >= self.check_fails:
                self._needs_check = True

    def _requeue_since_good(self):
        """Drop the suspect results and put them back on the queue (under lock)."""
        n = 0
        for ip, port in self.since_good:
            self.state["results"].get(ip, {}).pop(port, None)
            self.task_queue.append((ip, port))
            if self.display:
                self.display.unrecord(ip, port)
            n += 1
        self.since_good.clear()
        self.fail_streak = 0
        self._needs_check = False
        if self.display:
            self.display.fail_streak = 0
        return n

    def _run_health_check(self):
        """A long run of non-open results tripped the threshold: verify the link
        against a known-good target.  If the probe fails too, pause every worker
        and wait for recovery, then re-queue the suspect results."""
        with self.results_lock:
            target = self._pick_probe_target()
        if target is None:
            with self.results_lock:
                self.fail_streak = 0
                self.since_good.clear()
            return
        if self.probe(target) == "open":
            with self.results_lock:  # link is fine — just a dense closed region
                self.fail_streak = 0
                self.since_good.clear()
                if self.display:
                    self.display.fail_streak = 0
            return
        # Confirmed drop: pause all workers and wait for the link to return.
        self._resume_event.clear()
        with self.results_lock:
            # Invalidate probes already in flight. Workers only check
            # _resume_event at the top of their loop, so a connect() that
            # started before the pause will still return "filtered" and record
            # it as though the link were healthy.
            self._pause_gen += 1
        _warn(f"connection lost — probe {target[0]}:{target[1]} failed; pausing")
        recovered = False
        delay = self._recovery_delay
        while not self.shutdown.is_set():
            if self.shutdown.wait(delay):
                break
            if self.probe(target) == "open":
                recovered = True
                break
            delay = min(delay * 1.5, self._recovery_max)
        # Drop the suspect results on *every* exit path. They were recorded
        # while the link was down, so they are noise whether or not it came
        # back; leaving them behind on Ctrl+C would persist them as real and a
        # resume would then skip those ports entirely.
        with self.results_lock:
            n = self._requeue_since_good()
        if recovered:
            _warn(f"connection restored — re-queued {n} suspect result(s)")
        elif n:
            _warn(f"interrupted during outage — discarded {n} suspect result(s); "
                  f"they will be re-probed on resume")
        self._resume_event.set()

    # ── Worker ──────────────────────────────────────────────────────

    def _scan_one(self, ip, port):
        if self.banner:
            return probe_banner(ip, port, self.timeout)
        return scan_port(ip, port, self.timeout), None

    def _emit_open(self, ip, port, banner):
        """Stream one open port to stdout for piping (netcat/masscan style)."""
        if not self._stream_stdout:
            return
        line = f"{ip} {port}"
        if self.banner and banner:
            line += f"\t{_sanitize(banner)}"
        with self._stdout_lock:
            try:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            except OSError:
                pass

    def _worker(self):
        while True:
            self._resume_event.wait()
            if self.shutdown.is_set():
                break
            with self.results_lock:
                task = self.task_queue.popleft() if self.task_queue else None
            if task is None:
                break
            ip, port = task
            if self.display:
                self.display.set_current(ip, port)

            self._sleep(self._wait_host(ip))
            if self.threads == 1:
                self._sleep(self._wait_global())
            if self.shutdown.is_set():
                with self.results_lock:  # unclaim so resume re-runs it
                    self.task_queue.appendleft(task)
                break

            with self.results_lock:
                gen = self._pause_gen
            status, banner = self._scan_one(ip, port)

            with self.results_lock:
                if gen != self._pause_gen:
                    # A confirmed link outage began while this probe was in
                    # flight, so its result says nothing about the target.
                    # Re-queue rather than record it.
                    self.task_queue.append(task)
                    continue
                self.state["results"].setdefault(ip, {})[port] = status
                if self.display:
                    self.display.record(ip, port, status)
                self._on_result(ip, port, status)

            if status == "open":
                self._emit_open(ip, port, banner)
                if self.display:
                    self.display.add_open(ip, port, banner if self.banner else None)

            if (self.check_fails > 0 and self._needs_check
                    and self._check_lock.acquire(blocking=False)):
                try:
                    self._needs_check = False
                    self._run_health_check()
                finally:
                    self._check_lock.release()

            if self.threads == 1 and self.display:
                self.display.render()
            self._maybe_persist()

    # ── Summary ─────────────────────────────────────────────────────
    #
    # The final report (and the interrupt report) intentionally enumerate
    # *only* open ports — that's the actionable result. Closed/filtered
    # ports are summarised as counts only; the filtered ones are listed just
    # when -F/--show-filtered asks for them.

    def scoped_results(self):
        """This run's results only — the basis for every reported figure."""
        with self.results_lock:
            snapshot = {ip: dict(ports)
                        for ip, ports in self.state["results"].items()}
        return scope_results(snapshot, self.ips, self.ports)

    def _by_status(self, status):
        res = self.scoped_results()
        return {
            ip: sorted(p for p, s in res.get(ip, {}).items() if s == status)
            for ip in self.ips
            if any(s == status for s in res.get(ip, {}).values())
        }

    def _open_by_host(self):
        return self._by_status("open")

    def _filtered_by_host(self):
        return self._by_status("filtered")

    def _print_open_ports(self):
        """Print every open port found so far, grouped by host. Returns the
        total open-port count."""
        w = sys.stderr.write
        open_hosts = self._open_by_host()
        total_open = sum(len(v) for v in open_hosts.values())
        label_w = max((len(ip) for ip in open_hosts), default=0)

        if not open_hosts:
            w(c("  no open ports found\n", _DIM))
        else:
            for ip in sorted(open_hosts, key=ipaddress.ip_address):
                ports_str = ", ".join(self._fmt_port(p) for p in open_hosts[ip])
                w(f"  {c(_SWITCH_OPEN, _GREEN)} {c(f'{ip:<{label_w}}', _CYAN)}  "
                  f"{c(ports_str, _GREEN)}\n")

        if self.show_filtered:
            filt_hosts = self._filtered_by_host()
            if filt_hosts:
                w("\n" + c("  filtered:", _YELLOW) + "\n")
                for ip in sorted(filt_hosts, key=ipaddress.ip_address):
                    ports_str = ", ".join(str(p) for p in filt_hosts[ip])
                    w(f"  {c(_SWITCH_FILTERED, _YELLOW)} {c(f'{ip:<{label_w}}', _CYAN)}  "
                      f"{c(ports_str, _YELLOW)}\n")
        return total_open

    def _counts(self):
        by_status = {"open": 0, "closed": 0, "filtered": 0}
        for ports in self.scoped_results().values():
            for status in ports.values():
                by_status[status] = by_status.get(status, 0) + 1
        return by_status

    def _print_summary(self):
        # Measure *this* run. start_time may have been inherited from the run
        # that was interrupted, which would report a duration covering the gap
        # in between (observed: "duration 1h 47m" for an instant replay).
        start = self._run_start or self.state.get("start_time") or time.time()
        end = self.state.get("end_time") or time.time()
        counts = self._counts()

        # Label it when the figure covers only part of the scan, so it can't be
        # read as the total span the exported report shows.
        scope = " (this run)" if self._resumed else ""
        w = sys.stderr.write
        w("\n" + c(" ✓ SCAN COMPLETE", _BOLD + _GREEN)
          + c(f"   duration {Display._fmt_time(max(0.0, end - start))}{scope}",
              _DIM) + "\n")
        w(c("  " + "─" * 46, _DIM) + "\n")
        total_open = self._print_open_ports()
        w(c(f"\n  {total_open} open  ·  {counts['closed']} closed  ·  "
            f"{counts['filtered']} filtered\n\n", _DIM))

    @staticmethod
    def _fmt_port(port):
        svc = service_name(port)
        return f"{port} ({svc})" if svc else str(port)

    def _print_interrupt(self):
        with self.results_lock:
            done = sum(len(v) for v in self.state["results"].values())
        total = len(self.ips) * len(self.ports)

        w = sys.stderr.write
        w("\n" + c(" ⏸ INTERRUPTED", _BOLD + _YELLOW)
          + c(f"   {done}/{total} checks done", _DIM) + "\n")
        w(c("  Re-run the same command to resume — flags can be changed.", _DIM) + "\n")
        w(c("  " + "─" * 46, _DIM) + "\n")
        self._print_open_ports()
        w("\n")

    # ── Signal handling ─────────────────────────────────────────────

    def _install_signal(self):
        self._prev_sigint = None
        try:
            self._prev_sigint = signal.getsignal(signal.SIGINT)

            def handler(_signum, _frame):
                # Async-signal-safe: only flip events, never take locks or print.
                self.state["interrupted"] = True
                self.shutdown.set()
                self._resume_event.set()

            signal.signal(signal.SIGINT, handler)
        except (ValueError, OSError):
            self._prev_sigint = None  # not on the main thread; skip

    def _restore_signal(self):
        if self._prev_sigint is not None:
            try:
                signal.signal(signal.SIGINT, self._prev_sigint)
            except (ValueError, OSError):
                pass

    # ── Run ─────────────────────────────────────────────────────────

    def _config_desc(self):
        """One line describing the flags actually in effect this run, so a
        resumed scan visibly shows if/how they changed."""
        bits = [f"{len(self.ips)} host(s) x {len(self.ports)} port(s) = "
                f"{len(self.ips) * len(self.ports)} checks",
                f"threads={self.threads}", f"timeout={self.timeout:g}s"]
        if self.random_order:
            bits.append("random")
        if self.banner:
            bits.append("banner")
        if self.gap_max > 0:
            bits.append(f"pgap={self.gap_min}-{self.gap_max}s")
        if self.hgap_max > 0:
            bits.append(f"hgap={self.hgap_min}-{self.hgap_max}s")
        if self.check_fails > 0:
            bits.append(f"check-fails={self.check_fails}")
        return "  ".join(bits)

    def _announce(self, resumed, prev_done):
        """Pre-flight notes: environment caveats, resume state, effective flags.

        This prints unconditionally, *before* the dashboard switches to the
        alternate screen buffer — text written beforehand is restored when the
        buffer is torn down, so it survives into scrollback.  It used to bail
        out under a TTY and leave the resume banner living only on the alt
        screen, which is discarded before the summary prints: interactively
        there was then no trace at all that results had been reused, which is
        exactly how a replayed "open" gets mistaken for a live one.
        """
        if _under_proxychains():
            # The scan still works, but two of its guarantees weaken, and
            # silently degraded results are worse than slower ones.
            _warn("running under proxychains — -w/--timeout is advisory here: "
                  "the SOCKS handshake happens inside proxychains' hooked "
                  "connect(), so its own tcp_connect_time_out / "
                  "tcp_read_time_out govern. Set them at or below "
                  f"{self.timeout:g}s, or a dropped port costs their timeout.")
            if self.threads > 4:
                _warn(f"-t {self.threads} through proxychains: its hooks "
                      "serialise on a single chain, so high thread counts add "
                      "contention rather than speed. -t 1-4 is the safe range.")
        if self._stale_state:
            _warn(f"{_state_path(self.output_name)} is from a scan that already "
                  f"finished — not resuming it; re-probing every port. "
                  f"(Use --fresh to delete it.)")
        if resumed:
            sys.stderr.write(
                f"Resuming {self.output_name} — {prev_done} check(s) "
                f"already done. {self._config_desc()}\n"
            )
        else:
            sys.stderr.write(f"Starting scan. {self._config_desc()}\n")
        sys.stderr.flush()

    def run(self):
        """Execute the scan. Returns True on completion, False if interrupted."""
        if self.threads > 1 and self.gap_max > 0:
            _die("Cannot combine -t/--threads with -P/--pgap (packet gap). "
                 "Use -H/--hgap for per-host pacing.")

        self._load()
        self._run_start = time.time()
        # Count only what counts *towards this run* — a state file may carry
        # results for hosts/ports outside this scope, which previously made the
        # progress bar read e.g. "2/1  100.0%".
        carried = self.scoped_results()
        resumed = self._resumed = bool(carried)
        prev_done = sum(len(v) for v in carried.values())
        self._init_tasks()
        if not self.state["start_time"]:
            self.state["start_time"] = self._run_start

        self._announce(resumed, prev_done)
        self._install_signal()

        if _COLORS_ON:
            self.display = Display(self.ips, self.ports, self._run_start)
            self.display.fail_streak = self.fail_streak
            self.display.target = self.target_spec
            self.display.subtitle = self._config_desc()
            if resumed:
                self.display.resume_note = (
                    f"resuming — {prev_done} check(s) already done")
            self.display._sync_state(carried)
            self.display.start()

        try:
            workers = [threading.Thread(target=self._worker, daemon=True)
                       for _ in range(self.threads)]
            for t in workers:
                t.start()

            last_refresh = 0.0
            while any(t.is_alive() for t in workers) and not self.shutdown.is_set():
                if self.display and self.threads > 1:
                    now = time.time()
                    if now - last_refresh >= self.interval:
                        self.display.render()
                        last_refresh = now
                time.sleep(0.05)
            for t in workers:
                t.join(timeout=1.0)
        finally:
            if self.display:
                self.display.finish()   # tear down the alt screen, restore cursor
            self._restore_signal()

        if self.shutdown.is_set():
            self.state["interrupted"] = True
            self._persist()
            self._print_interrupt()
            return False

        self.state["end_time"] = time.time()
        self._persist()
        self._print_summary()
        return True


# ── CLI ────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="tcpsweep",
        description="TCP connect sweep (netcat-compatible). "
                    "Open ports stream to stdout; progress and summary to stderr.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s 192.168.1.1 22 80 443
  %(prog)s 192.168.1.0/24 --ports 22,80,443 -t 16
  %(prog)s example.com --top-ports 100     # resolve host, scan common ports
  %(prog)s -iL targets.txt --top-ports 20  # targets from a file
  %(prog)s 10.0.0.0/24 -p 1-1024 --exclude 10.0.0.1,10.0.0.254
  %(prog)s 192.168.1.1 -p 1-65535 -w 2 --rate 50   # 50 packets/second
  %(prog)s 192.168.0.0/24 192.168.4.0/24 192.168.6.0/24 -p 22 80  # many ranges
  %(prog)s 10.0.0.0/24 -p 1-1024 -t 16 -oA report   # export json/xml/txt/csv
  %(prog)s 10.0.0.0/24 -p 22 -oX out.xml -oJ out.json
  %(prog)s 10.0.0.0/24 -p 22 -b            # grab banners
  %(prog)s 192.168.1.0/24 -p 22 80 -F      # show filtered ports too

Output files (base name derived from the target, or set with -o):
    10.0.0.1       -> 10.0.0.1.json / .gnmap / .state.json
    192.168.1.0/24 -> 192.168.1.0_24.*
    10.0.0.{1-10}  -> 10.0.0.1-10.0.0.10.*

Switches are grouped by what you're trying to do: pick a target, control how
the scan behaves, pace it to avoid tripping something, or manage output and
resuming. Discovered ports show as a switch: ● open, ◐ filtered (with -F).
""",
    )
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")

    target = p.add_argument_group("target selection", "what to scan")
    target.add_argument("ip", nargs="?", default=None,
                        help="IP, CIDR, dash range, brace notation, or hostname "
                             "(e.g. 192.168.1.0/24, 10.0.0.{1-10}, example.com). "
                             "Optional if -iL is given.")
    target.add_argument("pos_ports", nargs="*", default=[], metavar="PORT",
                        help="Port numbers / ranges")
    target.add_argument("-p", "--ports", dest="opt_ports", nargs="*", default=[],
                        metavar="PORT",
                        help="Ports, comma or space separated; ranges 22-25 or 22:25")
    target.add_argument("--top-ports", dest="top_ports", type=int, default=None,
                        metavar="N",
                        help="Also scan the N most common ports (nmap frequency "
                             "order, max 100)")
    target.add_argument("-iL", "--target-file", dest="target_files",
                        action="append", default=[], metavar="FILE",
                        help="Read targets from FILE (one spec per line; '-' = "
                             "stdin). Repeatable.")
    target.add_argument("--exclude", dest="exclude", action="append", default=[],
                        metavar="SPEC",
                        help="Exclude these hosts from the sweep (same spec "
                             "grammar). Repeatable.")

    behavior = p.add_argument_group("scan behavior", "how the sweep runs")
    behavior.add_argument("-t", "--threads", type=int, default=1, metavar="N",
                          help="Parallel workers, for speed on large sweeps (default: 1)")
    behavior.add_argument("-w", "--timeout", type=float, default=6, metavar="S",
                          help="Connect timeout per port in seconds, must be > 0 "
                               "(default: 6). Fractions are allowed (e.g. 0.5)")
    behavior.add_argument("-r", "--random", action="store_true",
                          help="Scan in random order, to avoid an obvious "
                               "sequential footprint")
    behavior.add_argument("-b", "--banner", action="store_true",
                          help="Read a short service banner from each open port")
    behavior.add_argument("-F", "--show-filtered", action="store_true",
                          help="Also list filtered ports, not just open ones")

    pacing = p.add_argument_group(
        "rate limiting",
        "slow the sweep down to stay under the radar or off a fragile link")
    pacing.add_argument("-P", "--pgap", metavar="S[,S]", default="0",
                        help="Delay between packets: single value or MIN,MAX "
                             "(single-thread only)")
    pacing.add_argument("--rate", type=float, default=None, metavar="PPS",
                        help="Cap the send rate to PPS packets/second "
                             "(convenience for -P 1/PPS; single-thread only)")
    pacing.add_argument("-H", "--hgap", metavar="S[,S]", default="0",
                        help="Delay between packets to the same host")

    health = p.add_argument_group(
        "link health",
        "auto-pause on a flaky connection instead of misreporting drops as "
        "closed ports")
    health.add_argument("--cf", "--check-fails", dest="check_fails", type=int,
                        default=0, metavar="N",
                        help="Consecutive non-open results before a health probe; "
                             "0 = disabled (default)")
    health.add_argument("--ct", "--check-target", dest="check_targets",
                        action="append", default=[], metavar="IP:PORT",
                        help="Known-good target for the health probe (repeatable)")

    output = p.add_argument_group(
        "output & resume", "where results go, and continuing an interrupted scan")
    output.add_argument("-o", "--output", dest="output_name", metavar="NAME",
                        default=None,
                        help="Output base name (.json/.gnmap/.state.json); "
                             "defaults to the target spec")
    output.add_argument("--fresh", action="store_true",
                        help="Delete any existing state file and start clean. "
                             "Only an unfinished scan is resumed anyway; this "
                             "also discards one that was interrupted")
    output.add_argument("--interval", type=float, default=0.25, metavar="S",
                        help="Dashboard refresh interval in threaded mode (default: 0.25)")

    export = p.add_argument_group(
        "report export",
        "write a formatted report when the scan ends (also on Ctrl+C). "
        "A space before the filename is required, e.g. -oX out.xml")
    export.add_argument("-oJ", "--json-report", dest="export_json", metavar="FILE",
                        help="Write a JSON report to FILE")
    export.add_argument("-oX", "--xml", dest="export_xml", metavar="FILE",
                        help="Write an XML report to FILE")
    export.add_argument("-oT", "-oN", "--txt", dest="export_txt", metavar="FILE",
                        help="Write a plain-text report to FILE")
    export.add_argument("-oC", "--csv", dest="export_csv", metavar="FILE",
                        help="Write a CSV report to FILE")
    export.add_argument("-oA", "--export-all", dest="export_all", metavar="BASE",
                        help="Write BASE.json / .xml / .txt / .csv reports at once")
    return p


def main():
    args = build_parser().parse_args()

    # ── targets: positional specs (multi-range aware) + -iL, minus --exclude ──
    specs, pos_port_tokens = _classify_positionals(args.ip, args.pos_ports)
    for path in args.target_files:
        specs.extend(_read_target_file(path))
    if not specs:
        _die("No targets. Give an IP/host/CIDR/range, or -iL FILE.")
    ips = resolve_targets(specs, args.exclude)
    if not ips:
        _die("No targets left to scan (all excluded, or none resolved).")

    # ── ports: explicit ports and/or --top-ports ──
    ports = parse_ports(pos_port_tokens + args.opt_ports)
    if args.top_ports is not None:
        ports = sorted(set(ports) | set(top_ports(args.top_ports)))
    if not ports:
        _die("No ports specified. Use PORT args, -p/--ports, or --top-ports N.")

    if args.timeout <= 0:
        # settimeout(0) does not mean "no timeout" — it puts the socket in
        # non-blocking mode, so connect() raises BlockingIOError immediately
        # and *every* port, including live listeners, is reported filtered.
        _die(f"Timeout (-w/--timeout) must be greater than 0 (got {args.timeout}). "
             "A zero timeout makes the socket non-blocking, which reports every "
             "port as filtered — even open ones.")

    target_spec = ", ".join(specs)
    name_spec = specs[0]
    out_name = args.output_name or default_output_name(specs)
    if args.fresh:
        with contextlib.suppress(OSError):
            _state_path(out_name).unlink(missing_ok=True)

    check_targets = []
    for t in args.check_targets:
        host, sep, port = t.rpartition(":")
        if not sep or not host or not port.isdigit():
            _die(f"Invalid check target: {t} (expected IP:PORT)")
        check_targets.append((host, int(port)))

    # ── pacing: --rate is a convenience for the global packet gap ──
    if args.rate is not None:
        if args.pgap != "0":
            _die("Use either --rate or -P/--pgap, not both.")
        if args.rate <= 0:
            _die(f"--rate must be > 0 (got {args.rate}).")
        gap_min = gap_max = 1.0 / args.rate
    else:
        gap_min, gap_max = parse_gap(args.pgap)
    hgap_min, hgap_max = parse_gap(args.hgap)

    scanner = Scanner(
        ips, ports,
        spec=name_spec,
        target_spec=target_spec,
        output_name=out_name,
        timeout=args.timeout,
        random_order=args.random,
        gap_min=gap_min, gap_max=gap_max,
        hgap_min=hgap_min, hgap_max=hgap_max,
        threads=args.threads,
        interval=args.interval,
        check_fails=args.check_fails,
        check_targets=check_targets,
        show_filtered=args.show_filtered,
        banner=args.banner,
    )
    completed = scanner.run()

    # ── report export (runs for completed and interrupted scans) ──
    exports = []
    for path, fmt in ((args.export_json, "json"), (args.export_xml, "xml"),
                      (args.export_txt, "txt"), (args.export_csv, "csv")):
        if path:
            exports.append((path, fmt))
    if args.export_all:
        exports.extend((f"{args.export_all}.{fmt}", fmt) for fmt in REPORT_FORMATS)
    if exports:
        data = build_report_data(
            target_spec, ips, ports, scanner.scoped_results(),
            start=scanner.state.get("start_time"),
            end=scanner.state.get("end_time"),
            interrupted=scanner.state.get("interrupted", False),
        )
        for path, fmt in exports:
            write_report(path, fmt, data)
        sys.stderr.write(c(f"  ↳ wrote {len(exports)} report(s): "
                           + ", ".join(p for p, _ in exports) + "\n", _DIM))
        sys.stderr.flush()

    sys.exit(0 if completed else 130)


if __name__ == "__main__":
    main()
