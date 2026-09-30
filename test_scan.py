#!/usr/bin/env python3
"""Tests for tcpsweep.

The interesting cases are the proxy ones, and they are all reachable without a
proxy: the probe classifier is pure timing arithmetic, and the sweep engine
takes its prober as a callable, so a chain outage can be scripted exactly
rather than raced against a real proxy.
"""

import contextlib
import errno
import io
import ipaddress
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

import tcpsweep as ts

HERE = Path(__file__).parent


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Listener:
    """A real loopback listener, for the handful of end-to-end tests."""

    def __enter__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        return self

    def __exit__(self, *exc):
        self.sock.close()
        return False


def result(host="10.0.0.1", port=80, state=ts.OPEN, elapsed=0.0, banner=None):
    return ts.Result(host, port, state, elapsed, banner)


class ScriptedProber:
    """Stands in for Prober so chain behaviour can be dictated per call."""

    def __init__(self, script):
        self.script = script
        self.calls = []

    def __call__(self, task):
        self.calls.append(task)
        state = self.script(task, len(self.calls))
        return ts.Result(task[0], task[1], state, 0.0, None)


class Sink:
    """Stands in for Holdback: remembers what was let out and what was kept."""

    def __init__(self):
        self.emitted = []
        self.kept = []

    def emit(self, res):
        self.emitted.append((res.host, res.port, res.state))

    def keep(self, res):
        self.kept.append((res.host, res.port, res.state))


def fake_proxy_env(directory):
    """Make the tool believe it runs under proxychains while it connects
    directly, so the proxied code paths run without a proxy. The hook is only
    *named* in the environment -- nothing is preloaded into the running process,
    which is all the tool looks at. The timeouts are short because a stall
    costs them in full."""
    conf = Path(directory) / "pc.conf"
    conf.write_text("tcp_read_time_out 400\ntcp_connect_time_out 400\n"
                    "[ProxyList]\nsocks5 127.0.0.1 1080\n")
    return {"PROXYCHAINS_CONF_FILE": str(conf),
            "LD_PRELOAD": "libproxychains4.so"}


def run_main(*argv, env=None, stderr=None):
    """Run ``ts.main()`` in-process and return ``(exit code, stdout, stderr)``.

    In-process so a test can point the sanity probe at a loopback listener.
    Proxychains variables are cleared first, so the outcome does not depend on
    how the suite itself was launched. Never aim ``--json`` or ``--resume`` at
    a path under /dev: as root, a regression would replace the node.
    """
    base = {key: value for key, value in os.environ.items()
            if key not in ("LD_PRELOAD", "PROXYCHAINS_CONF_FILE")}
    base.update(env or {})
    out = io.StringIO()
    err = stderr if stderr is not None else io.StringIO()
    handlers = {name: signal.getsignal(getattr(signal, name))
                for name in ("SIGINT", "SIGTERM", "SIGHUP")}
    try:
        with mock.patch.object(sys, "argv", ["tcpsweep", *argv]), \
                mock.patch.dict(os.environ, base, clear=True), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                code = ts.main()
            except SystemExit as exc:
                code = exc.code
    finally:
        for name, handler in handlers.items():
            signal.signal(getattr(signal, name), handler)
    return code, out.getvalue(), err.getvalue()


# ── Proxy environment ─────────────────────────────────────────────────

class TestProxyDetection(unittest.TestCase):
    def test_detects_via_ld_preload(self):
        env = {"LD_PRELOAD": "/usr/lib/x86_64-linux-gnu/libproxychains.so.4"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertTrue(ts.Proxy.detect().active)

    def test_conf_env_alone_is_not_a_proxy(self):
        """Exported once in a shell profile, PROXYCHAINS_CONF_FILE is still set
        on a run that forgot the proxychains4 in front. Believing it made the
        tool classify direct connects as proxied (an unreachable host read
        'closed') and wait a minute or more on each stalled one."""
        buf = io.StringIO()
        with mock.patch.dict(os.environ,
                             {"PROXYCHAINS_CONF_FILE": "/etc/proxychains4.conf"},
                             clear=True), mock.patch.object(sys, "stderr", buf):
            self.assertFalse(ts.Proxy.detect().active)
        self.assertIn("no proxychains hook is loaded", buf.getvalue())

    def test_a_library_mapped_without_the_variable_counts(self):
        with tempfile.TemporaryDirectory() as td:
            hooked, plain = Path(td) / "hooked", Path(td) / "plain"
            hooked.write_text("7f00-7f01 r-xp 0 08:01 9 /usr/lib/libproxychains.so.4\n")
            plain.write_text("7f00-7f01 r-xp 0 08:01 9 /usr/lib/libc.so.6\n")
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertTrue(ts.hook_loaded(maps=str(hooked)))
                self.assertFalse(ts.hook_loaded(maps=str(plain)))
                self.assertFalse(ts.hook_loaded(maps=str(Path(td) / "missing")))

    def test_macos_style_preload_counts(self):
        with mock.patch.dict(os.environ,
                             {"DYLD_INSERT_LIBRARIES": "/opt/lib/libproxychains4.dylib"},
                             clear=True):
            self.assertTrue(ts.hook_loaded(maps="/nonexistent"))

    def test_absent_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            proxy = ts.Proxy.detect()
            self.assertFalse(proxy.active)
            self.assertIsNone(proxy.conf_path)

    def test_unrelated_preload_is_not_a_proxy(self):
        with mock.patch.dict(os.environ, {"LD_PRELOAD": "/usr/lib/libfoo.so"},
                             clear=True):
            self.assertFalse(ts.Proxy.detect().active)


class TestProxyConfig(unittest.TestCase):
    CONF = textwrap.dedent("""\
        # a comment
        strict_chain
        proxy_dns
        tcp_read_time_out 4000
        tcp_connect_time_out 3000   # trailing comment

        [ProxyList]
        socks5 127.0.0.1 1080
        socks4 10.0.0.9 9050
        """)

    def _load(self, text):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pc.conf"
            path.write_text(text)
            proxy = ts.Proxy()
            proxy._parse(str(path))
            return proxy

    def test_reads_timeouts_and_chain(self):
        proxy = self._load(self.CONF)
        self.assertEqual(proxy.read_ms, 4000)
        self.assertEqual(proxy.connect_ms, 3000)
        self.assertEqual(proxy.chain, "strict_chain")
        self.assertTrue(proxy.proxy_dns)
        self.assertEqual(proxy.proxy_count, 2)

    def test_budget_and_stall_threshold(self):
        proxy = self._load(self.CONF)
        self.assertAlmostEqual(proxy.budget, 7.0)
        # Half the read timeout: measured stalls land exactly on read_ms and
        # definitive answers come back in microseconds.
        self.assertAlmostEqual(proxy.stall_threshold, 2.0)

    def test_defaults_survive_an_empty_config(self):
        proxy = self._load("# nothing here\n")
        self.assertEqual(proxy.read_ms, 15000)
        self.assertEqual(proxy.connect_ms, 8000)

    def test_unreadable_config_does_not_raise(self):
        proxy = ts.Proxy()
        proxy._parse("/nonexistent/nope.conf")
        self.assertEqual(proxy.read_ms, 15000)

    def test_proxy_list_entries_are_not_read_as_directives(self):
        proxy = self._load(self.CONF)
        self.assertEqual(proxy.chain, "strict_chain")


# ── Probe classification ──────────────────────────────────────────────

class TestClassification(unittest.TestCase):
    """The core proxy insight: through a chain, only elapsed time carries
    information. Every SOCKS failure mode arrives as ECONNREFUSED."""

    def setUp(self):
        self.prober = ts.Prober(timeout=30, stall_threshold=2.0, proxied=True)

    def test_fast_refusal_is_closed(self):
        self.assertEqual(self.prober._negative("h", 1, 0.001).state, ts.CLOSED)

    def test_refusal_at_the_threshold_is_filtered(self):
        self.assertEqual(self.prober._negative("h", 1, 2.0).state, ts.FILTERED)

    def test_slow_refusal_is_filtered(self):
        # A proxy that gave up on tcp_read_time_out reports ECONNREFUSED for a
        # port that was never refused; calling that "closed" is the worst
        # error a port scanner can make.
        self.assertEqual(self.prober._negative("h", 1, 4.0).state, ts.FILTERED)

    def test_direct_mode_uses_its_own_budget(self):
        direct = ts.Prober(timeout=6.0, stall_threshold=5.4, proxied=False)
        self.assertEqual(direct._negative("h", 1, 0.01).state, ts.CLOSED)
        self.assertEqual(direct._negative("h", 1, 5.5).state, ts.FILTERED)


class TestProbeAgainstRealSockets(unittest.TestCase):
    def test_open_port(self):
        with Listener() as listener:
            prober = ts.Prober(2.0, 1.8, proxied=False)
            self.assertEqual(prober(("127.0.0.1", listener.port)).state, ts.OPEN)

    def test_closed_port(self):
        prober = ts.Prober(2.0, 1.8, proxied=False)
        self.assertEqual(prober(("127.0.0.1", free_port())).state, ts.CLOSED)

    def test_banner_is_captured_and_sanitised(self):
        import threading
        with Listener() as listener:
            def serve():
                conn, _ = listener.sock.accept()
                conn.sendall(b"SSH-2.0-OpenSSH_9.2\x1b[31mred\r\n")
                conn.close()
            threading.Thread(target=serve, daemon=True).start()
            prober = ts.Prober(2.0, 1.8, proxied=False, banner=True)
            outcome = prober(("127.0.0.1", listener.port))
            self.assertEqual(outcome.state, ts.OPEN)
            self.assertIn("SSH-2.0-OpenSSH_9.2", outcome.banner)
            self.assertNotIn("\033", outcome.banner)

    def test_unreachable_is_filtered_not_closed_when_direct(self):
        """No route, or a host that never answers, is not a closed port. The
        connect is faked so the test puts nothing on the wire."""
        prober = ts.Prober(0.4, 0.36, proxied=False)
        for failure in (OSError(errno.ENETUNREACH, "Network is unreachable"),
                        socket.timeout("timed out")):
            fake = mock.MagicMock()
            fake.connect.side_effect = failure
            with mock.patch.object(ts.socket, "socket", return_value=fake):
                self.assertEqual(prober(("192.0.2.1", 80)).state, ts.FILTERED)


# ── Targets ───────────────────────────────────────────────────────────

class TestTargets(unittest.TestCase):
    def setUp(self):
        self.proxy = ts.Proxy()

    def expand(self, spec):
        return ts.expand_target(spec, self.proxy)

    def test_single_address(self):
        self.assertEqual(self.expand("10.0.0.5"), ["10.0.0.5"])

    def test_cidr_excludes_network_and_broadcast(self):
        hosts = self.expand("10.0.0.0/29")
        self.assertEqual(hosts[0], "10.0.0.1")
        self.assertEqual(hosts[-1], "10.0.0.6")
        self.assertEqual(len(hosts), 6)

    def test_slash_32_and_31_still_yield_hosts(self):
        self.assertEqual(self.expand("10.0.0.7/32"), ["10.0.0.7"])
        self.assertEqual(len(self.expand("10.0.0.0/31")), 2)

    def test_dash_range(self):
        self.assertEqual(self.expand("10.0.0.8-11"),
                         ["10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.11"])

    def test_brace_expansion(self):
        self.assertEqual(self.expand("10.0.0.{1,4-6}"),
                         ["10.0.0.1", "10.0.0.4", "10.0.0.5", "10.0.0.6"])

    def test_ipv6_is_rejected_with_a_reason(self):
        with self.assertRaises(SystemExit):
            self.expand("2001:db8::/120")

    def test_reversed_range_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.expand("10.0.0.9-2")

    def test_octet_overflow_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.expand("10.0.0.250-260")

    def test_exclusions_apply(self):
        hosts = ts.collect_targets(["10.0.0.0/29"], ["10.0.0.3"], self.proxy)
        self.assertNotIn("10.0.0.3", hosts)
        self.assertEqual(len(hosts), 5)

    def test_duplicates_collapse_and_order_is_kept(self):
        hosts = ts.collect_targets(["10.0.0.2", "10.0.0.1", "10.0.0.2"], [],
                                   self.proxy)
        self.assertEqual(hosts, ["10.0.0.2", "10.0.0.1"])

    def test_target_file_skips_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "t.txt"
            path.write_text("10.0.0.1\n\n# comment\n10.0.0.2  # trailing\n")
            self.assertEqual(ts.read_target_file(str(path)),
                             ["10.0.0.1", "10.0.0.2"])


class TestProxyDnsPlaceholder(unittest.TestCase):
    def test_placeholder_address_is_flagged(self):
        proxy = ts.Proxy()
        proxy.active = True
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("224.0.0.1", 0))]
        buf = io.StringIO()
        with mock.patch.object(socket, "getaddrinfo", return_value=fake), \
                mock.patch.object(sys, "stderr", buf):
            self.assertEqual(ts.resolve("example.com", proxy), ["224.0.0.1"])
        self.assertIn("placeholder", buf.getvalue())

    def test_real_address_is_not_flagged(self):
        proxy = ts.Proxy()
        proxy.active = True
        real = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        buf = io.StringIO()
        with mock.patch.object(socket, "getaddrinfo", return_value=real), \
                mock.patch.object(sys, "stderr", buf):
            ts.resolve("example.com", proxy)
        self.assertEqual(buf.getvalue(), "")


# ── Ports ─────────────────────────────────────────────────────────────

class TestPorts(unittest.TestCase):
    def test_lists_ranges_and_dedup(self):
        self.assertEqual(ts.parse_ports(["80,443,80"]), [80, 443])
        self.assertEqual(ts.parse_ports(["20-23"]), [20, 21, 22, 23])
        self.assertEqual(ts.parse_ports(["20:22"]), [20, 21, 22])

    def test_rejects_bad_input(self):
        for bad in ["0", "65536", "http", "-5"]:
            with self.assertRaises(SystemExit, msg=bad):
                ts.parse_ports([bad])

    def test_top_ports_are_frequency_ordered(self):
        self.assertEqual(ts.TOP_PORTS[0], 80)
        self.assertEqual(len(ts.TOP_PORTS), 100)


# ── Triage ────────────────────────────────────────────────────────────

class TestTriage(unittest.TestCase):
    """Skip only the hosts that are expensive: a stall costs the whole proxy
    timeout, a fast negative costs nothing."""

    def _report(self, mapping):
        report = ts.Report()
        for host, states in mapping.items():
            for port, state in enumerate(states, start=1):
                report.record(result(host, port, state))
        return report

    def test_all_stalls_means_skip(self):
        report = self._report({"10.0.0.1": [ts.FILTERED, ts.FILTERED]})
        live, skipped = ts.triage(["10.0.0.1"], report)
        self.assertEqual((live, skipped), ([], ["10.0.0.1"]))

    def test_any_fast_negative_keeps_the_host(self):
        # A fast negative proves the chain answers for this host cheaply, so
        # sweeping it costs almost nothing even though nothing is open.
        report = self._report({"10.0.0.1": [ts.FILTERED, ts.CLOSED]})
        live, skipped = ts.triage(["10.0.0.1"], report)
        self.assertEqual((live, skipped), (["10.0.0.1"], []))

    def test_open_keeps_the_host(self):
        report = self._report({"10.0.0.1": [ts.OPEN]})
        self.assertEqual(ts.triage(["10.0.0.1"], report)[0], ["10.0.0.1"])

    def test_unprobed_host_is_not_skipped(self):
        live, skipped = ts.triage(["10.0.0.9"], ts.Report())
        self.assertEqual((live, skipped), (["10.0.0.9"], []))


# ── Sweep engine ──────────────────────────────────────────────────────

def make_sweep(prober, canaries=(), canary_after=3, chain_wait=0.3,
               concurrency=1, police=True):
    return ts.Sweep(prober, concurrency, ts.RateLimiter(0), canaries,
                    canary_after, chain_wait, police=police)


class Collector:
    """Records what the engine hands over, and in what order."""

    def __init__(self):
        self.recorded = []
        self.revoked = []
        self.vouched = []
        self.events = []        # ("record", h, p, state) / ("revoke", h, p) / ("vouch", h, p)

    def record(self, res):
        self.recorded.append((res.host, res.port, res.state))
        self.events.append(("record", res.host, res.port, res.state))

    def revoke(self, host, port):
        self.revoked.append((host, port))
        self.events.append(("revoke", host, port))

    def vouch(self, pairs):
        for host, port in pairs:
            self.vouched.append((host, port))
            self.events.append(("vouch", host, port))


class TestSweepEngine(unittest.TestCase):
    def test_every_task_is_probed_once(self):
        prober = ScriptedProber(lambda task, n: ts.CLOSED)
        sweep = make_sweep(prober, canary_after=10_000)
        sink = Collector()
        tasks = [("10.0.0.1", p) for p in (1, 2, 3)]
        sweep.run(tasks, sink.record, sink.revoke)
        self.assertEqual(sorted(prober.calls), sorted(tasks))
        self.assertEqual(len(sink.recorded), 3)

    def test_first_open_port_arms_the_canary(self):
        prober = ScriptedProber(
            lambda task, n: ts.OPEN if task[1] == 1 else ts.CLOSED)
        sweep = make_sweep(prober, canary_after=10_000)
        sink = Collector()
        sweep.run([("10.0.0.1", 1), ("10.0.0.1", 2)], sink.record, sink.revoke)
        self.assertEqual(sweep.canaries, [("10.0.0.1", 1)])
        self.assertTrue(sweep.chain_verified)

    def test_chain_stays_unverified_when_nothing_opens(self):
        prober = ScriptedProber(lambda task, n: ts.CLOSED)
        sweep = make_sweep(prober, canary_after=10_000)
        sink = Collector()
        sweep.run([("10.0.0.1", 1)], sink.record, sink.revoke)
        self.assertFalse(sweep.chain_verified)

    def test_dead_chain_revokes_unverified_results_and_stops(self):
        """A dead proxy answers ECONNREFUSED instantly, exactly like a closed
        port, so a long run of negatives must be re-validated before it is
        believed."""
        state = {"alive": True}

        def script(task, _n):
            if task == ("10.0.0.1", 1) and state["alive"]:
                state["alive"] = False       # canary answers once, then dies
                return ts.OPEN
            return ts.CLOSED

        prober = ScriptedProber(script)
        sweep = make_sweep(prober, canary_after=3, chain_wait=0.3)
        sink = Collector()
        tasks = [("10.0.0.1", p) for p in range(1, 12)]
        started = time.monotonic()
        sweep.run(tasks, sink.record, sink.revoke)

        self.assertTrue(sweep.chain_broken)
        self.assertEqual(sweep.outages, 1)
        self.assertTrue(sink.revoked, "unverified negatives must be withdrawn")
        self.assertLess(time.monotonic() - started, 10,
                        "must honour --chain-wait instead of hanging")

    def test_recovered_chain_requeues_the_suspect_probes(self):
        asked = {"n": 0}

        def script(task, _n):
            if task == ("10.0.0.1", 1):
                # Counted per control-target probe, not per call: workers run
                # ahead of the main thread, so a global count would move the
                # outage around from run to run. 1 is the probe itself, then
                # the chain is dead for two checks, then back.
                asked["n"] += 1
                return ts.OPEN if asked["n"] == 1 or asked["n"] >= 4 else ts.CLOSED
            return ts.CLOSED

        prober = ScriptedProber(script)
        sweep = make_sweep(prober, canary_after=3, chain_wait=5)
        sink = Collector()
        with mock.patch.object(ts, "CHAIN_POLL_START", 0.02), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            sweep.run([("10.0.0.1", p) for p in range(1, 8)],
                      sink.record, sink.revoke, sink.vouch)
        self.assertFalse(sweep.chain_broken)
        self.assertEqual(sweep.outages, 1)
        self.assertTrue(sink.revoked, "the outage has to withdraw something")
        for host, port in sink.revoked:
            # Withdrawn means recorded, taken back, and then recorded again
            # from a fresh probe -- not merely "seen in the call log".
            history = [e[0] for e in sink.events if e[1:3] == (host, port)]
            self.assertEqual(history[:3], ["record", "revoke", "record"])
            self.assertEqual(prober.calls.count((host, port)), 2)

    def test_a_raising_prober_does_not_kill_the_sweep(self):
        """An exception means the probe never produced an answer. Writing that
        down as a stall would journal it and could get a whole host skipped, so
        the probe is retried and then reported missing instead."""
        def script(task, _n):
            if task[1] == 2:
                raise RuntimeError("boom")
            return ts.CLOSED

        prober = ScriptedProber(script)
        sweep = make_sweep(prober, canary_after=10_000)
        sink = Collector()
        with mock.patch.object(ts, "PROBE_BACKOFF", 0.01), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            sweep.run([("10.0.0.1", p) for p in (1, 2, 3)],
                      sink.record, sink.revoke)
        self.assertEqual(sorted(p for _, p, _ in sink.recorded), [1, 3])
        self.assertEqual(sweep.lost, [("10.0.0.1", 2)])
        self.assertEqual(prober.calls.count(("10.0.0.1", 2)), ts.PROBE_ATTEMPTS)

    def test_a_transient_failure_is_retried_and_recorded(self):
        seen = {}

        def script(task, _n):
            seen[task] = seen.get(task, 0) + 1
            if seen[task] == 1:
                raise OSError(errno.EMFILE, "Too many open files")
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canary_after=10_000)
        sink = Collector()
        with mock.patch.object(ts, "PROBE_BACKOFF", 0.01), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            sweep.run([("10.0.0.1", 1)], sink.record, sink.revoke)
        self.assertEqual(sink.recorded, [("10.0.0.1", 1, ts.CLOSED)])
        self.assertEqual(sweep.lost, [])

    def test_stop_ends_the_sweep_early(self):
        prober = ScriptedProber(lambda task, n: ts.CLOSED)
        sweep = make_sweep(prober, canary_after=10_000)
        sweep.stop.set()
        sink = Collector()
        sweep.run([("10.0.0.1", p) for p in range(50)], sink.record, sink.revoke)
        self.assertEqual(sink.recorded, [])


class TestExplicitCanaryIsAuthoritative(unittest.TestCase):
    """A supplied control target must never be displaced by something the
    sweep happened to find.

    The previous design picked `known_open or check_targets`, so the first
    discovered open port silently replaced the operator's --ct -- and then a
    random junk service became the thing deciding whether the chain was alive.
    """

    def test_discovered_ports_do_not_displace_an_explicit_canary(self):
        prober = ScriptedProber(lambda task, n: ts.OPEN)
        sweep = make_sweep(prober, canaries=[("10.9.9.9", 22)],
                           canary_after=10_000)
        sink = Collector()
        sweep.run([("10.0.0.1", p) for p in (1, 2, 3)], sink.record, sink.revoke)
        self.assertEqual(sweep.canaries, [("10.9.9.9", 22)])
        self.assertTrue(sweep.explicit_canaries)

    def test_health_check_only_asks_the_explicit_canary(self):
        asked = []

        def script(task, _n):
            asked.append(task)
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script),
                           canaries=[("10.9.9.9", 22)], canary_after=2,
                           chain_wait=0.2)
        sink = Collector()
        sweep.run([("10.0.0.1", p) for p in range(1, 6)],
                  sink.record, sink.revoke)
        self.assertIn(("10.9.9.9", 22), asked)

    def test_auto_arming_keeps_backups_so_one_flaky_host_cannot_poison_it(self):
        prober = ScriptedProber(lambda task, n: ts.OPEN)
        sweep = make_sweep(prober, canary_after=10_000)
        sink = Collector()
        sweep.run([("10.0.0.1", p) for p in range(1, 8)],
                  sink.record, sink.revoke)
        self.assertEqual(len(sweep.canaries), ts.AUTO_CANARY_LIMIT)
        self.assertFalse(sweep.explicit_canaries)

    def test_a_single_healthy_backup_keeps_the_chain_alive(self):
        # First auto-canary goes bad, second still answers -> not a chain death.
        def script(task, _n):
            if task == ("10.0.0.1", 1):
                return ts.CLOSED          # the flaky one
            return ts.OPEN

        sweep = ts.Sweep(ScriptedProber(script), 1, ts.RateLimiter(0),
                         [("10.0.0.1", 1), ("10.0.0.2", 2)], 1, 0.2)
        self.assertTrue(sweep._canary_answers())


class TestChainHonesty(unittest.TestCase):
    """A canary proves the chain is alive, not that it is honest.

    Observed on a real proxy: every CONNECT answered success regardless of the
    target, so 192.0.2.1 -- an RFC 5737 address that cannot be routed -- came
    back open on 22, 80 and 12345 alike. Every port on every host reads as
    open, the canary passes trivially, and the scan looks perfect while being
    entirely fabricated.
    """

    def _sweep(self):
        return make_sweep(ScriptedProber(lambda task, n: ts.CLOSED))

    def test_fabricating_chain_is_caught_and_stops_the_sweep(self):
        sweep = self._sweep()
        liar = ScriptedProber(lambda task, n: ts.OPEN)     # says yes to anything
        buf = io.StringIO()
        with mock.patch.object(sys, "stderr", buf):
            verdict = ts.start_sanity_probe(liar, sweep,
                                            [(ts.SANITY_HOST, 65401)])
            verdict["done"].wait(timeout=5)
        self.assertTrue(verdict["fabricating"])
        self.assertTrue(sweep.stop.is_set())
        self.assertIn("cannot be reachable", buf.getvalue())

    def test_honest_chain_is_not_accused(self):
        sweep = self._sweep()
        honest = ScriptedProber(lambda task, n: ts.FILTERED)
        verdict = ts.start_sanity_probe(honest, sweep,
                                        [(ts.SANITY_HOST, p)
                                         for p in ts.SANITY_PORTS])
        verdict["done"].wait(timeout=5)
        self.assertFalse(verdict["fabricating"])
        self.assertTrue(verdict["checked"])
        self.assertFalse(sweep.stop.is_set())

    def test_refusal_on_the_sanity_target_is_also_honest(self):
        sweep = self._sweep()
        verdict = ts.start_sanity_probe(ScriptedProber(lambda t, n: ts.CLOSED),
                                        sweep, [(ts.SANITY_HOST, 65401)])
        verdict["done"].wait(timeout=5)
        self.assertFalse(verdict["fabricating"])

    def test_sanity_target_is_a_reserved_address(self):
        # RFC 5737 TEST-NET-1: must never be routable, so a success is proof
        # of fabrication rather than a lucky hit on someone's real host.
        self.assertTrue(
            ipaddress.ip_address(ts.SANITY_HOST) in
            ipaddress.ip_network("192.0.2.0/24"))

    def test_await_sanity_warns_when_it_cannot_conclude(self):
        buf = io.StringIO()
        with mock.patch.object(sys, "stderr", buf):
            ts.await_sanity({"done": ts.threading.Event()}, limit=0.05)
        self.assertIn("unconfirmed", buf.getvalue())


class TestCanaryPreflight(unittest.TestCase):
    """A dead --ct fails every health check, which would declare a healthy
    chain dead mid-sweep. Catch it before starting."""

    def test_open_canary_is_confirmed(self):
        with Listener() as listener:
            prober = ts.Prober(2.0, 1.8, proxied=False)
            self.assertEqual(
                ts.verify_canaries(prober, [("127.0.0.1", listener.port)]),
                ("127.0.0.1", listener.port))

    def test_dead_canary_is_rejected(self):
        prober = ts.Prober(1.0, 0.9, proxied=False)
        self.assertIsNone(ts.verify_canaries(prober, [("127.0.0.1", free_port())]))

    def test_any_one_open_canary_is_enough(self):
        with Listener() as listener:
            prober = ts.Prober(2.0, 1.8, proxied=False)
            found = ts.verify_canaries(prober, [("127.0.0.1", free_port()),
                                                ("127.0.0.1", listener.port)])
            self.assertEqual(found, ("127.0.0.1", listener.port))


class TestRateLimiter(unittest.TestCase):
    def test_zero_rate_is_a_noop(self):
        limiter = ts.RateLimiter(0)
        started = time.monotonic()
        for _ in range(50):
            limiter.take(ts.threading.Event())
        self.assertLess(time.monotonic() - started, 0.2)

    def test_rate_is_enforced(self):
        limiter = ts.RateLimiter(50)
        stop = ts.threading.Event()
        started = time.monotonic()
        for _ in range(5):
            limiter.take(stop)
        self.assertGreater(time.monotonic() - started, 0.05)


# ── Report ────────────────────────────────────────────────────────────

class TestReport(unittest.TestCase):
    def setUp(self):
        self.report = ts.Report()
        self.report.record(result("10.0.0.1", 80, ts.OPEN))
        self.report.record(result("10.0.0.1", 81, ts.CLOSED))
        self.report.record(result("10.0.0.2", 80, ts.FILTERED))

    def test_counts(self):
        self.assertEqual(self.report.counts(),
                         {ts.OPEN: 1, ts.CLOSED: 1, ts.FILTERED: 1})

    def test_open_ports(self):
        self.assertEqual(self.report.open_ports(), {"10.0.0.1": [80]})

    def test_responsive_excludes_stall_only_hosts(self):
        self.assertEqual(self.report.responsive(), ["10.0.0.1"])

    def test_revoke_removes_a_result(self):
        self.report.revoke("10.0.0.1", 81)
        self.assertEqual(self.report.counts()[ts.CLOSED], 0)

    def test_revoking_something_absent_is_harmless(self):
        self.report.revoke("10.9.9.9", 1)

    def test_json_omits_stalls_but_keeps_the_tally(self):
        payload = self.report.as_dict({"proxied": True})
        hosts = {h["host"]: h["ports"] for h in payload["hosts"]}
        self.assertNotIn("10.0.0.2", hosts)          # stall-only host
        self.assertEqual(payload["summary"][ts.FILTERED], 1)
        self.assertTrue(payload["proxied"])

    def test_probed_pairs_prevent_redundant_work(self):
        self.assertIn(("10.0.0.1", 80), self.report.probed())


class TestJournal(unittest.TestCase):
    """Resume must never become the 0.1.x replay bug: it is opt-in, scoped to
    the current run, and carried results are not evidence the chain works."""

    def journal(self, td, name="j.jsonl"):
        return ts.Journal(str(Path(td) / name))

    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            journal = self.journal(td)
            journal.open({"started": time.time()})
            journal.record(result("10.0.0.1", 80, ts.OPEN, banner="nginx"))
            journal.record(result("10.0.0.1", 81, ts.CLOSED))
            journal.close()

            stored, meta = self.journal(td).load()
            self.assertEqual(stored[("10.0.0.1", 80)], (ts.OPEN, "nginx"))
            self.assertEqual(stored[("10.0.0.1", 81)], (ts.CLOSED, None))
            self.assertEqual(meta["tcpsweep"], ts.__version__)

    def test_old_revocation_lines_are_still_honoured(self):
        """Journals written before negatives were journalled write-behind carry
        ``x`` lines for results withdrawn after a chain outage; ignoring them
        would bring those negatives back as though they had been real."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "j.jsonl"
            path.write_text('{"tcpsweep":"0.4.0"}\n'
                            '{"h":"10.0.0.1","p":80,"s":"closed"}\n'
                            '{"h":"10.0.0.1","p":81,"s":"closed"}\n'
                            '{"h":"10.0.0.1","p":80,"x":1}\n')
            stored, _ = ts.Journal(str(path)).load()
            self.assertEqual(stored, {("10.0.0.1", 81): (ts.CLOSED, None)})

    def test_lines_that_are_not_ours_are_ignored_not_fatal(self):
        """Pointing --resume at a --json report used to crash: its pretty-printed
        lines include bare JSON strings and numbers, which are valid JSON but
        not journal entries."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "j.jsonl"
            path.write_text('"10.0.0.5"\n[1, 2]\n123\nnull\n'
                            '{"h":"10.0.0.1","p":80,"s":"open"}\n')
            buf = io.StringIO()
            with mock.patch.object(sys, "stderr", buf):
                stored, _ = ts.Journal(str(path)).load()
            self.assertEqual(stored, {("10.0.0.1", 80): (ts.OPEN, None)})
            self.assertIn("4 unreadable", buf.getvalue())

    def test_wrong_types_and_unknown_states_are_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "j.jsonl"
            path.write_text('{"h":["x"],"p":80,"s":"open"}\n'
                            '{"h":"10.0.0.1","p":"80","s":"open"}\n'
                            '{"h":"10.0.0.1","p":80,"s":"bogus"}\n'
                            '{"h":["x"],"p":80,"x":1}\n')
            with mock.patch.object(sys, "stderr", io.StringIO()):
                stored, _ = ts.Journal(str(path)).load()
            self.assertEqual(stored, {})

    def test_banners_read_from_a_journal_are_cleaned(self):
        """clean() guards the terminal from hostile banners; a journal is just
        another place a banner can come from."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "j.jsonl"
            path.write_text('{"h":"10.0.0.1","p":80,"s":"open",'
                            '"b":"ok\\u001b[31mred"}\n')
            stored, _ = ts.Journal(str(path)).load()
            self.assertNotIn("\033", stored[("10.0.0.1", 80)][1])

    def test_truncated_tail_is_survivable(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "j.jsonl"
            path.write_text('{"tcpsweep":"0.3.0"}\n'
                            '{"h":"10.0.0.1","p":80,"s":"open"}\n'
                            '{"h":"10.0.0.1","p":8')     # killed mid-write
            buf = io.StringIO()
            with mock.patch.object(sys, "stderr", buf):
                stored, _ = ts.Journal(str(path)).load()
            self.assertEqual(stored[("10.0.0.1", 80)], (ts.OPEN, None))
            self.assertIn("unreadable", buf.getvalue())

    def test_missing_file_is_an_empty_start(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(ts.Journal(str(Path(td) / "nope")).load(), ({}, {}))

    def test_file_is_owner_only(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "j.jsonl"
            journal = ts.Journal(str(path))
            journal.open({})
            journal.close()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_carry_over_is_scoped_to_this_run(self):
        """A journal from a wider sweep must not smuggle hosts or ports the
        current invocation never asked about into its results."""
        with tempfile.TemporaryDirectory() as td:
            journal = self.journal(td)
            journal.open({})
            journal.record(result("10.0.0.1", 80, ts.OPEN))
            journal.record(result("10.0.0.9", 80, ts.OPEN))    # out of scope
            journal.record(result("10.0.0.1", 999, ts.OPEN))   # out of scope
            journal.close()

            report = ts.Report()
            with mock.patch.object(sys, "stdout", io.StringIO()):
                carried, _ = ts.carry_over(self.journal(td), report,
                                           ts.Stream(False), ["10.0.0.1"], [80])
            self.assertEqual(carried, 1)
            self.assertEqual(report.open_ports(), {"10.0.0.1": [80]})

    def test_carried_results_do_not_prove_the_chain_works(self):
        """They were not probed this run, so they must not mark the chain
        verified -- that has to be earned live. Run the real thing under a
        (pretend) proxy with one carried open and one live closed port: the
        caveat has to appear even though an open port is listed."""
        with tempfile.TemporaryDirectory() as td:
            carried, live = free_port(), free_port()
            while live == carried:
                live = free_port()
            journal = self.journal(td)
            journal.open({"started": time.time()})
            journal.record(result("127.0.0.1", carried, ts.OPEN))
            journal.close()
            code, out, err = run_main(
                "127.0.0.1", "-p", f"{carried},{live}", "--no-sanity",
                "--no-progress", "--resume", str(Path(td) / "j.jsonl"),
                env=fake_proxy_env(td))
            self.assertEqual(code, ts.EXIT_FOUND)         # the carried open counts
            self.assertEqual(out, f"127.0.0.1 {carried}\n")
            self.assertIn("resumed 1 probe(s)", err)
            self.assertIn("never confirmed", err)
            self.assertIn("carried over from a journal do not count", err)


class TestHelpers(unittest.TestCase):
    def test_clean_neutralises_control_and_escape_bytes(self):
        # Substituted, not deleted: the ESC can no longer start a sequence,
        # and the banner still shows that something was there.
        self.assertEqual(ts.clean("ok\x1b[31m\x00bad"), "ok.[31m.bad")
        self.assertNotIn("\033", ts.clean("\x1b]0;title\x07"))

    def test_human_time(self):
        self.assertEqual(ts.human_time(45), "45s")
        self.assertEqual(ts.human_time(90), "1m30s")
        self.assertEqual(ts.human_time(3700), "1h01m")

    def test_write_private_is_owner_only(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            ts.write_private(str(path), "{}")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_program_name_follows_the_invoked_name(self):
        with mock.patch.object(sys, "argv", ["/usr/local/bin/sweeper"]):
            self.assertEqual(ts.program_name(), "sweeper")
        with mock.patch.object(sys, "argv", ["./tcpsweep.py"]):
            self.assertEqual(ts.program_name(), "tcpsweep")
        # Piped to `python3 -` over ssh, argv[0] is not a name at all.
        for anonymous in ("-", "-c", ""):
            with mock.patch.object(sys, "argv", [anonymous]):
                self.assertEqual(ts.program_name(), "tcpsweep")

    def test_progress_arithmetic(self):
        progress = ts.Progress(10, enabled=False)
        for _ in range(3):
            progress.update(result(state=ts.CLOSED))
        progress.update(result(state=ts.OPEN))
        progress.update(result(state=ts.FILTERED))
        self.assertEqual((progress.done, progress.open_count, progress.stalls),
                         (5, 1, 1))
        progress.withdraw(2)
        self.assertEqual(progress.done, 3)


class TestPositionalSplit(unittest.TestCase):
    """`sweep HOST 22 80 443` must keep working; no address is digits-only."""

    def test_ports_and_targets_separate(self):
        targets, ports = ts.split_positionals(
            ["10.0.0.1", "22", "80", "1-1024"])
        self.assertEqual(targets, ["10.0.0.1"])
        self.assertEqual(ports, ["22", "80", "1-1024"])

    def test_address_forms_are_never_mistaken_for_ports(self):
        forms = ["10.0.0.0/24", "10.0.0.1-20", "10.0.0.{1,5}", "example.com"]
        targets, ports = ts.split_positionals(forms)
        self.assertEqual(targets, forms)
        self.assertEqual(ports, [])

    def test_comma_list_is_a_port_list(self):
        self.assertEqual(ts.split_positionals(["22,80"])[1], ["22,80"])


class TestCanaryParsing(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ts.parse_canaries(["10.0.0.1:22"]), [("10.0.0.1", 22)])

    def test_invalid(self):
        for bad in ["10.0.0.1", "10.0.0.1:", ":22", "10.0.0.1:abc"]:
            with self.assertRaises(SystemExit, msg=bad):
                ts.parse_canaries([bad])


# ── The trust model, part two ─────────────────────────────────────────

def quiet_sweep(sweep, tasks, sink):
    """Run *sweep* with the outage pause shortened and its warnings swallowed."""
    with mock.patch.object(ts, "CHAIN_POLL_START", 0.02), \
            mock.patch.object(sys, "stderr", io.StringIO()):
        sweep.run(tasks, sink.record, sink.revoke, sink.vouch)


class TestTailIsProven(unittest.TestCase):
    """The periodic canary check only fires after ``canary_after`` consecutive
    negatives, so what was left when the queue drained -- always fewer than
    that -- used to be believed with nothing behind it. A chain that died just
    before the last probe answers exactly like a closed port."""

    def test_a_chain_that_dies_after_the_last_open_is_caught_at_the_end(self):
        alive = {"value": True}

        def script(task, _n):
            if task == ("10.0.0.1", 1) and alive["value"]:
                alive["value"] = False       # the canary answers once, then dies
                return ts.OPEN
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canary_after=40,
                           chain_wait=0.2)
        sink = Collector()
        quiet_sweep(sweep, [("10.0.0.1", p) for p in (1, 2, 3, 4)], sink)
        self.assertTrue(sweep.chain_broken)
        self.assertEqual(sweep.outages, 1)
        self.assertEqual(sorted(sink.revoked), [("10.0.0.1", p) for p in (2, 3, 4)])
        self.assertEqual(sink.vouched, [])

    def test_an_explicit_canary_that_dies_after_preflight_is_caught(self):
        # main() marks the chain verified from the preflight probe alone, which
        # used to leave a short run with no later evidence whatsoever.
        sweep = make_sweep(ScriptedProber(lambda task, n: ts.CLOSED),
                           canaries=[("10.9.9.9", 22)], canary_after=40,
                           chain_wait=0.2)
        sweep.chain_verified = True
        sink = Collector()
        quiet_sweep(sweep, [("10.0.0.1", 1), ("10.0.0.1", 2)], sink)
        self.assertTrue(sweep.chain_broken)
        self.assertEqual(sorted(sink.revoked), [("10.0.0.1", 1), ("10.0.0.1", 2)])

    def test_a_healthy_chain_passes_and_vouches_the_tail(self):
        prober = ScriptedProber(
            lambda task, n: ts.OPEN if task[1] == 1 else ts.CLOSED)
        sweep = make_sweep(prober, canary_after=40)
        sink = Collector()
        quiet_sweep(sweep, [("10.0.0.1", p) for p in (1, 2, 3)], sink)
        self.assertEqual(sweep.outages, 0)
        self.assertFalse(sweep.chain_broken)
        self.assertEqual(sorted(sink.vouched), [("10.0.0.1", 2), ("10.0.0.1", 3)])
        self.assertEqual(prober.calls[-1], ("10.0.0.1", 1),
                         "the last thing asked must be the control target")

    def test_a_run_that_ends_on_an_open_needs_no_extra_probe(self):
        prober = ScriptedProber(
            lambda task, n: ts.CLOSED if task[1] == 1 else ts.OPEN)
        sweep = make_sweep(prober, canary_after=40)
        quiet_sweep(sweep, [("10.0.0.1", 1), ("10.0.0.1", 2)], Collector())
        self.assertEqual(len(prober.calls), 2)

    def test_without_a_control_target_there_is_nothing_to_ask(self):
        prober = ScriptedProber(lambda task, n: ts.CLOSED)
        sweep = make_sweep(prober, canary_after=40)
        sink = Collector()
        quiet_sweep(sweep, [("10.0.0.1", p) for p in (1, 2, 3)], sink)
        self.assertEqual(len(prober.calls), 3)
        self.assertEqual(sink.vouched, [], "nothing was proven, nothing vouched")

    def test_a_chain_that_comes_back_gets_its_tail_rerun_and_vouched(self):
        asked = {"n": 0}

        def script(task, _n):
            if task == ("10.0.0.1", 1):
                asked["n"] += 1
                # 1: the probe itself. 2: the final check finds the chain dead.
                # 3: the first poll finds it back. 4: the re-check after the re-run.
                return ts.OPEN if asked["n"] in (1, 3, 4) else ts.CLOSED
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canary_after=40,
                           chain_wait=5)
        sink = Collector()
        quiet_sweep(sweep, [("10.0.0.1", p) for p in (1, 2, 3)], sink)
        self.assertFalse(sweep.chain_broken)
        self.assertEqual(sweep.outages, 1)
        for port in (2, 3):
            history = [e[0] for e in sink.events if e[1:3] == ("10.0.0.1", port)]
            self.assertEqual(history, ["record", "revoke", "record", "vouch"])


class TestVouching(unittest.TestCase):
    """The engine reports which negatives the chain has just proved itself
    after, so the caller can journal exactly those and no others."""

    def test_negatives_are_vouched_only_after_the_proof(self):
        prober = ScriptedProber(
            lambda task, n: ts.OPEN if task[1] == 1 else ts.CLOSED)
        sweep = make_sweep(prober, canary_after=3)
        sink = Collector()
        quiet_sweep(sweep, [("10.0.0.1", p) for p in range(1, 8)], sink)
        self.assertEqual(sorted(sink.vouched),
                         [("10.0.0.1", p) for p in range(2, 8)])
        for port in range(2, 8):
            history = [e[0] for e in sink.events if e[1:3] == ("10.0.0.1", port)]
            self.assertEqual(history, ["record", "vouch"])

    def test_withdrawn_negatives_are_never_vouched(self):
        alive = {"value": True}

        def script(task, _n):
            if task == ("10.0.0.1", 1) and alive["value"]:
                alive["value"] = False
                return ts.OPEN
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canary_after=3,
                           chain_wait=0.2)
        sink = Collector()
        quiet_sweep(sweep, [("10.0.0.1", p) for p in range(1, 9)], sink)
        self.assertTrue(sink.revoked)
        self.assertEqual(sink.vouched, [])


class TestEpochInvalidation(unittest.TestCase):
    """A connect already inside the hook when the proxy dies returns the same
    instant ECONNREFUSED as a closed port. The epoch is how the engine
    recognises an answer that spanned an outage and refuses to record it."""

    def test_a_probe_that_spans_an_outage_is_rerun_not_recorded(self):
        canary, slow = ("10.9.9.9", 22), ("10.0.0.1", 1)
        inside, release = threading.Event(), threading.Event()
        seen = {}

        def script(task, _n):
            seen[task] = seen.get(task, 0) + 1
            if task == slow:
                if seen[task] == 1:
                    inside.set()
                    release.wait(5)        # still in the hook as the chain dies
                    return ts.CLOSED       # ...so this is the dead chain's answer
                return ts.OPEN             # the real answer, on the second try
            if task == canary:
                if seen[task] == 1:
                    release.set()          # the first health check fails: outage
                    return ts.CLOSED
                return ts.OPEN             # the next poll finds the chain back
            inside.wait(5)                 # be sure the slow probe is in flight
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canaries=[canary],
                           canary_after=2, chain_wait=5, concurrency=2)
        sink = Collector()
        quiet_sweep(sweep, [slow, ("10.0.0.1", 2), ("10.0.0.1", 3)], sink)
        self.assertEqual(sweep.outages, 1)
        self.assertEqual(seen[slow], 2,
                         "the stale answer has to be discarded and the probe repeated")
        history = [e[3] for e in sink.events if e[:3] == ("record",) + slow]
        self.assertEqual(history, [ts.OPEN])


class TestHoldback(unittest.TestCase):
    """Nothing reaches stdout or the journal until the chain is judged honest."""

    def setUp(self):
        self.out, self.kept = [], []
        self.verdict = {"fabricating": False, "checked": False,
                        "done": threading.Event()}

    def gate(self, verdict="default"):
        verdict = self.verdict if verdict == "default" else verdict
        return ts.Holdback(verdict, self.out.append, self.kept.append)

    def test_nothing_leaves_before_the_verdict(self):
        gate = self.gate()
        gate.emit(result(port=1))
        gate.keep(result(port=1))
        self.assertEqual((self.out, self.kept), ([], []))

    def test_an_honest_verdict_releases_everything_in_order(self):
        gate = self.gate()
        gate.emit(result(port=1))
        gate.emit(result(port=2))
        gate.keep(result(port=1))
        self.verdict["checked"] = True
        self.verdict["done"].set()
        gate.emit(result(port=3))       # the next result notices the verdict
        self.assertEqual([r.port for r in self.out], [1, 2, 3])
        self.assertEqual([r.port for r in self.kept], [1])

    def test_a_fabricating_verdict_discards_what_was_held_and_stays_sealed(self):
        gate = self.gate()
        gate.emit(result(port=1))
        gate.keep(result(port=1))
        self.verdict.update(fabricating=True, checked=True)
        self.verdict["done"].set()
        gate.emit(result(port=2))
        gate.settle()
        gate.emit(result(port=3))
        self.assertEqual((self.out, self.kept), ([], []))
        self.assertEqual(gate.state, "sealed")

    def test_no_verdict_means_nothing_is_held(self):
        gate = self.gate(verdict=None)
        gate.emit(result(port=1))
        gate.keep(result(port=1))
        self.assertEqual(len(self.out), 1)
        self.assertEqual(len(self.kept), 1)

    def test_an_unconcluded_check_releases_rather_than_loses_findings(self):
        gate = self.gate()
        gate.emit(result(port=1))
        gate.settle()                   # waiting is over; the probe never answered
        self.assertEqual([r.port for r in self.out], [1])

    def test_keep_without_a_journal_is_harmless(self):
        gate = ts.Holdback(None, self.out.append, None)
        gate.keep(result(port=1))


class TestSanityProbeShape(unittest.TestCase):
    def sweep(self):
        return make_sweep(ScriptedProber(lambda task, n: ts.CLOSED))

    def test_targets_are_probed_side_by_side(self):
        # Each probe waits for the other: serial probing would time out here.
        barrier = threading.Barrier(2, timeout=5)

        def script(task, _n):
            barrier.wait()
            return ts.FILTERED

        verdict = ts.start_sanity_probe(
            ScriptedProber(script), self.sweep(),
            [(ts.SANITY_HOST, 1), (ts.SANITY_HOST, 2)])
        self.assertTrue(verdict["done"].wait(10))
        self.assertTrue(verdict["checked"])
        self.assertFalse(verdict["fabricating"])

    def test_a_success_ends_the_wait_while_the_other_probe_is_stuck(self):
        release = threading.Event()

        def script(task, _n):
            if task[1] == 1:
                return ts.OPEN
            release.wait(5)
            return ts.FILTERED

        sweep = self.sweep()
        with mock.patch.object(sys, "stderr", io.StringIO()):
            verdict = ts.start_sanity_probe(
                ScriptedProber(script), sweep,
                [(ts.SANITY_HOST, 1), (ts.SANITY_HOST, 2)])
            self.assertTrue(verdict["done"].wait(3))
        release.set()
        self.assertTrue(verdict["fabricating"])
        self.assertTrue(sweep.stop.is_set())

    def test_a_probe_that_could_not_be_made_leaves_the_verdict_unconfirmed(self):
        def script(task, _n):
            raise OSError(errno.EMFILE, "Too many open files")

        verdict = ts.start_sanity_probe(
            ScriptedProber(script), self.sweep(), [(ts.SANITY_HOST, 1)])
        self.assertTrue(verdict["done"].wait(5))
        self.assertFalse(verdict["checked"])
        self.assertFalse(verdict["fabricating"])
        buf = io.StringIO()
        with mock.patch.object(sys, "stderr", buf):
            ts.await_sanity(verdict, limit=1)
        self.assertIn("unconfirmed", buf.getvalue())
        self.assertEqual(ts.sanity_state(verdict), "unconfirmed")

    def test_sanity_state_names_every_outcome(self):
        self.assertEqual(ts.sanity_state(None), "skipped")
        self.assertEqual(ts.sanity_state({"fabricating": True, "checked": True}),
                         "failed")
        self.assertEqual(ts.sanity_state({"fabricating": False, "checked": True}),
                         "passed")


class TestHonestyEndToEnd(unittest.TestCase):
    """The whole of main(), under a pretend proxy, with the sanity probe aimed
    at loopback: a listener there stands in for a chain that answers success
    to a target that cannot exist."""

    def run_tool(self, td, *args, sanity_ports):
        with mock.patch.object(ts, "SANITY_HOST", "127.0.0.1"), \
                mock.patch.object(ts, "SANITY_PORTS", tuple(sanity_ports)):
            return run_main(*args, "--no-progress", env=fake_proxy_env(td))

    def journal_entries(self, path):
        lines = [json.loads(line) for line in Path(path).read_text().splitlines()]
        return [entry for entry in lines if "h" in entry]

    def test_a_fabricating_chain_gets_nothing_out_and_nothing_journalled(self):
        with Listener() as target, Listener() as liar, \
                tempfile.TemporaryDirectory() as td:
            journal, report = Path(td) / "j.jsonl", Path(td) / "r.json"
            code, out, err = self.run_tool(
                td, "127.0.0.1", "-p", str(target.port), "--resume", str(journal),
                "--json", str(report), sanity_ports=[liar.port])
            self.assertEqual(code, ts.EXIT_PROXY)
            self.assertEqual(out, "", "a fabricated hit must never reach a pipeline")
            self.assertEqual(self.journal_entries(journal), [],
                             "...nor be replayed by the next --resume")
            payload = json.loads(report.read_text())
            self.assertTrue(payload["chain_fabricating"])
            self.assertEqual(payload["chain_sanity"], "failed")
            self.assertIn("untrustworthy", err)

    def test_an_honest_chain_releases_what_was_held(self):
        with Listener() as target, tempfile.TemporaryDirectory() as td:
            journal, report = Path(td) / "j.jsonl", Path(td) / "r.json"
            code, out, err = self.run_tool(
                td, "127.0.0.1", "-p", str(target.port), "--resume", str(journal),
                "--json", str(report), sanity_ports=[free_port(), free_port()])
            self.assertEqual(code, ts.EXIT_FOUND)
            self.assertEqual(out, f"127.0.0.1 {target.port}\n")
            self.assertEqual(
                [(e["h"], e["p"], e["s"]) for e in self.journal_entries(journal)],
                [("127.0.0.1", target.port, ts.OPEN)])
            self.assertEqual(json.loads(report.read_text())["chain_sanity"],
                             "passed")

    def test_no_sanity_streams_immediately_and_says_so_in_the_json(self):
        with Listener() as target, tempfile.TemporaryDirectory() as td:
            report = Path(td) / "r.json"
            code, out, _ = run_main(
                "127.0.0.1", "-p", str(target.port), "--no-sanity", "-q",
                "--json", str(report), env=fake_proxy_env(td))
            self.assertEqual(code, ts.EXIT_FOUND)
            self.assertEqual(out, f"127.0.0.1 {target.port}\n")
            self.assertEqual(json.loads(report.read_text())["chain_sanity"],
                             "skipped")

    def test_an_unconcluded_check_still_releases_at_the_end(self):
        """If the verdict never arrives, the findings are released with a
        warning rather than lost -- and main() has to be the one to do it."""
        stuck = {"fabricating": False, "checked": False,
                 "done": threading.Event()}
        with Listener() as target, tempfile.TemporaryDirectory() as td:
            report = Path(td) / "r.json"
            with mock.patch.object(ts, "start_sanity_probe", lambda *a: stuck), \
                    mock.patch.object(ts, "await_sanity", lambda *a: None):
                code, out, _ = run_main(
                    "127.0.0.1", "-p", str(target.port), "--json", str(report),
                    "--no-progress", env=fake_proxy_env(td))
            self.assertEqual(code, ts.EXIT_FOUND)
            self.assertEqual(out, f"127.0.0.1 {target.port}\n")
            self.assertEqual(json.loads(report.read_text())["chain_sanity"],
                             "unconfirmed")

    def test_a_carried_open_is_held_back_too(self):
        # A resumed run's stdout is only complete -- and only trustworthy --
        # once the chain has been judged, carried findings included.
        with Listener() as liar, tempfile.TemporaryDirectory() as td:
            journal = Path(td) / "j.jsonl"
            carried = free_port()
            writer = ts.Journal(str(journal))
            writer.open({"started": time.time()})
            writer.record(result("127.0.0.1", carried, ts.OPEN))
            writer.close()
            code, out, _ = self.run_tool(
                td, "127.0.0.1", "-p", str(carried), "--resume", str(journal),
                sanity_ports=[liar.port])
            self.assertEqual(code, ts.EXIT_PROXY)
            self.assertEqual(out, "")


# ── Hardening: the engine ─────────────────────────────────────────────

class TestGate(unittest.TestCase):
    """The pause gate and the epoch move in a fixed order, because a probe can
    be anywhere in between."""

    def test_the_gate_closes_before_the_epoch_moves(self):
        gate = ts.Gate()
        log = []

        class Spy(threading.Event):
            def clear(self):
                log.append(gate.epoch)      # the epoch at the moment of closing
                super().clear()

        gate._open = Spy()
        gate._open.set()
        gate.close()
        self.assertEqual(log, [0])
        self.assertEqual(gate.epoch, 1)

    def test_a_probe_that_slips_through_as_the_chain_dies_is_discarded(self):
        """Stamped after the gate, this probe would carry the new epoch onto the
        dead chain, and its instant refusal would be recorded as a real
        'closed' -- 12 times in 1200 runs of a 16-worker stress test."""
        class OutageAtTheGate(ts.Gate):
            fired = False

            def wait(self):
                super().wait()
                if not self.fired:
                    self.fired = True
                    self.close()            # the chain dies as the worker walks through
                    threading.Timer(0.05, self.release).start()

        seen = []

        def script(task, _n):
            seen.append(task)
            # The dead chain's answer, then the truth.
            return ts.CLOSED if len(seen) == 1 else ts.OPEN

        sweep = make_sweep(ScriptedProber(script), canary_after=10_000)
        sweep.gate = OutageAtTheGate()
        sink = Collector()
        sweep.run([("10.0.0.1", 1)], sink.record, sink.revoke)
        self.assertEqual(len(seen), 2,
                         "the stale answer has to be thrown away and repeated")
        self.assertEqual(sink.recorded, [("10.0.0.1", 1, ts.OPEN)])


class TestCompletionOrder(unittest.TestCase):
    def test_an_open_vouches_only_for_negatives_that_finished_before_it(self):
        """Probes finish in one order and could be handled in another. An open
        port proves the chain was alive when it answered; a negative that came
        back afterwards -- possibly from a dead chain -- is not covered by it."""
        host = "10.0.0.1"
        first, slow, opener = (host, 10), (host, 11), (host, 12)
        canary = ("10.9.9.9", 22)
        busy, opener_done, slow_done, release = (threading.Event()
                                                 for _ in range(4))

        def script(task, _n):
            if task == canary:
                return ts.OPEN
            if task == opener:
                busy.wait(5)                # answer only once main is occupied...
                opener_done.set()
                return ts.OPEN
            if task == slow:
                opener_done.wait(5)         # ...and come back after the open port
                slow_done.set()
                return ts.CLOSED
            return ts.CLOSED

        class Busy(Collector):
            def record(self, res):
                super().record(res)
                if (res.host, res.port) == first:
                    busy.set()
                    release.wait(5)

        def let_go():
            slow_done.wait(5)
            time.sleep(0.15)                # both futures are done when main looks
            release.set()

        threading.Thread(target=let_go, daemon=True).start()
        sweep = make_sweep(ScriptedProber(script), canaries=[canary],
                           canary_after=10_000, concurrency=3)
        sink = Busy()
        quiet_sweep(sweep, [first, slow, opener], sink)
        order = [e[:3] for e in sink.events]
        opened = order.index(("record",) + opener)
        self.assertLess(order.index(("vouch",) + first), opened)
        self.assertGreater(order.index(("vouch",) + slow), opened,
                           "the late negative waits for a proof of its own")


class TestDirectMode(unittest.TestCase):
    def test_direct_results_are_trusted_and_vouched_as_they_arrive(self):
        """A one-shot service, an IPS that starts dropping the scanner, a
        crash: with no proxy none of them is 'the chain is down', yet the tail
        proof used to withdraw the results and wait two minutes before exit 3."""
        seen = {}

        def script(task, _n):
            seen[task] = seen.get(task, 0) + 1
            return ts.OPEN if task[1] == 1 and seen[task] == 1 else ts.CLOSED

        prober = ScriptedProber(script)
        sweep = make_sweep(prober, canary_after=2, police=False)
        sink = Collector()
        quiet_sweep(sweep, [("10.0.0.1", p) for p in range(1, 7)], sink)
        self.assertEqual(sweep.outages, 0)
        self.assertFalse(sweep.chain_broken)
        self.assertEqual(sweep.canaries, [], "nothing to arm without a chain")
        self.assertEqual(len(prober.calls), 6, "no control-target probes at all")
        self.assertEqual(sorted(sink.vouched),
                         [("10.0.0.1", p) for p in range(2, 7)])
        for port in range(2, 7):
            history = [e[0] for e in sink.events if e[1:3] == ("10.0.0.1", port)]
            self.assertEqual(history, ["record", "vouch"])

    def test_an_explicit_canary_turns_policing_on_even_without_a_proxy(self):
        sweep = make_sweep(ScriptedProber(lambda t, n: ts.CLOSED),
                           canaries=[("10.9.9.9", 22)], police=False)
        self.assertTrue(sweep.police)

    def test_main_polices_only_under_a_proxy(self):
        seen, real = [], ts.Sweep

        def spy(*args, **kwargs):
            seen.append(kwargs.get("police"))
            return real(*args, **kwargs)

        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(ts, "Sweep", spy), \
                mock.patch.object(ts, "sweep_all", lambda *a: None):
            run_main("127.0.0.1", "-p", "80", "-q", "--no-sanity",
                     env=fake_proxy_env(td))
            run_main("127.0.0.1", "-p", "80", "-q")
        self.assertEqual(seen, [True, False])


class TestExitCode(unittest.TestCase):
    """The order matters: the more a run must not be believed, the earlier it
    decides the code."""

    def code(self, broken=False, lost=(), found=False, fabricating=False,
             interrupted=False):
        report = ts.Report()
        report.record(result(state=ts.OPEN if found else ts.CLOSED))
        sweep = types.SimpleNamespace(chain_broken=broken, lost=list(lost))
        return ts.exit_code(sweep, report, fabricating, interrupted)

    def test_found_and_nothing(self):
        self.assertEqual(self.code(found=True), ts.EXIT_FOUND)
        self.assertEqual(self.code(found=False), ts.EXIT_NONE)

    def test_a_broken_chain_or_lost_probes_outrank_a_find(self):
        self.assertEqual(self.code(found=True, broken=True), ts.EXIT_PROXY)
        self.assertEqual(self.code(found=True, lost=[("h", 1)]), ts.EXIT_PROXY)

    def test_interruption_outranks_a_broken_chain(self):
        self.assertEqual(self.code(broken=True, interrupted=True),
                         ts.EXIT_INTERRUPT)

    def test_fabrication_outranks_everything(self):
        self.assertEqual(self.code(found=True, interrupted=True, fabricating=True),
                         ts.EXIT_PROXY)


class TestOutagePatience(unittest.TestCase):
    def test_a_control_target_that_keeps_dropping_ends_the_run(self):
        """It answers just long enough to be let back in and then stops again,
        so nothing is ever proven: the sweep used to go round for ever."""
        canary = ("10.9.9.9", 22)
        asked = {"n": 0}

        def script(task, _n):
            if task == canary:
                asked["n"] += 1
                # Fails the check, passes the poll, fails the next check...
                return ts.OPEN if asked["n"] % 2 == 0 else ts.CLOSED
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canaries=[canary],
                           canary_after=2, chain_wait=5)
        sink = Collector()
        runner = threading.Thread(
            target=quiet_sweep,
            args=(sweep, [("10.0.0.1", p) for p in range(1, 40)], sink),
            daemon=True)
        runner.start()
        runner.join(20)
        self.assertFalse(runner.is_alive(), "the sweep must not go round for ever")
        self.assertTrue(sweep.chain_broken)
        self.assertEqual(sweep.outages, ts.OUTAGE_PATIENCE + 1)

    def test_a_flaky_control_target_does_not_abort_a_run_that_is_progressing(self):
        """A control target that merely drops now and then (sshd's MaxStartups
        is one way) is an outage each time, and it can drop several checks in a
        row before it answers. That must not add up to 'gave up': a patience of
        three aborted sweeps whose chain was perfectly healthy."""
        canary = ("10.9.9.9", 22)
        answers = [False, True] * 5         # five failed checks, each let back in
        asked = {"n": 0}

        def script(task, _n):
            if task == canary:
                asked["n"] += 1
                return ts.OPEN if asked["n"] > len(answers) or answers[asked["n"] - 1] else ts.CLOSED
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canaries=[canary],
                           canary_after=2, chain_wait=5)
        sink = Collector()
        runner = threading.Thread(
            target=quiet_sweep,
            args=(sweep, [("10.0.0.1", p) for p in range(1, 41)], sink),
            daemon=True)
        runner.start()
        runner.join(30)
        self.assertFalse(runner.is_alive())
        self.assertFalse(sweep.chain_broken)
        self.assertEqual(sweep.outages, 5)
        self.assertEqual(len({(h, p) for h, p, _ in sink.recorded}), 40)


class TestUnsendableProbesAtScale(unittest.TestCase):
    def test_a_failing_probe_does_not_stall_the_others(self):
        """The retry backoff is paid on a worker. On the main thread it froze
        every other result behind one failing probe."""
        started = time.monotonic()
        first_other = []

        class Timed(Collector):
            def record(self, res):
                super().record(res)
                if res.port != 1 and not first_other:
                    first_other.append(time.monotonic() - started)

        def script(task, _n):
            if task == ("10.0.0.1", 1):
                raise OSError(errno.EMFILE, "Too many open files")
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canary_after=10_000,
                           concurrency=2)
        sink = Timed()
        with mock.patch.object(ts, "PROBE_BACKOFF", 0.4), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            sweep.run([("10.0.0.1", p) for p in range(1, 6)],
                      sink.record, sink.revoke)
        self.assertLess(first_other[0], 0.2)

    def test_a_run_of_unsendable_probes_stops_the_sweep(self):
        def script(task, _n):
            raise OSError(errno.EMFILE, "Too many open files")

        sweep = make_sweep(ScriptedProber(script), canary_after=10_000,
                           concurrency=4)
        buf = io.StringIO()
        with mock.patch.object(ts, "PROBE_BACKOFF", 0.001), \
                mock.patch.object(ts, "LOST_LIMIT", 5), \
                mock.patch.object(sys, "stderr", buf):
            sweep.run([("10.0.0.1", p) for p in range(1, 400)],
                      Collector().record, Collector().revoke)
        self.assertTrue(sweep.stop.is_set())
        self.assertGreaterEqual(len(sweep.lost), 5)
        self.assertLess(len(sweep.lost), 60, "it has to stop, not grind on")
        self.assertIn("stopping", buf.getvalue())


class TestHoldbackTiming(unittest.TestCase):
    """The verdict lands at some moment, and that is when output is released --
    not whenever the sweep next happens to have something to say. A lone open
    port used to sit held until the sweep ended, or for ever on SIGTERM."""

    def setUp(self):
        self.out, self.kept = [], []
        self.verdict = {"fabricating": False, "checked": False,
                        "done": threading.Event()}
        self.gate = ts.Holdback(self.verdict, self.out.append, self.kept.append)

    def wait_for(self, condition):
        deadline = time.monotonic() + 3
        while not condition() and time.monotonic() < deadline:
            time.sleep(0.01)

    def test_release_happens_when_the_verdict_lands(self):
        self.gate.emit(result(port=1))
        self.gate.keep(result(port=1))
        self.assertEqual((self.out, self.kept), ([], []))
        self.verdict["checked"] = True
        self.verdict["done"].set()          # nobody calls the gate again
        self.wait_for(lambda: self.out and self.kept)
        self.assertEqual([r.port for r in self.out], [1])
        self.assertEqual([r.port for r in self.kept], [1])

    def test_a_fabricating_verdict_discards_at_once_too(self):
        self.gate.emit(result(port=1))
        self.verdict.update(fabricating=True, checked=True)
        self.verdict["done"].set()
        self.wait_for(lambda: self.gate.state == "sealed")
        self.assertEqual(self.gate.state, "sealed")
        self.assertEqual((self.out, self.gate.held), ([], []))

    def test_an_unconfirmed_release_shows_open_ports_but_journals_nothing(self):
        self.gate.emit(result(port=1))
        self.gate.keep(result(port=1))
        self.gate.settle()                  # the probe never concluded
        self.gate.emit(result(port=2))
        self.gate.keep(result(port=2))
        self.assertEqual(self.gate.state, "unconfirmed")
        self.assertEqual([r.port for r in self.out], [1, 2])
        self.assertEqual(self.kept, [], "a journal is replayed without a probe")

    def test_a_concurrent_release_neither_loses_nor_reorders(self):
        for port in range(1, 401):
            if port == 150:
                self.verdict["checked"] = True
                self.verdict["done"].set()  # lands mid-stream, on another thread
            self.gate.emit(result(port=port))
            if port % 25 == 0:
                time.sleep(0.005)
        self.gate.settle()
        self.assertEqual([r.port for r in self.out], list(range(1, 401)))


class TestHonestyWait(unittest.TestCase):
    def verdict(self):
        return {"fabricating": False, "checked": False,
                "done": threading.Event()}

    def test_ctrl_c_shortens_the_wait(self):
        verdict, stop = self.verdict(), threading.Event()
        threading.Timer(0.2, stop.set).start()
        started = time.monotonic()
        with mock.patch.object(sys, "stderr", io.StringIO()):
            ts.await_sanity(verdict, limit=30, stop=stop)
        self.assertLess(time.monotonic() - started, 5)

    def test_it_returns_the_moment_the_verdict_lands(self):
        verdict = self.verdict()

        def land():
            verdict["checked"] = True
            verdict["done"].set()

        threading.Timer(0.2, land).start()
        buf, started = io.StringIO(), time.monotonic()
        with mock.patch.object(sys, "stderr", buf):
            ts.await_sanity(verdict, limit=30)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(buf.getvalue(), "")


class TestUnconfirmedEndToEnd(unittest.TestCase):
    def test_an_unconfirmed_check_shows_the_open_port_but_journals_nothing(self):
        stuck = {"fabricating": False, "checked": False,
                 "done": threading.Event()}
        with Listener() as target, tempfile.TemporaryDirectory() as td:
            journal = Path(td) / "j.jsonl"
            with mock.patch.object(ts, "start_sanity_probe", lambda *a: stuck), \
                    mock.patch.object(ts, "await_sanity", lambda *a, **k: None):
                code, out, _ = run_main(
                    "127.0.0.1", "-p", str(target.port), "--resume", str(journal),
                    "--no-progress", env=fake_proxy_env(td))
            self.assertEqual(code, ts.EXIT_FOUND)
            self.assertEqual(out, f"127.0.0.1 {target.port}\n")
            lines = [json.loads(x) for x in journal.read_text().splitlines()]
            self.assertEqual([x for x in lines if "h" in x], [],
                             "an unjudged result must not outlive the run")


# ── Hardening: the edges ──────────────────────────────────────────────

class TestHardening(unittest.TestCase):
    def test_a_crash_is_not_a_clean_negative(self):
        """Python exits 1 on an uncaught exception, and 1 is 'completed,
        nothing open'."""
        with mock.patch.object(ts, "Sweep", side_effect=RuntimeError("boom")):
            code, _, err = run_main("127.0.0.1", "-p", "80", "-q")
        self.assertEqual(code, ts.EXIT_PROXY)
        self.assertIn("RuntimeError: boom", err)
        self.assertIn("cannot be trusted", err)

    def test_a_vanished_stderr_does_not_end_the_run(self):
        """An ssh session that drops closes stderr; the next warning or progress
        line raised, and the run died with no report and exit status 120."""
        class Gone(io.StringIO):
            def write(self, text):
                raise BrokenPipeError(errno.EPIPE, "Broken pipe")

        with Listener() as target, tempfile.TemporaryDirectory() as td:
            report = Path(td) / "r.json"
            code, out, _ = run_main("127.0.0.1", "-p", str(target.port),
                                    "--json", str(report), stderr=Gone())
            self.assertEqual(code, ts.EXIT_FOUND)
            self.assertEqual(out, f"127.0.0.1 {target.port}\n")
            self.assertTrue(report.exists())

    def test_a_broken_stdout_neither_raises_nor_changes_the_exit_status(self):
        class Broken(io.StringIO):
            def write(self, text):
                raise BrokenPipeError(errno.EPIPE, "Broken pipe")

            def flush(self):
                raise BrokenPipeError(errno.EPIPE, "Broken pipe")

        with mock.patch.object(sys, "stdout", Broken()):
            ts.Stream(False).emit(result())
            ts._flush_quietly(sys.stdout)

    def test_the_tolerant_stream_delegates_the_rest(self):
        self.assertFalse(ts.Tolerant(io.StringIO()).isatty())

    def signals(self):
        return {name: signal.getsignal(getattr(signal, name))
                for name in ("SIGINT", "SIGTERM", "SIGHUP")}

    def restore(self, saved):
        for name, handler in saved.items():
            signal.signal(getattr(signal, name), handler)

    def test_sigterm_and_sighup_stop_the_sweep_like_ctrl_c(self):
        """SIGHUP is a dropped ssh session with a terminal, SIGTERM is `timeout`
        or a service manager; both used to kill the run without a report."""
        saved = self.signals()
        try:
            for name in ("SIGTERM", "SIGHUP"):
                # Without a handler of the tool's own, the default action would
                # kill the test run itself: catch the signal here instead, so a
                # regression is a failed assertion and not a dead runner.
                signal.signal(getattr(signal, name), lambda signum, frame: None)
                sweep = make_sweep(ScriptedProber(lambda t, n: ts.CLOSED))
                hit = ts.install_sigint(sweep)
                os.kill(os.getpid(), getattr(signal, name))
                self.assertTrue(hit["value"], name)
                self.assertTrue(sweep.stop.is_set(), name)
        finally:
            self.restore(saved)

    def test_a_second_ctrl_c_aborts_at_once(self):
        """A connect already inside the hook cannot be cancelled and can take a
        whole read timeout to return; the operator must not have to wait."""
        saved = self.signals()
        try:
            # Start from the ordinary handler whatever the environment set: a
            # background job begins with SIGINT ignored, and the tool respects
            # that (see test_a_signal_the_caller_ignores_stays_ignored).
            signal.signal(signal.SIGINT, signal.default_int_handler)
            with mock.patch.object(ts.os, "_exit") as hard_exit:
                sweep = make_sweep(ScriptedProber(lambda t, n: ts.CLOSED))
                ts.install_sigint(sweep)
                handler = signal.getsignal(signal.SIGINT)
                handler(signal.SIGINT, None)
                self.assertTrue(sweep.stop.is_set())
                hard_exit.assert_not_called()
                handler(signal.SIGINT, None)
                hard_exit.assert_called_once_with(ts.EXIT_INTERRUPT)
        finally:
            self.restore(saved)

    def test_numeric_shorthand_is_refused_not_resolved(self):
        """getaddrinfo follows inet_aton: '010.0.0.1' is octal and means
        8.0.0.1, '192.168.1' means 192.168.0.1. Scanning a different host from
        the one typed, without a word, is the one mistake a scope cannot afford."""
        proxy = ts.Proxy()
        for spec in ("010.0.0.1", "192.168.1", "0x7f.1", "2130706433"):
            with self.assertRaises(SystemExit, msg=spec):
                ts.expand_target(spec, proxy)

    def test_real_names_and_addresses_still_resolve(self):
        proxy = ts.Proxy()
        real = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))]
        with mock.patch.object(socket, "getaddrinfo", return_value=real):
            self.assertEqual(ts.expand_target("web01.corp.example", proxy),
                             ["10.1.2.3"])
        self.assertEqual(ts.expand_target("10.0.0.7", proxy), ["10.0.0.7"])

    def test_excluding_a_hostname_through_proxy_dns_is_refused(self):
        """Under proxy_dns the name resolves to a placeholder that can never
        match a real target, so the exclusion silently excluded nothing."""
        proxy = ts.Proxy()
        proxy.active = proxy.proxy_dns = True
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("224.0.0.7", 0))]
        with mock.patch.object(socket, "getaddrinfo", return_value=fake):
            with self.assertRaises(SystemExit):
                ts.collect_targets(["10.0.0.1-3"], ["web01.corp.example"], proxy)

    def test_excluding_a_hostname_directly_still_works(self):
        proxy = ts.Proxy()
        real = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0))]
        with mock.patch.object(socket, "getaddrinfo", return_value=real):
            self.assertEqual(
                ts.collect_targets(["10.0.0.1-3"], ["web01"], proxy),
                ["10.0.0.1", "10.0.0.3"])

    def test_a_journal_that_recurses_or_overflows_is_survivable(self):
        """--resume may be pointed at anything: 200000 open brackets recursed
        the JSON parser to death, a -Infinity timestamp overflowed the age
        warning, and `true` was accepted as a port and printed as one."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "j.jsonl"
            path.write_text("[" * 200000 + "\n"
                            '{"tcpsweep":"0.5.0","started":-Infinity}\n'
                            '{"h":"127.0.0.1","p":true,"s":"open"}\n'
                            '{"h":"127.0.0.1","p":0,"s":"open"}\n'
                            '{"h":"127.0.0.1","p":70000,"s":"open"}\n'
                            '{"h":"127.0.0.1","p":80,"s":"open"}\n')
            with mock.patch.object(sys, "stderr", io.StringIO()):
                stored, _ = ts.Journal(str(path)).load()
            self.assertEqual(stored, {("127.0.0.1", 80): (ts.OPEN, None)})
            code, out, err = run_main("127.0.0.1", "-p", "80", "--resume",
                                      str(path), "--no-progress")
            self.assertEqual(code, ts.EXIT_FOUND)
            self.assertEqual(out, "127.0.0.1 80\n")
            self.assertNotIn("Traceback", err)


    def test_a_signal_the_caller_ignores_stays_ignored(self):
        """nohup sets SIGHUP to SIG_IGN so that a sweep outlives its terminal;
        handling it anyway turned 'survive the logout' into 'stop'."""
        saved = self.signals()
        try:
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            ts.install_sigint(make_sweep(ScriptedProber(lambda t, n: ts.CLOSED)))
            self.assertEqual(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)
            self.assertNotIn(signal.getsignal(signal.SIGTERM),
                             (signal.SIG_IGN, signal.SIG_DFL))
        finally:
            self.restore(saved)

    def test_an_address_exclusion_cannot_apply_to_a_hostname_target(self):
        """Under proxy_dns a hostname target is a placeholder whose real address
        is not ours to know, so --exclude 10.0.0.5 silently did nothing for it."""
        proxy = ts.Proxy()
        proxy.active = proxy.proxy_dns = True
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("224.0.0.5", 0))]
        with mock.patch.object(socket, "getaddrinfo", return_value=fake), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                ts.collect_targets(["dc01.corp.local"], ["10.0.0.5"], proxy)

    def test_literal_targets_can_still_be_excluded_under_proxy_dns(self):
        """Even with remote_dns_subnet 10, where a literal 10.x address looks
        like a placeholder by value: only what a hostname really resolved to
        counts."""
        proxy = ts.Proxy()
        proxy.active = proxy.proxy_dns = True
        proxy.dns_subnet = 10
        self.assertEqual(
            ts.collect_targets(["10.0.0.1-3"], ["10.0.0.2"], proxy),
            ["10.0.0.1", "10.0.0.3"])

    def test_leading_zeros_are_refused_even_where_ipaddress_accepts_them(self):
        """Before Python 3.8.12 / 3.9.5, ipaddress read 010.0.0.1 as decimal
        (CVE-2021-29921) while the connect reads it as octal, 8.0.0.1. Faked
        here, since a modern interpreter never shows it."""
        class Lenient:
            def __init__(self, text):
                parts = text.split(".")
                if len(parts) != 4 or not all(x.isdigit() for x in parts):
                    raise ValueError(text)
                self.value = ".".join(str(int(x)) for x in parts)

            def __str__(self):
                return self.value

        with mock.patch.object(ipaddress, "IPv4Address", Lenient):
            for spec in ("010.0.0.1", "010.0.0.1-3"):
                with self.assertRaises(SystemExit, msg=spec):
                    ts.expand_target(spec, ts.Proxy())
            self.assertEqual(ts.expand_target("10.0.0.1", ts.Proxy()),
                             ["10.0.0.1"])

    def test_a_directory_is_not_a_report_file(self):
        with tempfile.TemporaryDirectory() as td:
            for path in (td, td + "/", str(Path(td) / "new") + "/"):
                with self.assertRaises(SystemExit, msg=path):
                    ts.check_report_path(path, "--json")

    def test_a_journal_timestamp_is_input(self):
        for bad in (10 ** 400, float("-inf"), float("nan"), True, "yesterday", None):
            self.assertIsNone(ts.journal_age(bad), repr(bad)[:30])
        self.assertAlmostEqual(ts.journal_age(time.time() - 100), 100, delta=5)

    def test_an_abandoned_run_is_not_reported_as_verified(self):
        class Abandoned(ts.Sweep):
            def run(self, tasks, record, revoke, vouch=None):
                self.chain_verified = True      # an open port answered earlier...
                self.chain_broken = True        # ...and then the chain never came back
                self.stop.set()

        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(ts, "Sweep", Abandoned):
            report = Path(td) / "r.json"
            code, _, err = run_main("127.0.0.1", "-p", "80", "-q",
                                    "--json", str(report))
            payload = json.loads(report.read_text())
        self.assertEqual(code, ts.EXIT_PROXY)
        self.assertTrue(payload["chain_broken"])
        self.assertFalse(payload["chain_verified"])

    def test_a_direct_scan_journals_its_negatives_as_it_goes(self):
        """No proxy, nothing to police: refusals are trusted and journalled at
        once, with no canary and no open port needed."""
        with tempfile.TemporaryDirectory() as td:
            ports = [free_port(), free_port()]
            while ports[0] == ports[1]:
                ports[1] = free_port()
            journal = Path(td) / "j.jsonl"
            code, _, _ = run_main("127.0.0.1", "-p", ",".join(map(str, ports)),
                                  "--resume", str(journal), "--no-progress", "-q")
            entries = [json.loads(x) for x in journal.read_text().splitlines()
                       if '"h"' in x]
        self.assertEqual(code, ts.EXIT_NONE)
        self.assertEqual(sorted((e["p"], e["s"]) for e in entries),
                         sorted((port, ts.CLOSED) for port in ports))


# ── What the journal is given ─────────────────────────────────────────

class TestWriteBehindJournal(unittest.TestCase):
    """Opens go in at once; negatives only once the chain has vouched for them,
    so a chain that died a moment before an interruption cannot leave a run of
    fake 'closed' behind for --resume to believe."""

    def sweep_all(self, script, ports, canary_after=4, chain_wait=0.2,
                  stop_at=None):
        sweep = make_sweep(ScriptedProber(script), canary_after=canary_after,
                           chain_wait=chain_wait)
        out = Sink()
        with mock.patch.object(ts, "CHAIN_POLL_START", 0.02), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            ts.sweep_all(sweep, ts.Report(), out, ts.Progress(0, False),
                         ["10.0.0.1"], ports, types.SimpleNamespace(shuffle=False),
                         [])
        return sweep, out

    def test_a_healthy_run_journals_everything_it_can_stand_behind(self):
        _, out = self.sweep_all(
            lambda task, n: ts.OPEN if task[1] == 1 else ts.CLOSED, range(1, 8))
        self.assertEqual(sorted(out.kept),
                         [("10.0.0.1", p, ts.OPEN if p == 1 else ts.CLOSED)
                          for p in range(1, 8)])

    def test_negatives_before_a_dead_chain_are_never_journalled(self):
        alive = {"value": True}

        def script(task, _n):
            if task == ("10.0.0.1", 1) and alive["value"]:
                alive["value"] = False
                return ts.OPEN
            return ts.CLOSED

        sweep, out = self.sweep_all(script, range(1, 9), canary_after=3)
        self.assertTrue(sweep.chain_broken)
        self.assertEqual(out.kept, [("10.0.0.1", 1, ts.OPEN)])

    def test_without_any_proof_no_negative_is_journalled(self):
        _, out = self.sweep_all(lambda task, n: ts.CLOSED, range(1, 6))
        self.assertEqual(out.kept, [])

    def test_an_interruption_keeps_the_unproven_tail_out(self):
        proven = threading.Event()

        def script(task, _n):
            if task[1] != 1:
                proven.wait(5)      # the open is handled before any negative
            return ts.OPEN if task[1] == 1 else ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canary_after=1000)

        class Interrupted(ts.Report):
            negatives = 0

            def record(self, res):
                super().record(res)
                if res.state != ts.OPEN:
                    self.negatives += 1
                    if self.negatives == 3:
                        sweep.stop.set()        # Ctrl+C, in effect

        class Watching(Sink):
            def keep(self, res):
                super().keep(res)
                proven.set()

        report, out = Interrupted(), Watching()
        with mock.patch.object(sys, "stderr", io.StringIO()):
            ts.sweep_all(sweep, report, out, ts.Progress(0, False),
                         ["10.0.0.1"], range(1, 10),
                         types.SimpleNamespace(shuffle=False), [])
        self.assertGreaterEqual(report.negatives, 3)
        # Three negatives were recorded, but the chain never proved itself
        # after them: only the open port, its own proof, was written down.
        self.assertEqual(out.kept, [("10.0.0.1", 1, ts.OPEN)])

    def test_only_opens_reach_stdout(self):
        _, out = self.sweep_all(
            lambda task, n: ts.OPEN if task[1] in (1, 3) else ts.CLOSED,
            range(1, 6))
        self.assertEqual(sorted(p for _, p, _ in out.emitted), [1, 3])


class TestLostProbes(unittest.TestCase):
    def test_socket_creation_failure_is_not_disguised_as_a_result(self):
        prober = ts.Prober(1.0, 0.9, proxied=False)
        with mock.patch.object(ts.socket, "socket",
                               side_effect=OSError(errno.EMFILE, "Too many open files")):
            with self.assertRaises(OSError):
                prober(("127.0.0.1", 9))

    def test_a_lost_probe_does_not_get_its_host_skipped(self):
        """Triage skips a host whose discovery probes all stalled. A probe that
        never happened is not a stall."""
        def script(task, _n):
            if task[0] == "10.0.0.1":
                raise OSError(errno.EMFILE, "Too many open files")
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canary_after=10_000)
        report = ts.Report()
        with mock.patch.object(ts, "PROBE_BACKOFF", 0.01), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            ts.sweep_all(sweep, report, Sink(), ts.Progress(0, False),
                         ["10.0.0.1", "10.0.0.2"], [80],
                         types.SimpleNamespace(shuffle=False), [80])
        self.assertEqual(report.skipped, [])
        self.assertNotIn("10.0.0.1", report.hosts)
        self.assertEqual(sweep.lost, [("10.0.0.1", 80)])

    def test_lost_probes_fail_the_run_instead_of_reading_as_clean(self):
        with Listener() as listener, tempfile.TemporaryDirectory() as td:
            report = Path(td) / "r.json"
            with mock.patch.object(ts, "PROBE_BACKOFF", 0.01), \
                    mock.patch.object(ts.socket, "socket",
                                      side_effect=OSError(errno.EMFILE, "Too many open files")):
                code, out, err = run_main("127.0.0.1", "-p", str(listener.port),
                                          "--json", str(report))
            self.assertEqual(code, ts.EXIT_PROXY)
            self.assertEqual(out, "")
            self.assertIn("could not be sent", err)
            self.assertEqual(json.loads(report.read_text())["probes_lost"], 1)


# ── Scope ─────────────────────────────────────────────────────────────

class TestDiscoveryScope(unittest.TestCase):
    """-p names what may be probed; the liveness pass may only choose among it."""

    def test_default_discovery_never_leaves_the_requested_ports(self):
        self.assertEqual(ts.default_discovery([445]), [445])
        self.assertEqual(ts.default_discovery([22, 80, 8000]), [80, 22])
        many = list(range(9000, 9020))
        self.assertEqual(ts.default_discovery(many), many[:6])

    def test_the_default_port_list_keeps_the_full_discovery_set(self):
        self.assertEqual(ts.default_discovery(sorted(ts.TOP_PORTS[:20])),
                         list(ts.DEFAULT_DISCOVER_PORTS))

    def test_main_hands_discovery_only_what_was_asked_for(self):
        seen = []
        with mock.patch.object(ts, "sweep_all",
                               lambda *args: seen.append(args[-1])):
            run_main("127.0.0.1-2", "-p", "445", "-q")
            run_main("127.0.0.1-2", "-p", "445", "--discover-ports", "22,80", "-q")
            run_main("127.0.0.1-2", "-p", "445", "--no-discover", "-q")
        # The default follows -p; a list the operator names is theirs to name;
        # and --no-discover means none.
        self.assertEqual(seen, [[445], [22, 80], []])

    def run_all(self, hosts, ports, discover):
        prober = ScriptedProber(lambda task, n: ts.CLOSED)
        sweep = make_sweep(prober, canary_after=10_000)
        ts.sweep_all(sweep, ts.Report(), Sink(), ts.Progress(0, False), hosts,
                     ports, types.SimpleNamespace(shuffle=False), discover)
        return prober

    def test_one_port_costs_one_probe_per_host(self):
        hosts = [f"10.0.0.{i}" for i in range(1, 6)]
        prober = self.run_all(hosts, [445], ts.default_discovery([445]))
        self.assertEqual(len(prober.calls), 5)
        self.assertEqual({port for _, port in prober.calls}, {445})

    def test_no_pair_is_probed_twice(self):
        """Discovery results are real results; sweeping them again would be
        redundant traffic through the chain."""
        prober = self.run_all(["10.0.0.1", "10.0.0.2"], [80, 443], [80])
        self.assertEqual(len(prober.calls), 4)
        self.assertEqual(len(set(prober.calls)), 4)


# ── Small hardening ───────────────────────────────────────────────────

class TestWritePrivate(unittest.TestCase):
    """--json must never replace something that is not a plain file, and must
    never follow a link somewhere it was not pointed. As root, the atomic rename
    swapped /dev/null for a regular file, and 'all tests passed' because nothing
    checked. These tests stay in temp directories; the one that names /dev
    mocks the write."""

    def test_a_plain_file_is_replaced_and_made_private(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            path.write_text("old")
            path.chmod(0o644)
            ts.write_private(str(path), "new")
            self.assertEqual(path.read_text(), "new")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_a_symlink_to_a_file_is_replaced_not_followed(self):
        """A link planted where the report goes must not make the tool overwrite
        whatever it points at (following it truncated the victim, kept its mode,
        and was not atomic)."""
        with tempfile.TemporaryDirectory() as td:
            victim, link = Path(td) / "victim.txt", Path(td) / "scan.json"
            victim.write_text("precious")
            victim.chmod(0o644)
            link.symlink_to(victim)
            ts.write_private(str(link), "{}")
            self.assertEqual(victim.read_text(), "precious")
            self.assertFalse(link.is_symlink())
            self.assertEqual(link.read_text(), "{}")
            self.assertEqual(link.stat().st_mode & 0o777, 0o600)

    def test_a_dangling_symlink_is_replaced_too(self):
        with tempfile.TemporaryDirectory() as td:
            gone, link = Path(td) / "gone.json", Path(td) / "scan.json"
            link.symlink_to(gone)
            ts.write_private(str(link), "{}")
            self.assertFalse(gone.exists())
            self.assertEqual(link.read_text(), "{}")

    def open_reader(self, fifo):
        """A reader that exists the moment this returns. The tool opens a fifo
        non-blocking, so one that is merely about to open would be too late."""
        return os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)

    def drain(self, descriptor):
        try:
            return os.read(descriptor, 4096).decode()
        finally:
            os.close(descriptor)

    def test_a_fifo_is_written_to_not_replaced(self):
        with tempfile.TemporaryDirectory() as td:
            fifo = Path(td) / "pipe"
            os.mkfifo(fifo)
            reader = self.open_reader(fifo)
            ts.write_private(str(fifo), "{}")
            self.assertEqual(self.drain(reader), "{}")
            self.assertTrue(stat.S_ISFIFO(os.stat(fifo).st_mode))

    def test_a_symlink_to_a_fifo_is_written_into(self):
        with tempfile.TemporaryDirectory() as td:
            fifo, link = Path(td) / "pipe", Path(td) / "scan.json"
            os.mkfifo(fifo)
            link.symlink_to(fifo)
            reader = self.open_reader(fifo)
            ts.write_private(str(link), "{}")
            self.assertEqual(self.drain(reader), "{}")
            self.assertTrue(link.is_symlink())

    def test_a_fifo_nobody_reads_fails_at_once_instead_of_hanging(self):
        with tempfile.TemporaryDirectory() as td:
            fifo = Path(td) / "pipe"
            os.mkfifo(fifo)
            outcome = []

            def write():
                try:
                    ts.write_private(str(fifo), "{}")
                    outcome.append("wrote")
                except OSError as exc:
                    outcome.append(exc.errno)

            worker = threading.Thread(target=write, daemon=True)
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive(), "blocked waiting for a reader")
            self.assertEqual(outcome, [errno.ENXIO])

    def test_nothing_directly_under_dev_is_ever_replaced(self):
        """As root, replacing /dev/stdout or /dev/null breaks it for every
        process on the box. The write is mocked: the paths are only named."""
        with mock.patch.object(ts, "_write_through") as through, \
                mock.patch.object(ts.tempfile, "mkstemp",
                                  side_effect=AssertionError("temp file in /dev")):
            for path in ("/dev/stdout", "/dev/null", "/dev/tcpsweep-example"):
                ts.write_private(path, "{}")
        self.assertEqual(through.call_count, 3)


class TestReportPathCheck(unittest.TestCase):
    def test_an_unwritable_path_fails_before_any_probe(self):
        with mock.patch.object(ts, "sweep_all",
                               side_effect=AssertionError("scanned anyway")):
            code, out, err = run_main("127.0.0.1", "-p", "80", "-q",
                                      "--json", "/no/such/dir/report.json")
        self.assertEqual(code, ts.EXIT_USAGE)
        self.assertEqual(out, "")
        self.assertIn("cannot write --json", err)

    def test_a_writable_path_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            ts.check_report_path(str(Path(td) / "new.json"), "--json")


class TestFitConcurrency(unittest.TestCase):
    HELD = 10

    def fake_resource(self, soft, hard, raised):
        module = types.ModuleType("resource")
        module.RLIMIT_NOFILE = 7
        module.RLIM_INFINITY = -1
        module.getrlimit = lambda which: (soft, hard)
        module.setrlimit = lambda which, limits: raised.append(limits)
        return module

    def fit(self, requested, soft, hard, per_probe=1):
        raised, buf = [], io.StringIO()
        with mock.patch.dict(sys.modules,
                             {"resource": self.fake_resource(soft, hard, raised)}), \
                mock.patch.object(ts, "open_fd_count", lambda: self.HELD), \
                mock.patch.object(sys, "stderr", buf):
            return ts.fit_concurrency(requested, per_probe), raised, buf.getvalue()

    def test_enough_headroom_changes_nothing(self):
        self.assertEqual(self.fit(16, 1024, 4096), (16, [], ""))

    def test_the_soft_limit_is_raised_when_the_hard_limit_allows(self):
        fitted, raised, warning = self.fit(500, 256, 4096)
        self.assertEqual(fitted, 500)
        self.assertEqual(raised, [(self.HELD + ts.FD_RESERVE + 500, 4096)])
        self.assertEqual(warning, "")

    def test_it_clamps_and_says_so_when_the_limit_cannot_move(self):
        fitted, _, warning = self.fit(500, 300, 300)
        self.assertEqual(fitted, 300 - self.HELD - ts.FD_RESERVE)
        self.assertIn(f"using -c {fitted}", warning)

    def test_it_never_returns_less_than_one_worker(self):
        self.assertEqual(self.fit(50, 40, 40)[0], 1)

    def test_an_unlimited_limit_is_left_alone(self):
        self.assertEqual(self.fit(9999, -1, -1), (9999, [], ""))

    def test_a_platform_without_rlimits_is_fine(self):
        with mock.patch.dict(sys.modules, {"resource": None}):
            self.assertEqual(ts.fit_concurrency(99), 99)

    def test_a_proxied_probe_needs_two_descriptors(self):
        """proxychains dials the chain on a second socket and dup2s it over the
        first. Budgeting one per probe let -c 800 through a limit of 1024, and
        the hook's failing socket() came back as an instant 'closed' -- ten of
        them journalled and vouched in the run that found this."""
        fitted, raised, _ = self.fit(500, 1024, 4096, per_probe=2)
        self.assertEqual(fitted, 500)
        self.assertEqual(raised, [(self.HELD + ts.FD_RESERVE + 1000, 4096)])
        fitted, _, warning = self.fit(600, 1024, 1024, per_probe=2)
        self.assertEqual(fitted, (1024 - self.HELD - ts.FD_RESERVE) // 2)
        self.assertIn("2 per probe", warning)

    def test_the_descriptors_already_open_are_counted(self):
        self.assertGreaterEqual(ts.open_fd_count(), 3)

    def test_main_budgets_two_descriptors_only_under_a_proxy(self):
        seen = []

        def fake(requested, per_probe=1):
            seen.append(per_probe)
            return requested

        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(ts, "fit_concurrency", fake), \
                mock.patch.object(ts, "sweep_all", lambda *a: None):
            run_main("127.0.0.1", "-p", "80", "-q", "--no-sanity",
                     env=fake_proxy_env(td))
            run_main("127.0.0.1", "-p", "80", "-q")
        self.assertEqual(seen, [ts.FD_PER_PROBE_PROXIED, 1])


class TestDnsPlaceholderSubnet(unittest.TestCase):
    def proxy(self, text):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pc.conf"
            path.write_text(text)
            proxy = ts.Proxy()
            proxy.active = True
            proxy._parse(str(path))
            return proxy

    def test_a_moved_subnet_is_recognised(self):
        proxy = self.proxy("proxy_dns\nremote_dns_subnet 10\n")
        self.assertEqual(proxy.dns_subnet, 10)
        self.assertTrue(proxy.is_dns_placeholder("10.0.0.5"))
        self.assertFalse(proxy.is_dns_placeholder("192.168.1.1"))

    def test_loopback_subnet_is_recognised(self):
        proxy = self.proxy("proxy_dns\nremote_dns_subnet 127\n")
        self.assertTrue(proxy.is_dns_placeholder("127.0.0.9"))

    def test_the_subnet_means_nothing_without_proxy_dns(self):
        proxy = self.proxy("remote_dns_subnet 10\n")
        self.assertFalse(proxy.is_dns_placeholder("10.0.0.5"))

    def test_the_default_multicast_placeholder_still_gives_itself_away(self):
        self.assertTrue(self.proxy("proxy_dns\n").is_dns_placeholder("224.0.0.1"))

    def test_resolve_warns_about_a_moved_subnet(self):
        proxy = self.proxy("proxy_dns\nremote_dns_subnet 10\n")
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))]
        buf = io.StringIO()
        with mock.patch.object(socket, "getaddrinfo", return_value=fake), \
                mock.patch.object(sys, "stderr", buf):
            self.assertEqual(ts.resolve("example.com", proxy), ["10.0.0.1"])
        self.assertIn("placeholder", buf.getvalue())


# ── End to end ────────────────────────────────────────────────────────

class TestCommandLine(unittest.TestCase):
    def run_tool(self, *args, **kwargs):
        return subprocess.run([sys.executable, str(HERE / "tcpsweep.py"), *args],
                              capture_output=True, text=True, timeout=120,
                              **kwargs)

    def test_open_port_streams_to_stdout_and_exits_zero(self):
        with Listener() as listener:
            done = self.run_tool("127.0.0.1", "-p", str(listener.port),
                                 "-w", "2", "-q")
            self.assertEqual(done.returncode, ts.EXIT_FOUND)
            self.assertEqual(done.stdout.strip(),
                             f"127.0.0.1 {listener.port}")

    def test_nothing_open_exits_one(self):
        done = self.run_tool("127.0.0.1", "-p", str(free_port()), "-w", "2", "-q")
        self.assertEqual(done.returncode, ts.EXIT_NONE)
        self.assertEqual(done.stdout.strip(), "")

    def test_no_targets_is_a_usage_error(self):
        self.assertEqual(self.run_tool().returncode, ts.EXIT_USAGE)

    def test_zero_timeout_warns_and_falls_back(self):
        # settimeout(0) is non-blocking mode, not "no timeout": it reports
        # every port, live listeners included, as unreachable. Existing command
        # lines pass -w 0, so degrade loudly instead of breaking them.
        with Listener() as listener:
            done = self.run_tool("127.0.0.1", str(listener.port), "-w", "0")
            self.assertEqual(done.returncode, ts.EXIT_FOUND)
            self.assertIn("not 'no timeout'", done.stderr)
            self.assertEqual(done.stdout.strip(), f"127.0.0.1 {listener.port}")

    def test_negative_timeout_is_rejected(self):
        done = self.run_tool("127.0.0.1", "-p", "80", "-w", "-1")
        self.assertEqual(done.returncode, ts.EXIT_USAGE)
        self.assertIn("cannot be negative", done.stderr)

    def test_positional_ports_still_work(self):
        with Listener() as listener:
            done = self.run_tool("127.0.0.1", str(listener.port), "-w", "2", "-q")
            self.assertEqual(done.returncode, ts.EXIT_FOUND)
            self.assertEqual(done.stdout.strip(), f"127.0.0.1 {listener.port}")

    def test_legacy_thread_and_random_flags_are_aliases(self):
        with Listener() as listener:
            done = self.run_tool("127.0.0.1", str(listener.port), "-w", "2",
                                 "-t", "4", "-r", "-q")
            self.assertEqual(done.returncode, ts.EXIT_FOUND)

    def test_json_output_is_written_and_private(self):
        with Listener() as listener, tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.json"
            self.run_tool("127.0.0.1", "-p", str(listener.port), "-w", "2",
                          "-q", "--json", str(out))
            payload = json.loads(out.read_text())
            self.assertEqual(payload["hosts"][0]["ports"][0]["state"], ts.OPEN)
            self.assertFalse(payload["proxied"])
            self.assertEqual(payload["chain_sanity"], "skipped")   # direct: nothing to check
            self.assertEqual(payload["probes_lost"], 0)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_targets_from_stdin(self):
        with Listener() as listener:
            done = self.run_tool("-iL", "-", "-p", str(listener.port), "-w", "2",
                                 "-q", input="127.0.0.1\n")
            self.assertEqual(done.returncode, ts.EXIT_FOUND)

    def test_a_vanished_reader_does_not_change_the_exit_status(self):
        """An ssh drop closes both pipes. The run must still finish, write its
        report and exit with the code it earned: Python turns a failed flush at
        exit into status 120, and a failed write leaves its data in the buffer
        to fail again."""
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "r.json"
            proc = subprocess.Popen(
                [sys.executable, str(HERE / "tcpsweep.py"), "127.0.0.1",
                 "-p", "20-40", "--rate", "20", "--json", str(report)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.3)
            proc.stdout.close()
            proc.stderr.close()
            code = proc.wait(timeout=60)
            self.assertIn(code, (ts.EXIT_FOUND, ts.EXIT_NONE))
            self.assertTrue(report.exists())

    def test_runs_from_stdin_as_python_dash(self):
        """``ssh pivot python3 - ARGS < tcpsweep.py`` -- the README's way of
        scanning from the far end of a tunnel."""
        with Listener() as listener:
            done = subprocess.run(
                [sys.executable, "-", "127.0.0.1", str(listener.port),
                 "-w", "2", "-q"],
                input=(HERE / "tcpsweep.py").read_text(),
                capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, ts.EXIT_FOUND)
        self.assertEqual(done.stdout.strip(), f"127.0.0.1 {listener.port}")

    def test_help_names_the_tool_when_run_from_stdin(self):
        done = subprocess.run([sys.executable, "-", "--help"],
                              input=(HERE / "tcpsweep.py").read_text(),
                              capture_output=True, text=True, timeout=60)
        self.assertIn("usage: tcpsweep", done.stdout)

    def test_ct_alias_is_accepted(self):
        with Listener() as listener:
            done = self.run_tool("127.0.0.1", "-p", str(listener.port), "-w", "2",
                                 "--ct", f"127.0.0.1:{listener.port}", "-q")
            self.assertEqual(done.returncode, ts.EXIT_FOUND)

    def test_dead_control_target_fails_before_the_sweep_starts(self):
        done = self.run_tool("127.0.0.1", "-p", "1-40", "-w", "1",
                             "--ct", f"127.0.0.1:{free_port()}")
        self.assertEqual(done.returncode, ts.EXIT_USAGE)
        self.assertIn("did not answer open", done.stderr)
        self.assertEqual(done.stdout.strip(), "")

    def test_resume_skips_what_the_journal_already_holds(self):
        with Listener() as listener, tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "j.jsonl")
            port = str(listener.port)
            first = self.run_tool("127.0.0.1", port, "-w", "2", "-q",
                                  "--resume", path)
            self.assertEqual(first.returncode, ts.EXIT_FOUND)

            second = self.run_tool("127.0.0.1", port, "-w", "2", "--resume",
                                   path, "--json", str(Path(td) / "r.json"))
            self.assertEqual(second.returncode, ts.EXIT_FOUND)
            self.assertIn("resumed 1 probe(s)", second.stderr)
            # stdout stays complete on a resumed run, so pipelines still work.
            self.assertEqual(second.stdout.strip(), f"127.0.0.1 {port}")

    def test_resume_is_never_automatic(self):
        """No default path and no auto-discovery: the replay bug in 0.1.x came
        from resuming a state file nobody asked for."""
        with Listener() as listener:
            done = self.run_tool("127.0.0.1", str(listener.port), "-w", "2", "-q")
            self.assertEqual(done.returncode, ts.EXIT_FOUND)
            self.assertNotIn("resumed", done.stderr)

    def test_help_mentions_the_proxy_contract(self):
        done = self.run_tool("--help")
        self.assertIn("proxychains", done.stdout)
        self.assertIn("tcp_read_time_out", done.stdout)


if __name__ == "__main__":
    unittest.main()
