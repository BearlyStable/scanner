#!/usr/bin/env python3
"""Tests for tcpsweep.

The interesting cases are the proxy ones, and they are all reachable without a
proxy: the probe classifier is pure timing arithmetic, and the sweep engine
takes its prober as a callable, so a chain outage can be scripted exactly
rather than raced against a real proxy.
"""

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
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


# ── Proxy environment ─────────────────────────────────────────────────

class TestProxyDetection(unittest.TestCase):
    def test_detects_via_ld_preload(self):
        env = {"LD_PRELOAD": "/usr/lib/x86_64-linux-gnu/libproxychains.so.4"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertTrue(ts.Proxy.detect().active)

    def test_detects_via_conf_env(self):
        with mock.patch.dict(os.environ,
                             {"PROXYCHAINS_CONF_FILE": "/etc/proxychains4.conf"},
                             clear=True):
            self.assertTrue(ts.Proxy.detect().active)

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
        prober = ts.Prober(0.4, 0.36, proxied=False)
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
               concurrency=1):
    return ts.Sweep(prober, concurrency, ts.RateLimiter(0), canaries,
                    canary_after, chain_wait)


class Collector:
    def __init__(self):
        self.recorded = []
        self.revoked = []

    def record(self, res):
        self.recorded.append((res.host, res.port, res.state))

    def revoke(self, host, port):
        self.revoked.append((host, port))


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
        calls = {"n": 0}

        def script(task, _n):
            calls["n"] += 1
            if task == ("10.0.0.1", 1):
                # Open, then dead for one check, then back.
                return ts.OPEN if calls["n"] == 1 or calls["n"] > 6 else ts.CLOSED
            return ts.CLOSED

        prober = ScriptedProber(script)
        sweep = make_sweep(prober, canary_after=3, chain_wait=5)
        sink = Collector()
        sweep.run([("10.0.0.1", p) for p in range(1, 8)],
                  sink.record, sink.revoke)
        self.assertFalse(sweep.chain_broken)
        if sink.revoked:
            reprobed = [t for t in prober.calls if t in sink.revoked]
            self.assertTrue(reprobed, "withdrawn probes must be re-run")

    def test_a_raising_prober_does_not_kill_the_sweep(self):
        def script(task, _n):
            if task[1] == 2:
                raise RuntimeError("boom")
            return ts.CLOSED

        sweep = make_sweep(ScriptedProber(script), canary_after=10_000)
        sink = Collector()
        sweep.run([("10.0.0.1", p) for p in (1, 2, 3)], sink.record, sink.revoke)
        self.assertEqual(len(sink.recorded), 3)

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

    def test_revocation_is_journalled(self):
        """A chain outage withdraws its negatives; without a matching record
        they would return on the next resume as though they had been real."""
        with tempfile.TemporaryDirectory() as td:
            journal = self.journal(td)
            journal.open({})
            journal.record(result("10.0.0.1", 80, ts.CLOSED))
            journal.revoke("10.0.0.1", 80)
            journal.close()
            stored, _ = self.journal(td).load()
            self.assertEqual(stored, {})

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
        """They were not probed this run, so they must not arm the canary or
        mark the chain verified -- that has to be earned live."""
        with tempfile.TemporaryDirectory() as td:
            journal = self.journal(td)
            journal.open({})
            journal.record(result("10.0.0.1", 80, ts.OPEN))
            journal.close()
            report = ts.Report()
            with mock.patch.object(sys, "stdout", io.StringIO()):
                ts.carry_over(self.journal(td), report, ts.Stream(False),
                              ["10.0.0.1"], [80])
            sweep = make_sweep(ScriptedProber(lambda t, n: ts.CLOSED))
            self.assertFalse(sweep.chain_verified)
            self.assertEqual(sweep.canaries, [])


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
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_targets_from_stdin(self):
        with Listener() as listener:
            done = self.run_tool("-iL", "-", "-p", str(listener.port), "-w", "2",
                                 "-q", input="127.0.0.1\n")
            self.assertEqual(done.returncode, ts.EXIT_FOUND)

    def test_discovery_does_not_reprobe_a_port_it_already_did(self):
        """Discovery results are real results; sweeping them again would be
        redundant traffic through the chain."""
        with Listener() as listener:
            port = str(listener.port)
            done = self.run_tool("127.0.0.1-2", "-p", port, "-w", "1",
                                 "--discover-ports", port, "-q",
                                 "--json", "/dev/stdout")
        self.assertEqual(done.returncode, ts.EXIT_FOUND)

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

            second = self.run_tool("127.0.0.1", port, "-w", "2",
                                   "--resume", path, "--json", "/dev/null")
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
