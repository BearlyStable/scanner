#!/usr/bin/env python3
"""Tests for scan.py (netcat-style TCP sweep)."""

import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import tcpsweep as scan


# ── IP / port / gap parsing ────────────────────────────────────────────

class TestSplitBraces(unittest.TestCase):
    def test_no_braces(self):
        self.assertEqual(scan._split_respecting_braces("a,b,c"), ["a", "b", "c"])

    def test_single_brace(self):
        self.assertEqual(scan._split_respecting_braces("192.168.1.{1-5,254}"),
                         ["192.168.1.{1-5,254}"])

    def test_brace_plus_plain(self):
        self.assertEqual(scan._split_respecting_braces("192.168.1.{1,2},10.0.0.1"),
                         ["192.168.1.{1,2}", "10.0.0.1"])

    def test_nested_braces(self):
        self.assertEqual(scan._split_respecting_braces("a{b{c},d},e"),
                         ["a{b{c},d}", "e"])

    def test_empty_input(self):
        self.assertEqual(scan._split_respecting_braces(""), [""])

    def test_single_item(self):
        self.assertEqual(scan._split_respecting_braces("10.0.0.1"), ["10.0.0.1"])

    def test_comma_only(self):
        self.assertEqual(scan._split_respecting_braces(","), ["", ""])


class TestBraceExpand(unittest.TestCase):
    def test_single_value(self):
        self.assertEqual(scan._brace_expand("10.0.0.{1}"), ["10.0.0.1"])

    def test_multiple_values(self):
        self.assertEqual(scan._brace_expand("10.0.0.{1,2,3}"),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_range(self):
        self.assertEqual(scan._brace_expand("192.168.1.{1-3}"),
                         ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_mixed_range_and_single(self):
        self.assertEqual(scan._brace_expand("10.0.0.{1-2,5,10}"),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.10"])

    def test_suffix(self):
        self.assertEqual(scan._brace_expand("10.0.{1-2}.1"),
                         ["10.0.1.1", "10.0.2.1"])

    def test_spaces_ignored(self):
        self.assertEqual(scan._brace_expand("10.0.0.{ 1 , 2 }"),
                         ["10.0.0.1", "10.0.0.2"])


class TestExpandIps(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(scan.expand_ips("192.168.1.1"), ["192.168.1.1"])

    def test_cidr_large(self):
        result = scan.expand_ips("192.168.1.0/24")
        self.assertEqual(len(result), 254)
        self.assertIn("192.168.1.1", result)
        self.assertNotIn("192.168.1.0", result)
        self.assertNotIn("192.168.1.255", result)

    def test_cidr_small(self):
        result = scan.expand_ips("192.168.1.0/29")
        self.assertEqual(len(result), 6)
        self.assertEqual(result[0], "192.168.1.1")

    def test_cidr_31(self):
        self.assertEqual(len(scan.expand_ips("192.168.1.0/31")), 2)

    def test_comma_separated(self):
        self.assertEqual(scan.expand_ips("10.0.0.1,10.0.0.2,10.0.0.3"),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_dash_range(self):
        self.assertEqual(scan.expand_ips("192.168.1.1-5"),
                         ["192.168.1.1", "192.168.1.2", "192.168.1.3",
                          "192.168.1.4", "192.168.1.5"])

    def test_brace_notation(self):
        self.assertEqual(scan.expand_ips("192.168.1.{1-3}"),
                         ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_brace_with_commas(self):
        self.assertEqual(scan.expand_ips("10.0.0.{1,5,10}"),
                         ["10.0.0.1", "10.0.0.5", "10.0.0.10"])

    def test_sorted_order(self):
        self.assertEqual(scan.expand_ips("10.0.0.{1,5,3}"),
                         ["10.0.0.1", "10.0.0.3", "10.0.0.5"])

    def test_duplicate_removal(self):
        self.assertEqual(scan.expand_ips("10.0.0.1,10.0.0.1"), ["10.0.0.1"])

    def test_cidr_30(self):
        self.assertEqual(scan.expand_ips("10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])

    def test_invalid_ip_exits(self):
        with self.assertRaises(SystemExit):
            scan.expand_ips("999.999.999.999")


class TestExpandIpsInvalid(unittest.TestCase):
    """Ranges that would produce invalid octets exit cleanly, not crash."""

    def test_dash_range_out_of_bounds(self):
        with self.assertRaises(SystemExit):
            scan.expand_ips("192.168.1.250-260")

    def test_brace_range_out_of_bounds(self):
        with self.assertRaises(SystemExit):
            scan.expand_ips("192.168.1.{250-260}")

    def test_reversed_range(self):
        with self.assertRaises(SystemExit):
            scan.expand_ips("10.0.0.10-5")

    def test_non_numeric_brace_token(self):
        with self.assertRaises(SystemExit):
            scan.expand_ips("10.0.0.{a}")

    def test_invalid_cidr(self):
        with self.assertRaises(SystemExit):
            scan.expand_ips("10.0.0.0/40")


class TestParseGap(unittest.TestCase):
    def test_single_value(self):
        self.assertEqual(scan.parse_gap("4"), (4.0, 4.0))

    def test_range(self):
        self.assertEqual(scan.parse_gap("4,9"), (4.0, 9.0))

    def test_floats(self):
        self.assertEqual(scan.parse_gap("0.5,1.5"), (0.5, 1.5))

    def test_spaces_stripped(self):
        self.assertEqual(scan.parse_gap("4 , 9"), (4.0, 9.0))

    def test_zero(self):
        self.assertEqual(scan.parse_gap("0"), (0.0, 0.0))

    def test_invalid_exits(self):
        with self.assertRaises(SystemExit):
            scan.parse_gap("abc")


class TestParsePorts(unittest.TestCase):
    def test_single(self):
        self.assertEqual(scan.parse_ports(["22", "80", "443"]), [22, 80, 443])

    def test_range_dash(self):
        self.assertEqual(scan.parse_ports(["22-25"]), [22, 23, 24, 25])

    def test_range_colon(self):
        self.assertEqual(scan.parse_ports(["22:24"]), [22, 23, 24])

    def test_mixed(self):
        self.assertEqual(scan.parse_ports(["22", "80-82", "443"]),
                         [22, 80, 81, 82, 443])

    def test_empty(self):
        self.assertEqual(scan.parse_ports([]), [])

    def test_dedup(self):
        self.assertEqual(scan.parse_ports(["22", "20-25"]),
                         [20, 21, 22, 23, 24, 25])

    def test_comma_separated(self):
        self.assertEqual(scan.parse_ports(["22,80,443"]), [22, 80, 443])

    def test_non_numeric_exits(self):
        with self.assertRaises(SystemExit):
            scan.parse_ports(["abc"])

    def test_too_large_exits(self):
        with self.assertRaises(SystemExit):
            scan.parse_ports(["99999"])

    def test_zero_exits(self):
        with self.assertRaises(SystemExit):
            scan.parse_ports(["0"])

    def test_range_upper_out_of_bounds_exits(self):
        with self.assertRaises(SystemExit):
            scan.parse_ports(["22-99999"])


# ── Port scanning ──────────────────────────────────────────────────────

class TestScanPort(unittest.TestCase):
    def test_closed_port(self):
        self.assertEqual(scan.scan_port("127.0.0.1", 19999, timeout=1), "closed")

    def test_open_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 19_998))
        s.listen(1)
        try:
            self.assertEqual(scan.scan_port("127.0.0.1", 19_998, timeout=1), "open")
        finally:
            s.close()

    def test_filtered(self):
        result = scan.scan_port("255.255.255.0", 0, timeout=0)
        self.assertIn(result, ("filtered", "closed", "open"))

    def test_status_is_valid(self):
        self.assertIn(scan.scan_port("127.0.0.1", 80, timeout=1),
                      ("open", "closed", "filtered"))

    @unittest.skipUnless(os.path.isdir("/proc/self/fd"), "needs /proc")
    def test_no_fd_leak(self):
        """Scanning many closed ports must not leak sockets."""
        before = len(os.listdir("/proc/self/fd"))
        for p in range(20000, 20200):
            scan.scan_port("127.0.0.1", p, timeout=1)
        after = len(os.listdir("/proc/self/fd"))
        self.assertLessEqual(after - before, 5)


class TestBanner(unittest.TestCase):
    def test_open_no_banner(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 19_995))
        srv.listen(1)
        try:
            status, banner = scan.probe_banner("127.0.0.1", 19_995, timeout=1)
            self.assertEqual(status, "open")
            self.assertIsNone(banner)
        finally:
            srv.close()

    def test_closed(self):
        status, banner = scan.probe_banner("127.0.0.1", 19_999, timeout=1)
        self.assertEqual(status, "closed")
        self.assertIsNone(banner)


# ── State persistence ──────────────────────────────────────────────────

class TestStatePersistence(unittest.TestCase):
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "testname")
            state = {
                "ips": ["10.0.0.1"], "ports": [22, 80],
                "results": {"10.0.0.1": {"22": "open"}},
                "pending": [["10.0.0.1", 80]], "interrupted": False,
                "start_time": 1000, "end_time": None, "random_order": False,
            }
            scan.save_state(state, name)
            loaded = scan.load_state(name)
            self.assertEqual(loaded["ips"], ["10.0.0.1"])
            self.assertEqual(loaded["results"]["10.0.0.1"]["22"], "open")
            self.assertEqual(loaded["pending"], [["10.0.0.1", 80]])

    def test_load_missing_file(self):
        self.assertIsNone(scan.load_state("/tmp/does_not_exist_12345"))

    def test_state_path_suffix(self):
        self.assertEqual(scan._state_path("myname").name, "myname.state.json")


# ── Output files ───────────────────────────────────────────────────────

class TestOutputFiles(unittest.TestCase):
    def test_json_multiple_hosts(self):
        results = {"10.0.0.1": {"22": "open"}, "10.0.0.2": {"22": "closed"}}
        with tempfile.TemporaryDirectory() as td:
            base = str(Path(td) / "out")
            scan.write_json_output(base, results)
            data = json.load(open(f"{base}.json"))
            self.assertIn("10.0.0.2", data)

    def test_json_ips_version_sorted(self):
        results = {
            "10.0.0.10": {"22": "open"}, "10.0.0.2": {"22": "closed"},
            "10.0.0.1": {"22": "closed"}, "10.0.0.20": {"22": "open"},
            "10.0.0.3": {"22": "filtered"},
        }
        with tempfile.TemporaryDirectory() as td:
            base = str(Path(td) / "out")
            scan.write_json_output(base, results)
            keys = list(json.load(open(f"{base}.json")).keys())
            self.assertEqual(keys, ["10.0.0.1", "10.0.0.2", "10.0.0.3",
                                    "10.0.0.10", "10.0.0.20"])

    def test_grepable_ips_version_sorted(self):
        results = {"10.0.0.10": {"22": "open"}, "10.0.0.2": {"22": "closed"},
                   "10.0.0.1": {"22": "closed"}}
        with tempfile.TemporaryDirectory() as td:
            base = str(Path(td) / "out")
            scan.write_grepable_output(base, results)
            lines = open(f"{base}.gnmap").readlines()
            hosts = [l.split(": ")[1].split(" ")[0] for l in lines]
            self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2", "10.0.0.10"])

    def test_grepable_ports_numeric_sorted(self):
        """Ports must sort numerically, not lexically (regression: 1023<22)."""
        results = {"10.0.0.1": {"1023": "open", "22": "open",
                                "80": "open", "443": "open"}}
        with tempfile.TemporaryDirectory() as td:
            base = str(Path(td) / "out")
            scan.write_grepable_output(base, results)
            line = open(f"{base}.gnmap").read().strip()
            self.assertEqual(line, "Host: 10.0.0.1 [22/open, 80/open, 443/open, 1023/open]")

    def test_json_ports_numeric_sorted(self):
        results = {"10.0.0.1": {1023: "open", 22: "open", 80: "open"}}
        with tempfile.TemporaryDirectory() as td:
            base = str(Path(td) / "out")
            scan.write_json_output(base, results)
            ports = list(json.load(open(f"{base}.json"))["10.0.0.1"].keys())
            self.assertEqual(ports, ["22", "80", "1023"])


# ── Display ────────────────────────────────────────────────────────────

class TestDisplayTime(unittest.TestCase):
    def test_seconds(self):
        self.assertEqual(scan.Display._fmt_time(0), "0s")
        self.assertEqual(scan.Display._fmt_time(59), "59s")

    def test_minutes(self):
        self.assertEqual(scan.Display._fmt_time(60), "1m 0s")
        self.assertEqual(scan.Display._fmt_time(65), "1m 5s")

    def test_hours(self):
        self.assertEqual(scan.Display._fmt_time(3600), "1h 0m")
        self.assertEqual(scan.Display._fmt_time(3661), "1h 1m")


class TestDisplay(unittest.TestCase):
    def test_init(self):
        d = scan.Display(["10.0.0.1"], [22, 80], start_time=0)
        self.assertEqual(d.total, 2)
        self.assertFalse(d.finished)

    def test_record(self):
        d = scan.Display(["10.0.0.1"], [22], start_time=0)
        d.record("10.0.0.1", 22, "open")
        self.assertEqual(d.results["10.0.0.1"][22], "open")

    def test_unrecord(self):
        d = scan.Display(["10.0.0.1"], [22], start_time=0)
        d.record("10.0.0.1", 22, "closed")
        d.unrecord("10.0.0.1", 22)
        self.assertNotIn(22, d.results["10.0.0.1"])

    def test_finish(self):
        d = scan.Display(["10.0.0.1"], [22], start_time=0)
        d.finish()
        self.assertTrue(d.finished)

    def test_fail_streak_default(self):
        self.assertEqual(scan.Display(["10.0.0.1"], [22]).fail_streak, 0)

    def test_sync_state_populates(self):
        d = scan.Display(["10.0.0.1", "10.0.0.2"], [22, 80], start_time=0)
        d._sync_state({"10.0.0.1": {22: "open", 80: "closed"}})
        self.assertEqual(d.results["10.0.0.1"][22], "open")
        self.assertNotIn("10.0.0.2", d.results)

    def test_sync_state_preserves_existing(self):
        d = scan.Display(["10.0.0.1", "10.0.0.2"], [22, 80], start_time=0)
        d.record("10.0.0.1", 22, "open")
        d._sync_state({"10.0.0.2": {22: "open"}})
        self.assertIn("10.0.0.1", d.results)
        self.assertIn("10.0.0.2", d.results)


# ── Task building ──────────────────────────────────────────────────────

class TestBuildTasks(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(scan._build_tasks(["10.0.0.1"], [22, 80], False),
                         [("10.0.0.1", 22), ("10.0.0.1", 80)])

    def test_multiple_hosts(self):
        tasks = scan._build_tasks(["10.0.0.1", "10.0.0.2"], [22], False)
        self.assertEqual(len(tasks), 2)
        self.assertIn(("10.0.0.2", 22), tasks)

    def test_random_is_permutation(self):
        tasks = scan._build_tasks(["10.0.0.1"], [22, 80, 443], True)
        self.assertEqual(set(t[1] for t in tasks), {22, 80, 443})


# ── Scanner ────────────────────────────────────────────────────────────

class TestScannerInit(unittest.TestCase):
    def test_defaults(self):
        s = scan.Scanner(["10.0.0.1"], [22])
        self.assertEqual(s.timeout, 6)
        self.assertFalse(s.random_order)
        self.assertEqual(s.gap_min, 0)
        self.assertEqual(s.output_name, "10.0.0.1")
        self.assertEqual(s.check_fails, 0)

    def test_multi_ip_default_name(self):
        s = scan.Scanner(["10.0.0.1", "10.0.0.2"], [22])
        self.assertEqual(s.output_name, "scan")

    def test_custom_output_name(self):
        self.assertEqual(scan.Scanner(["10.0.0.1"], [22], output_name="office").output_name,
                         "office")

    def test_state_has_keys(self):
        s = scan.Scanner(["10.0.0.1"], [22])
        for key in ("ips", "ports", "results", "pending", "interrupted",
                    "start_time", "end_time", "random_order"):
            self.assertIn(key, s.state)

    def test_random_gap_equal(self):
        self.assertEqual(scan.Scanner._random_gap(5, 5), 5.0)

    def test_random_gap_range(self):
        for _ in range(10):
            v = scan.Scanner._random_gap(1, 10)
            self.assertGreaterEqual(v, 1)
            self.assertLessEqual(v, 10)

    def test_wait_global_zero(self):
        self.assertEqual(scan.Scanner(["10.0.0.1"], [22])._wait_global(), 0.0)

    def test_wait_host_zero(self):
        self.assertEqual(scan.Scanner(["10.0.0.1"], [22])._wait_host("10.0.0.1"), 0.0)

    def test_wait_global_paces(self):
        s = scan.Scanner(["10.0.0.1"], [22], gap_min=2, gap_max=2)
        self.assertEqual(s._wait_global(), 0.0)     # first packet is free
        self.assertGreater(s._wait_global(), 0.0)   # next must wait

    def test_wait_host_paces(self):
        s = scan.Scanner(["10.0.0.1"], [22], hgap_min=1, hgap_max=1)
        self.assertEqual(s._wait_host("10.0.0.1"), 0.0)
        self.assertGreater(s._wait_host("10.0.0.1"), 0.0)


class TestScannerTasks(unittest.TestCase):
    def test_fresh_scan(self):
        s = scan.Scanner(["10.0.0.1"], [22, 80])
        s._init_tasks()
        self.assertEqual(len(s.task_queue), 2)

    def test_skips_done(self):
        s = scan.Scanner(["10.0.0.1"], [22, 80])
        s.state["results"] = {"10.0.0.1": {22: "open"}}
        s._init_tasks()
        self.assertEqual(list(s.task_queue), [("10.0.0.1", 80)])

    def test_random_shuffles(self):
        s = scan.Scanner(["10.0.0.1"], list(range(100)), random_order=True)
        s._init_tasks()
        self.assertNotEqual(list(s.task_queue),
                            [("10.0.0.1", p) for p in range(100)])

    def test_ordered_preserves_input_order(self):
        s = scan.Scanner(["10.0.0.1"], [100, 10, 20])
        s._init_tasks()
        self.assertEqual(list(s.task_queue),
                         [("10.0.0.1", 100), ("10.0.0.1", 10), ("10.0.0.1", 20)])


class TestScannerPersist(unittest.TestCase):
    def test_persist_rebuilds_pending(self):
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "pname")
            s = scan.Scanner(["10.0.0.1"], [22, 80, 443], output_name=name)
            s.state["results"] = {"10.0.0.1": {22: "open"}}
            s._persist()
            state = json.load(open(name + ".state.json"))
            self.assertEqual(len(state["pending"]), 2)

    def test_persist_thread_safe_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "mtpersist")
            s = scan.Scanner(["127.0.0.1"], list(range(19_900, 19_950)),
                             timeout=1, threads=8, output_name=name)
            s.run()
            state = json.load(open(name + ".state.json"))
            self.assertEqual(sum(len(v) for v in state["results"].values()), 50)


class TestScannerLoad(unittest.TestCase):
    def test_load_resumed(self):
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "lname")
            scan.save_state({
                "ips": ["10.0.0.1"], "ports": [22, 80],
                "results": {"10.0.0.1": {"22": "open"}},
                "pending": [], "interrupted": True,
                "start_time": 100, "end_time": None, "random_order": False,
            }, name)
            s = scan.Scanner(["10.0.0.1"], [22, 80], output_name=name)
            s._load()
            self.assertEqual(s.state["results"]["10.0.0.1"][22], "open")

    def test_load_no_state_file(self):
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "no_state_12345")
            s = scan.Scanner(["10.0.0.1"], [22], output_name=name)
            s._load()
            self.assertEqual(s.state["results"], {})

    def _write_state(self, name, **over):
        st = {"ips": ["10.0.0.1"], "ports": [22],
              "results": {"10.0.0.1": {"22": "open"}},
              "pending": [], "interrupted": False,
              "start_time": 100, "end_time": None, "random_order": False}
        st.update(over)
        scan.save_state(st, name)

    def test_completed_scan_is_not_resumed(self):
        """The bug this guards: a finished scan leaves its state file behind,
        and the next run replays "open" for ports it never probed."""
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "done")
            self._write_state(name, interrupted=False, end_time=200)
            s = scan.Scanner(["10.0.0.1"], [22], output_name=name)
            s._load()
            self.assertEqual(s.state["results"], {})
            self.assertTrue(s._stale_state)

    def test_crashed_scan_is_resumed(self):
        """A killed process never sets end_time and never gets to flip
        `interrupted`, so completion must be judged on end_time alone."""
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "crashed")
            self._write_state(name, interrupted=False, end_time=None)
            s = scan.Scanner(["10.0.0.1"], [22], output_name=name)
            s._load()
            self.assertEqual(s.state["results"]["10.0.0.1"][22], "open")
            self.assertFalse(s._stale_state)

    def test_load_survives_non_numeric_port_key(self):
        """Structurally valid JSON can still hold a bad port key; degrade to
        a fresh scan the way load_state() does, don't raise."""
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "badkey")
            self._write_state(name, results={"10.0.0.1": {"http": "open"}})
            s = scan.Scanner(["10.0.0.1"], [22], output_name=name)
            s._load()                      # must not raise
            self.assertEqual(s.state["results"], {})

    def test_load_does_not_force_random_order(self):
        """Flags always come from *this* run's CLI args, not the saved
        state, so a resumed scan can turn --random on or off freely."""
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "lname2")
            scan.save_state({
                "ips": ["10.0.0.1"], "ports": [22],
                "results": {"10.0.0.1": {"22": "open"}},
                "pending": [], "interrupted": True,
                "start_time": 100, "end_time": None, "random_order": True,
            }, name)
            s = scan.Scanner(["10.0.0.1"], [22], output_name=name, random_order=False)
            s._load()
            self.assertFalse(s.random_order)
            s._init_tasks()
            self.assertFalse(s.state["random_order"])


# ── End-to-end scans ───────────────────────────────────────────────────

def _cleanup(prefix):
    for ext in (".json", ".gnmap", ".state.json"):
        Path(prefix + ext).unlink(missing_ok=True)


class TestSingleThreadEndToEnd(unittest.TestCase):
    def test_scan_closed_ports(self):
        name = "/tmp/tst_closed"
        _cleanup(name)
        s = scan.Scanner(["127.0.0.1"], [19_997, 19_998, 19_999],
                         timeout=1, output_name=name)
        s.run()
        self.assertEqual(s.state["results"]["127.0.0.1"][19_997], "closed")
        self.assertEqual(s.state["results"]["127.0.0.1"][19_999], "closed")
        _cleanup(name)

    def test_scan_open_port(self):
        name = "/tmp/tst_open"
        _cleanup(name)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 19_990))
        srv.listen(5)
        try:
            s = scan.Scanner(["127.0.0.1"], [19_990], timeout=2, output_name=name)
            s.run()
            self.assertEqual(s.state["results"]["127.0.0.1"][19_990], "open")
        finally:
            srv.close()
            _cleanup(name)

    def test_files_written(self):
        name = "/tmp/tst_files"
        _cleanup(name)
        scan.Scanner(["127.0.0.1"], [19_999], timeout=1, output_name=name).run()
        for ext in (".json", ".gnmap", ".state.json"):
            self.assertTrue(Path(name + ext).exists())
        _cleanup(name)

    def test_open_port_streamed_to_stdout(self):
        """Open ports are emitted to stdout for piping."""
        name = "/tmp/tst_stream"
        _cleanup(name)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 19_989))
        srv.listen(5)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                s = scan.Scanner(["127.0.0.1"], [19_989], timeout=1, output_name=name)
                s.run()
            self.assertIn("127.0.0.1 19989", buf.getvalue())
        finally:
            srv.close()
            _cleanup(name)


class TestMultiThread(unittest.TestCase):
    def test_basic_multithread(self):
        name = "/tmp/tst_mt"
        _cleanup(name)
        s = scan.Scanner(["127.0.0.1"], [19_991, 19_992, 19_993, 19_994],
                         timeout=1, threads=4, output_name=name)
        s.run()
        self.assertEqual(len(s.state["results"]["127.0.0.1"]), 4)
        _cleanup(name)

    def test_thread_files(self):
        name = "/tmp/tst_mt2"
        _cleanup(name)
        scan.Scanner(["127.0.0.1"], [19_999], timeout=1, threads=2,
                     output_name=name).run()
        self.assertTrue(Path(f"{name}.json").exists())
        _cleanup(name)

    def test_hgap_with_threads(self):
        name = "/tmp/tst_hgap"
        _cleanup(name)
        s = scan.Scanner(["127.0.0.1"], [19_999, 19_998], timeout=1,
                         threads=2, hgap_min=0, hgap_max=0, output_name=name)
        s.run()
        self.assertEqual(len(s.state["results"]["127.0.0.1"]), 2)
        _cleanup(name)


class TestResumeEndToEnd(unittest.TestCase):
    def test_resume_continues(self):
        name = "/tmp/tst_resume"
        _cleanup(name)
        s1 = scan.Scanner(["127.0.0.1"], [19_980, 19_981, 19_982, 19_983],
                          timeout=1, output_name=name)
        s1.state["results"] = {"127.0.0.1": {19_980: "closed"}}
        s1._persist()

        s2 = scan.Scanner(["127.0.0.1"], [19_980, 19_981, 19_982, 19_983],
                          timeout=1, output_name=name)
        s2.run()
        self.assertIn(19_980, s2.state["results"]["127.0.0.1"])
        self.assertIn(19_983, s2.state["results"]["127.0.0.1"])
        _cleanup(name)

    def test_resume_honors_changed_flags(self):
        """A resumed scan can use different threads/timeout/random-order
        than the interrupted run that wrote the state file."""
        name = "/tmp/tst_resume_flags"
        _cleanup(name)
        s1 = scan.Scanner(["127.0.0.1"], [19_970, 19_971, 19_972, 19_973],
                          timeout=1, threads=1, random_order=False, output_name=name)
        s1.state["results"] = {"127.0.0.1": {19_970: "closed"}}
        s1._persist()

        s2 = scan.Scanner(["127.0.0.1"], [19_970, 19_971, 19_972, 19_973],
                          timeout=2, threads=4, random_order=True, output_name=name)
        s2.run()
        self.assertEqual(s2.threads, 4)
        self.assertEqual(s2.timeout, 2)
        self.assertTrue(s2.random_order)
        self.assertEqual(len(s2.state["results"]["127.0.0.1"]), 4)
        _cleanup(name)

    def test_resume_message_announces_new_config(self):
        """Resuming should be visibly reported, including the flags in
        effect for *this* run."""
        name = "/tmp/tst_resume_announce"
        _cleanup(name)
        scan.save_state({
            "ips": ["127.0.0.1"], "ports": [19_960],
            "results": {"127.0.0.1": {"19960": "closed"}},
            "pending": [], "interrupted": True,
            "start_time": time.time(), "end_time": None, "random_order": False,
        }, name)
        r = subprocess.run(
            [sys.executable, "-m", "tcpsweep", "127.0.0.1", "19960",
             "-t", "3", "-w", "1", "-o", name],
            capture_output=True, text=True, cwd=str(Path(__file__).parent),
        )
        self.assertIn("Resuming", r.stderr)
        self.assertIn("threads=3", r.stderr)
        _cleanup(name)


class TestOpenPortsOnlyOutput(unittest.TestCase):
    """The final report and the Ctrl+C report only enumerate open ports."""

    def test_summary_omits_closed_ports(self):
        name = "/tmp/tst_summary_open"
        _cleanup(name)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 19_988))
        srv.listen(5)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                s = scan.Scanner(["127.0.0.1"], [19_988, 19_997], timeout=1,
                                 output_name=name)
                s.run()
            out = buf.getvalue()
            self.assertIn("19988", out)
            self.assertNotIn("19997", out)
        finally:
            srv.close()
            _cleanup(name)

    def test_interrupt_report_lists_open_ports_only(self):
        name = "/tmp/tst_interrupt_open"
        _cleanup(name)
        s = scan.Scanner(["127.0.0.1"], [19_998, 19_999], timeout=1, output_name=name)
        s.state["results"] = {"127.0.0.1": {19_998: "open", 19_999: "closed"}}
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            s._print_interrupt()
        out = buf.getvalue()
        self.assertIn("19998", out)
        self.assertNotIn("19999", out)
        self.assertIn("INTERRUPTED", out)
        _cleanup(name)

    def test_interrupt_report_no_open_ports_yet(self):
        name = "/tmp/tst_interrupt_none"
        _cleanup(name)
        s = scan.Scanner(["127.0.0.1"], [19_999], timeout=1, output_name=name)
        s.state["results"] = {"127.0.0.1": {19_999: "closed"}}
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            s._print_interrupt()
        self.assertIn("no open ports found", buf.getvalue())
        _cleanup(name)


class TestThreadsWithGapConflict(unittest.TestCase):
    def test_threads_and_pgap_conflict(self):
        s = scan.Scanner(["127.0.0.1"], [80], threads=4, gap_min=1, gap_max=1)
        with self.assertRaises(SystemExit):
            s.run()

    def test_threads_with_hgap_allowed(self):
        name = "/tmp/tst_hgap_ok"
        _cleanup(name)
        scan.Scanner(["127.0.0.1"], [19_999], timeout=1, threads=2,
                     hgap_min=0, hgap_max=0, output_name=name).run()
        _cleanup(name)


# ── CLI ────────────────────────────────────────────────────────────────

class TestParser(unittest.TestCase):
    def _parse(self, *args):
        return scan.build_parser().parse_args(list(args))

    def test_basic_pos_ports(self):
        a = self._parse("10.0.0.1", "22", "80")
        self.assertEqual(a.ip, "10.0.0.1")
        self.assertEqual(a.pos_ports, ["22", "80"])

    def test_opt_ports(self):
        self.assertEqual(self._parse("10.0.0.1", "-p", "22", "80").opt_ports,
                         ["22", "80"])

    def test_combined_ports(self):
        a = self._parse("10.0.0.1", "443", "-p", "22", "80")
        self.assertEqual(a.pos_ports, ["443"])
        self.assertEqual(a.opt_ports, ["22", "80"])

    def test_flags(self):
        a = self._parse("10.0.0.1", "22", "-o", "office", "-r",
                        "-t", "4", "-P", "2,5", "-H", "1")
        self.assertTrue(a.random)
        self.assertEqual(a.threads, 4)
        self.assertEqual(a.pgap, "2,5")
        self.assertEqual(a.hgap, "1")
        self.assertEqual(a.output_name, "office")

    def test_timeout(self):
        self.assertEqual(self._parse("10.0.0.1", "22", "--timeout", "3").timeout, 3)

    def test_banner_flag(self):
        self.assertTrue(self._parse("10.0.0.1", "22", "-b").banner)

    def test_banner_default(self):
        self.assertFalse(self._parse("10.0.0.1", "22").banner)

    def test_show_filtered_flag(self):
        self.assertTrue(self._parse("10.0.0.1", "22", "-F").show_filtered)

    def test_show_filtered_default(self):
        self.assertFalse(self._parse("10.0.0.1", "22").show_filtered)

    def test_output_flag(self):
        self.assertEqual(self._parse("10.0.0.1", "22", "-o", "myname").output_name,
                         "myname")

    def test_output_long_flag(self):
        self.assertEqual(self._parse("10.0.0.1", "22", "--output", "myname").output_name,
                         "myname")

    def test_fresh_flag(self):
        self.assertTrue(self._parse("10.0.0.1", "22", "--fresh").fresh)

    def test_check_fails_default_zero(self):
        self.assertEqual(self._parse("10.0.0.1", "22").check_fails, 0)

    def test_check_fails_cli(self):
        self.assertEqual(self._parse("10.0.0.1", "22", "--cf", "10").check_fails, 10)

    def test_check_target_cli(self):
        self.assertEqual(self._parse("10.0.0.1", "22", "--ct", "10.0.0.2:80").check_targets,
                         ["10.0.0.2:80"])

    def test_make_default_name_single_ip(self):
        self.assertEqual(scan._make_default_name("192.168.1.1"), "192.168.1.1")

    def test_make_default_name_cidr(self):
        self.assertEqual(scan._make_default_name("192.168.1.0/24"), "192.168.1.0_24")

    def test_make_default_name_brace(self):
        self.assertEqual(scan._make_default_name("10.0.0.{1-10}"), "10.0.0.1-10.0.0.10")

    def test_make_default_name_dash(self):
        self.assertIn("10.0.0.", scan._make_default_name("10.0.0.1-5"))


class TestDie(unittest.TestCase):
    def test_exits_code_1(self):
        with self.assertRaises(SystemExit) as ctx:
            scan._die("msg")
        self.assertEqual(ctx.exception.code, 1)


class TestCliExit(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "tcpsweep", *args],
                              capture_output=True, text=True,
                              cwd=str(Path(__file__).parent))

    def test_invalid_ip(self):
        r = self._run("999.1.1.1", "22")     # numeric, not a hostname
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Invalid IP", r.stderr)

    def test_no_ports(self):
        r = self._run("127.0.0.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("No ports", r.stderr)

    def test_threads_and_pgap_error(self):
        r = self._run("127.0.0.1", "22", "-t", "4", "-P", "2")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("threads", r.stderr)
        self.assertIn("pgap", r.stderr)

    def test_invalid_check_target(self):
        r = self._run("10.0.0.1", "22", "--ct", "badopt")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Invalid check target", r.stderr)


class TestInterruptSignal(unittest.TestCase):
    def test_sigint_saves_state(self):
        import signal
        name = "/tmp/tst_sig"
        _cleanup(name)
        # Pace with a packet gap so the scan is still running when SIGINT lands.
        proc = subprocess.Popen(
            [sys.executable, "-m", "tcpsweep", "127.0.0.0/29", "-p", "22:1023",
             "--timeout", "5", "-P", "0.01", "-o", name],
            cwd=str(Path(__file__).parent),
        )
        time.sleep(1)
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=10)
        state = scan.load_state(name)
        self.assertIsNotNone(state)
        self.assertGreater(sum(len(v) for v in state["results"].values()), 0)
        self.assertTrue(state["interrupted"])
        _cleanup(name)


# ── Connection health check ────────────────────────────────────────────

class TestConnectionCheck(unittest.TestCase):
    def test_disabled_by_default(self):
        s = scan.Scanner(["10.0.0.1"], [22])
        self.assertEqual(s.check_fails, 0)
        s._on_result("10.0.0.1", 22, "closed")
        self.assertEqual(s.fail_streak, 0)  # no tracking when disabled

    def test_open_resets_streak_and_records_known_open(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_fails=5)
        s._on_result("10.0.0.1", 22, "open")
        self.assertEqual(s.fail_streak, 0)
        self.assertIn(("10.0.0.1", 22), s.known_open)

    def test_closed_increments_streak(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_fails=3)
        s._on_result("10.0.0.1", 22, "closed")
        s._on_result("10.0.0.1", 80, "closed")
        self.assertEqual(s.fail_streak, 2)

    def test_threshold_flags_check(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_fails=2)
        s._on_result("10.0.0.1", 22, "closed")
        self.assertFalse(s._needs_check)
        s._on_result("10.0.0.1", 80, "closed")
        self.assertTrue(s._needs_check)

    def test_since_good_tracked_during_streak(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_fails=10)
        s._on_result("10.0.0.1", 22, "open")
        s._on_result("10.0.0.1", 80, "closed")
        s._on_result("10.0.0.1", 443, "filtered")
        self.assertEqual(len(s.since_good), 2)
        self.assertIn(("10.0.0.1", 80), s.since_good)

    def test_since_good_cleared_after_open(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_fails=10)
        s._on_result("10.0.0.1", 80, "closed")
        s._on_result("10.0.0.1", 443, "closed")
        self.assertEqual(len(s.since_good), 2)
        s._on_result("10.0.0.1", 22, "open")
        self.assertEqual(len(s.since_good), 0)

    def test_pick_target_known_open(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_fails=2)
        s.known_open = [("10.0.0.1", 22)]
        self.assertEqual(s._pick_probe_target(), ("10.0.0.1", 22))

    def test_pick_target_check_targets(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_targets=[("10.0.0.2", 80)])
        self.assertEqual(s._pick_probe_target(), ("10.0.0.2", 80))

    def test_pick_target_none(self):
        self.assertIsNone(scan.Scanner(["10.0.0.1"], [22])._pick_probe_target())

    def test_probe_returns_status(self):
        self.assertEqual(scan.Scanner(["10.0.0.1"], [22], timeout=1)
                         .probe(("127.0.0.1", 19_999)), "closed")

    def test_requeue_since_good(self):
        s = scan.Scanner(["10.0.0.1"], [22, 80, 443], check_fails=2)
        s.state["results"] = {"10.0.0.1": {80: "closed", 443: "closed"}}
        s.since_good = [("10.0.0.1", 80), ("10.0.0.1", 443)]
        s.fail_streak = 2
        n = s._requeue_since_good()
        self.assertEqual(n, 2)
        self.assertNotIn(80, s.state["results"]["10.0.0.1"])
        self.assertNotIn(443, s.state["results"]["10.0.0.1"])
        self.assertIn(("10.0.0.1", 80), s.task_queue)
        self.assertIn(("10.0.0.1", 443), s.task_queue)
        self.assertEqual(s.fail_streak, 0)
        self.assertEqual(len(s.since_good), 0)

    def test_health_check_no_target_resets(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_fails=2)
        s.fail_streak = 5
        s.since_good = [("10.0.0.1", 80)]
        s._run_health_check()  # no target -> just resets, no hang
        self.assertEqual(s.fail_streak, 0)
        self.assertEqual(len(s.since_good), 0)

    def test_health_check_probe_ok_resets(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_fails=2,
                         check_targets=[("10.0.0.1", 22)])
        s.probe = lambda t: "open"
        s.fail_streak = 5
        s.since_good = [("10.0.0.1", 80)]
        s._run_health_check()
        self.assertEqual(s.fail_streak, 0)
        self.assertEqual(len(s.since_good), 0)

    def test_health_check_recovers_and_requeues(self):
        s = scan.Scanner(["10.0.0.1"], [22, 80], check_fails=2,
                         check_targets=[("10.0.0.1", 22)])
        s.state["results"] = {"10.0.0.1": {80: "closed"}}
        s.since_good = [("10.0.0.1", 80)]
        calls = [0]

        def probe(_t):
            calls[0] += 1
            return "closed" if calls[0] == 1 else "open"  # down, then recovered

        s.probe = probe
        s._recovery_delay = 0.01
        s._run_health_check()
        self.assertNotIn(80, s.state["results"].get("10.0.0.1", {}))
        self.assertIn(("10.0.0.1", 80), s.task_queue)

    def test_display_fail_streak_synced(self):
        s = scan.Scanner(["10.0.0.1"], [22], check_fails=5)
        d = scan.Display(["10.0.0.1"], [22])
        s.display = d
        s._on_result("10.0.0.1", 22, "closed")
        self.assertEqual(d.fail_streak, 1)
        s._on_result("10.0.0.1", 80, "open")
        self.assertEqual(d.fail_streak, 0)


# ── Hardening: atomic writes, permissions, sanitisation ────────────────

class TestAtomicWrite(unittest.TestCase):
    def test_writes_content(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.txt"
            scan._atomic_write(p, "hello")
            self.assertEqual(p.read_text(), "hello")

    def test_no_temp_left_behind(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.txt"
            scan._atomic_write(p, "data")
            leftovers = [q.name for q in Path(td).iterdir() if q.name != "f.txt"]
            self.assertEqual(leftovers, [])

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "secret.txt"
            scan._atomic_write(p, "x")
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_output_files_owner_only(self):
        results = {"10.0.0.1": {"22": "open"}}
        with tempfile.TemporaryDirectory() as td:
            base = str(Path(td) / "out")
            scan.write_json_output(base, results)
            scan.write_grepable_output(base, results)
            scan.save_state({"results": results}, base)
            for ext in (".json", ".gnmap", ".state.json"):
                self.assertEqual(os.stat(base + ext).st_mode & 0o777, 0o600,
                                 f"{ext} should be 0600")


class TestCorruptState(unittest.TestCase):
    def test_corrupt_state_loads_as_none(self):
        """A truncated/garbage state file degrades to a fresh scan, not a crash."""
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "bad")
            scan._state_path(name).write_text("{ this is not valid json ")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                self.assertIsNone(scan.load_state(name))

    def test_scanner_resumes_past_corrupt_state(self):
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "bad2")
            scan._state_path(name).write_text("not json")
            s = scan.Scanner(["127.0.0.1"], [19_999], timeout=1, output_name=name)
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                s._load()
            self.assertEqual(s.state["results"], {})


class TestSanitize(unittest.TestCase):
    def test_strips_escape_and_control(self):
        out = scan._sanitize("a\x1b[31mX\x00b")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x00", out)
        self.assertEqual(out, "a.[31mX.b")

    def test_empty_and_none(self):
        self.assertEqual(scan._sanitize(""), "")
        self.assertEqual(scan._sanitize(None), "")

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(scan._sanitize("  ssh  "), "ssh")

    def test_banner_is_sanitised(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 19_987))
        srv.listen(1)

        def serve():
            conn, _ = srv.accept()
            conn.sendall(b"OK\x1b[2Jmalicious")
            conn.close()

        import threading as _t
        th = _t.Thread(target=serve, daemon=True)
        th.start()
        try:
            status, banner = scan.probe_banner("127.0.0.1", 19_987, timeout=2)
            self.assertEqual(status, "open")
            self.assertIsNotNone(banner)
            self.assertNotIn("\x1b", banner)
        finally:
            th.join(timeout=2)
            srv.close()


class TestDisplayCounters(unittest.TestCase):
    def test_record_tracks_done_and_counts(self):
        d = scan.Display(["10.0.0.1"], [22, 80, 443], start_time=0)
        d.record("10.0.0.1", 22, "open")
        d.record("10.0.0.1", 80, "closed")
        self.assertEqual(d.done, 2)
        self.assertEqual(d.counts["open"], 1)
        self.assertEqual(d.counts["closed"], 1)

    def test_unrecord_decrements(self):
        d = scan.Display(["10.0.0.1"], [22, 80], start_time=0)
        d.record("10.0.0.1", 22, "closed")
        d.unrecord("10.0.0.1", 22)
        self.assertEqual(d.done, 0)
        self.assertEqual(d.counts["closed"], 0)

    def test_rerecord_does_not_double_count(self):
        d = scan.Display(["10.0.0.1"], [22], start_time=0)
        d.record("10.0.0.1", 22, "closed")
        d.record("10.0.0.1", 22, "open")   # health-check requeue can re-record
        self.assertEqual(d.done, 1)
        self.assertEqual(d.counts["closed"], 0)
        self.assertEqual(d.counts["open"], 1)

    def test_sync_state_seeds_counters(self):
        d = scan.Display(["10.0.0.1"], [22, 80], start_time=0)
        d._sync_state({"10.0.0.1": {22: "open", 80: "filtered"}})
        self.assertEqual(d.done, 2)
        self.assertEqual(d.counts["filtered"], 1)

    def test_add_open_feeds_recent_panel(self):
        d = scan.Display(["10.0.0.1"], [22], start_time=0)
        d.add_open("10.0.0.1", 22)
        self.assertEqual(len(d._recent), 1)
        self.assertEqual(d._recent[0][0], "10.0.0.1:22")

    def test_set_current_tracks_in_flight_probe(self):
        d = scan.Display(["10.0.0.1"], [22], start_time=0)
        self.assertIsNone(d._current)
        d.set_current("10.0.0.1", 22)
        self.assertEqual(d._current, ("10.0.0.1", 22))

    def test_recent_panel_is_bounded(self):
        d = scan.Display(["10.0.0.1"], list(range(50)), start_time=0)
        for p in range(50):
            d.add_open("10.0.0.1", p)
        self.assertLessEqual(len(d._recent), d._MAX_RECENT)

    def test_fit_truncates_without_breaking_layout(self):
        out = scan.Display._fit("abcdefghij", 5)
        self.assertEqual(len(out), 5)
        self.assertTrue(out.endswith("…"))

    def test_lifecycle_methods_are_callable(self):
        """start()/render()/finish() must be real methods (regression: an
        instance attribute once shadowed start()), and safe to call headless."""
        d = scan.Display(["10.0.0.1"], [22], start_time=0)
        self.assertTrue(callable(d.start))
        self.assertTrue(callable(d.render))
        self.assertTrue(callable(d.finish))
        d.start()          # no-op when stderr is not a TTY; must not raise
        d.render()
        d.finish()
        self.assertTrue(d.finished)


# ── New features: top-ports, hostnames, target files, exclude, rate ────

class TestTopPorts(unittest.TestCase):
    def test_top_ports_returns_frequency_order(self):
        self.assertEqual(scan.top_ports(3), [80, 23, 443])

    def test_top_ports_caps_at_list_length(self):
        self.assertEqual(scan.top_ports(10_000), scan._TOP_PORTS)
        self.assertEqual(len(scan._TOP_PORTS), 100)

    def test_top_ports_zero_exits(self):
        with self.assertRaises(SystemExit):
            scan.top_ports(0)

    def test_top_ports_are_valid_and_unique(self):
        self.assertEqual(len(set(scan._TOP_PORTS)), len(scan._TOP_PORTS))
        self.assertTrue(all(1 <= p <= 65535 for p in scan._TOP_PORTS))


class TestResolve(unittest.TestCase):
    def test_localhost_resolves(self):
        self.assertIn("127.0.0.1", scan.expand_ips("localhost"))

    def test_hostname_dedup_and_ip_mix(self):
        real = socket.getaddrinfo

        def fake(host, *a, **k):
            if host == "example.test":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.9.9.9", 0)),
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.9.9.9", 0))]
            return real(host, *a, **k)

        socket.getaddrinfo = fake
        try:
            self.assertEqual(scan.expand_ips("example.test"), ["10.9.9.9"])
            # a hostname and a literal that collapse to the same set dedup
            out = scan.resolve_targets(["example.test", "10.9.9.9"])
            self.assertEqual(out, ["10.9.9.9"])
        finally:
            socket.getaddrinfo = real

    def test_unresolvable_host_exits(self):
        real = socket.getaddrinfo

        def fake(*a, **k):
            raise socket.gaierror("no such host")

        socket.getaddrinfo = fake
        try:
            with self.assertRaises(SystemExit):
                scan.expand_ips("nonexistent.invalid")
        finally:
            socket.getaddrinfo = real


class TestResolveTargets(unittest.TestCase):
    def test_union_and_sort(self):
        self.assertEqual(scan.resolve_targets(["10.0.0.2", "10.0.0.1"]),
                         ["10.0.0.1", "10.0.0.2"])

    def test_exclude_removes_hosts(self):
        out = scan.resolve_targets(["10.0.0.0/29"], exclude=["10.0.0.1"])
        self.assertNotIn("10.0.0.1", out)
        self.assertIn("10.0.0.2", out)

    def test_exclude_can_empty_the_set(self):
        self.assertEqual(scan.resolve_targets(["10.0.0.1"], exclude=["10.0.0.1"]), [])


class TestTargetFile(unittest.TestCase):
    def test_reads_specs_skipping_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "targets.txt"
            p.write_text("# a comment\n10.0.0.1\n\n10.0.0.2  # inline\n   \n")
            self.assertEqual(scan._read_target_file(str(p)),
                             ["10.0.0.1", "10.0.0.2"])

    def test_missing_file_exits(self):
        with self.assertRaises(SystemExit):
            scan._read_target_file("/tmp/definitely_not_here_98765.txt")

    def test_file_targets_feed_resolve(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.txt"
            p.write_text("10.0.0.0/30\n10.0.0.5\n")
            specs = scan._read_target_file(str(p))
            self.assertEqual(scan.resolve_targets(specs),
                             ["10.0.0.1", "10.0.0.2", "10.0.0.5"])


class TestNewCliFlags(unittest.TestCase):
    def _parse(self, *args):
        return scan.build_parser().parse_args(list(args))

    def test_top_ports_flag(self):
        self.assertEqual(self._parse("10.0.0.1", "--top-ports", "50").top_ports, 50)

    def test_target_file_flag(self):
        self.assertEqual(self._parse("--target-file", "hosts.txt").target_files,
                         ["hosts.txt"])

    def test_target_file_short_flag(self):
        self.assertEqual(self._parse("-iL", "hosts.txt").target_files, ["hosts.txt"])

    def test_exclude_flag_repeatable(self):
        a = self._parse("10.0.0.0/24", "22", "--exclude", "10.0.0.1",
                        "--exclude", "10.0.0.2")
        self.assertEqual(a.exclude, ["10.0.0.1", "10.0.0.2"])

    def test_rate_flag(self):
        self.assertEqual(self._parse("10.0.0.1", "22", "--rate", "50").rate, 50.0)

    def test_ip_optional_when_absent(self):
        a = self._parse("-iL", "hosts.txt")
        self.assertIsNone(a.ip)

    def test_positional_still_splits_ip_and_ports(self):
        a = self._parse("10.0.0.1", "22", "80")
        self.assertEqual(a.ip, "10.0.0.1")
        self.assertEqual(a.pos_ports, ["22", "80"])


class TestNewCliExit(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "tcpsweep", *args],
                              capture_output=True, text=True,
                              cwd=str(Path(__file__).parent))

    def test_no_targets(self):
        r = self._run("-p", "22")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("No targets", r.stderr)

    def test_rate_and_pgap_conflict(self):
        r = self._run("127.0.0.1", "22", "--rate", "10", "-P", "0.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--rate", r.stderr)

    def test_all_excluded_exits(self):
        r = self._run("10.0.0.1", "22", "--exclude", "10.0.0.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("No targets left", r.stderr)

    def test_top_ports_only_scans(self):
        """--top-ports alone (no explicit ports) is a valid port selection."""
        name = "/tmp/tst_topports"
        _cleanup(name)
        r = self._run("127.0.0.1", "--top-ports", "5", "-w", "1", "-o", name)
        self.assertEqual(r.returncode, 0)
        data = json.load(open(name + ".json"))
        self.assertEqual(len(data["127.0.0.1"]), 5)   # 5 ports scanned
        _cleanup(name)


# ── Multi-range positionals, report export ─────────────────────────────

class TestClassifyPositionals(unittest.TestCase):
    def test_classic_ip_then_ports(self):
        t, p = scan._classify_positionals("127.0.0.1", ["22", "80"])
        self.assertEqual(t, ["127.0.0.1"])
        self.assertEqual(p, ["22", "80"])

    def test_multiple_ranges_positional(self):
        t, p = scan._classify_positionals("10.0.0.0/24", ["10.0.1.0/24", "22", "80-90"])
        self.assertEqual(t, ["10.0.0.0/24", "10.0.1.0/24"])
        self.assertEqual(p, ["22", "80-90"])

    def test_hostname_is_a_target(self):
        t, p = scan._classify_positionals("example.com", ["443"])
        self.assertEqual(t, ["example.com"])
        self.assertEqual(p, ["443"])

    def test_port_range_and_list_stay_ports(self):
        t, p = scan._classify_positionals("10.0.0.1", ["22-25", "80,443"])
        self.assertEqual(t, ["10.0.0.1"])
        self.assertEqual(p, ["22-25", "80,443"])

    def test_brace_spec_is_target(self):
        t, p = scan._classify_positionals("10.0.0.{1-5}", ["22"])
        self.assertEqual(t, ["10.0.0.{1-5}"])

    def test_no_ip_only_ports(self):
        t, p = scan._classify_positionals(None, ["22"])
        self.assertEqual(t, [])
        self.assertEqual(p, ["22"])


class TestReport(unittest.TestCase):
    def _data(self, interrupted=False):
        results = {"10.0.0.1": {22: "open", 80: "closed", 443: "filtered"},
                   "10.0.0.2": {22: "closed"}}
        return scan.build_report_data(
            "10.0.0.0/29", ["10.0.0.1", "10.0.0.2"], [22, 80, 443],
            results, start=1000.0, end=1002.5, interrupted=interrupted)

    def test_summary_counts_all_states(self):
        self.assertEqual(self._data()["summary"],
                         {"open": 1, "closed": 2, "filtered": 1})

    def test_hosts_list_only_open_and_filtered(self):
        d = self._data()
        self.assertEqual([h["ip"] for h in d["hosts"]], ["10.0.0.1"])  # .2 all closed
        self.assertEqual({p["status"] for p in d["hosts"][0]["ports"]},
                         {"open", "filtered"})

    def test_duration_computed(self):
        self.assertEqual(self._data()["duration_sec"], 2.5)

    def test_json_render_valid(self):
        self.assertEqual(json.loads(scan.render_report("json", self._data()))
                         ["summary"]["open"], 1)

    def test_xml_render_parses(self):
        root = ET.fromstring(scan.render_report("xml", self._data()))
        self.assertEqual(root.tag, "scanreport")
        self.assertIsNotNone(root.find("hosts/host[@address='10.0.0.1']"))
        self.assertEqual(root.find("summary").get("closed"), "2")

    def test_csv_render_rows(self):
        s = scan.render_report("csv", self._data())
        self.assertIn("ip,port,protocol,status,service", s)
        self.assertIn("10.0.0.1,22,tcp,open", s)

    def test_txt_render_readable(self):
        s = scan.render_report("txt", self._data())
        self.assertIn("Host: 10.0.0.1", s)
        self.assertIn("22/tcp", s)
        self.assertIn("1 open, 2 closed, 1 filtered", s)

    def test_interrupted_flag_surfaces(self):
        d = self._data(interrupted=True)
        self.assertIn("INTERRUPTED", scan.render_report("txt", d))
        self.assertEqual(ET.fromstring(scan.render_report("xml", d))
                         .find("scan").get("interrupted"), "true")

    def test_unknown_format_exits(self):
        with self.assertRaises(SystemExit):
            scan.render_report("yaml", self._data())

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_write_report_atomic_0600(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.json"
            scan.write_report(str(p), "json", self._data())
            self.assertTrue(p.exists())
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)


class TestExportFlags(unittest.TestCase):
    def _p(self, *a):
        return scan.build_parser().parse_args(list(a))

    def test_all_export_flags(self):
        a = self._p("10.0.0.1", "22", "-oJ", "j", "-oX", "x", "-oT", "t",
                    "-oC", "c", "-oA", "base")
        self.assertEqual(
            (a.export_json, a.export_xml, a.export_txt, a.export_csv, a.export_all),
            ("j", "x", "t", "c", "base"))

    def test_oN_alias_for_txt(self):
        self.assertEqual(self._p("10.0.0.1", "22", "-oN", "f").export_txt, "f")

    def test_long_aliases(self):
        a = self._p("10.0.0.1", "22", "--xml", "x", "--json-report", "j", "--csv", "c")
        self.assertEqual((a.export_xml, a.export_json, a.export_csv), ("x", "j", "c"))

    def test_output_base_still_works_alongside_export(self):
        a = self._p("10.0.0.1", "22", "-o", "base", "-oX", "r.xml")
        self.assertEqual(a.output_name, "base")
        self.assertEqual(a.export_xml, "r.xml")


class TestReportExportCli(unittest.TestCase):
    def _run(self, *a):
        return subprocess.run([sys.executable, "-m", "tcpsweep", *a],
                              capture_output=True, text=True,
                              cwd=str(Path(__file__).parent))

    def test_export_all_writes_valid_files(self):
        with tempfile.TemporaryDirectory() as td:
            base = str(Path(td) / "rep")
            name = str(Path(td) / "work")
            r = self._run("127.0.0.1", "19999", "-w", "1", "-o", name, "-oA", base)
            self.assertEqual(r.returncode, 0)
            for ext in ("json", "xml", "txt", "csv"):
                self.assertTrue(Path(f"{base}.{ext}").exists(), f"missing {ext}")
            json.load(open(f"{base}.json"))     # valid JSON
            ET.parse(f"{base}.xml")             # valid XML

    def test_individual_export_flag(self):
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "work")
            xmlp = str(Path(td) / "out.xml")
            r = self._run("127.0.0.1", "19999", "-w", "1", "-o", name, "-oX", xmlp)
            self.assertEqual(r.returncode, 0)
            self.assertTrue(Path(xmlp).exists())

    def test_multi_range_positional_scan(self):
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "mr")
            r = self._run("127.0.0.0/30", "127.0.0.4/31", "-p", "19999",
                          "-w", "1", "-o", name)
            self.assertEqual(r.returncode, 0)
            data = json.load(open(f"{name}.json"))
            self.assertEqual(sorted(data),
                             ["127.0.0.1", "127.0.0.2", "127.0.0.4", "127.0.0.5"])


class TestScopeIsolation(unittest.TestCase):
    """Nothing outside this run's ``ips x ports`` may reach a user-facing
    artefact. A state file is shared by output *name*, so it can carry hosts
    and ports the current invocation never touched — and a report that lists
    an open port on an out-of-scope host is worse than no report."""

    IPS = ["127.0.0.2"]
    PORTS = [80]
    STRAY = {"9.9.9.9": {80: "open"},
             "127.0.0.1": {80: "open"},
             "127.0.0.2": {80: "closed", 443: "open"}}

    def test_scope_results_drops_out_of_scope(self):
        scoped = scan.scope_results(self.STRAY, self.IPS, self.PORTS)
        self.assertEqual(scoped, {"127.0.0.2": {80: "closed"}})

    def test_report_excludes_out_of_scope_hosts(self):
        data = scan.build_report_data(
            "127.0.0.2", self.IPS, self.PORTS, self.STRAY, start=1, end=2)
        self.assertEqual([h["ip"] for h in data["hosts"]], [])
        self.assertEqual(data["summary"], {"open": 0, "closed": 1, "filtered": 0})

    def test_counts_and_open_list_are_scoped(self):
        s = scan.Scanner(self.IPS, self.PORTS)
        s.state["results"] = {ip: dict(p) for ip, p in self.STRAY.items()}
        self.assertEqual(s._open_by_host(), {})
        self.assertEqual(s._counts(), {"open": 0, "closed": 1, "filtered": 0})

    def test_working_files_are_scoped(self):
        with tempfile.TemporaryDirectory() as td:
            name = str(Path(td) / "scoped")
            s = scan.Scanner(self.IPS, self.PORTS, output_name=name)
            s.state["results"] = {ip: dict(p) for ip, p in self.STRAY.items()}
            s._persist()
            self.assertEqual(json.load(open(f"{name}.json")),
                             {"127.0.0.2": {"80": "closed"}})
            # …while the state file keeps everything, so narrowing -p on a
            # resume never destroys results the earlier run paid for.
            state = json.load(open(f"{name}.state.json"))
            self.assertEqual(sorted(state["results"]),
                             ["127.0.0.1", "127.0.0.2", "9.9.9.9"])


class TestLinkOutageHandling(unittest.TestCase):
    """Results produced while the link is known-down are noise. They must
    never be recorded as though they described the target."""

    def test_probe_overlapping_an_outage_is_requeued(self):
        with tempfile.TemporaryDirectory() as td:
            s = scan.Scanner(["127.0.0.1"], [19_951], timeout=1,
                             output_name=str(Path(td) / "outage"))
            s._init_tasks()
            calls = []

            def fake(ip, port):
                calls.append((ip, port))
                if len(calls) == 1:
                    with s.results_lock:
                        s._pause_gen += 1      # outage starts mid-connect()
                    return "filtered", None
                return "closed", None

            s._scan_one = fake
            s._worker()
            self.assertEqual(len(calls), 2)    # re-probed, not trusted
            self.assertEqual(s.state["results"]["127.0.0.1"][19_951], "closed")

    def test_shutdown_during_outage_discards_suspect_results(self):
        with tempfile.TemporaryDirectory() as td:
            s = scan.Scanner(["10.0.0.1"], [22, 80], check_fails=2,
                             output_name=str(Path(td) / "drop"))
            s.state["results"] = {"10.0.0.1": {22: "filtered", 80: "filtered"}}
            s.since_good = [("10.0.0.1", 22), ("10.0.0.1", 80)]
            s.known_open = [("10.0.0.1", 443)]
            s.probe = lambda target: "filtered"      # link never comes back
            s.shutdown.set()                         # Ctrl+C during the outage
            s._run_health_check()
            self.assertEqual(s.state["results"]["10.0.0.1"], {})
            self.assertEqual(len(s.task_queue), 2)   # queued for a re-probe


class TestTimeoutValidation(unittest.TestCase):
    def test_zero_timeout_is_rejected(self):
        """settimeout(0) is non-blocking mode, not 'no timeout' — it reports
        every port filtered, including live listeners."""
        r = subprocess.run(
            [sys.executable, "-m", "tcpsweep", "127.0.0.1", "80", "-w", "0"],
            capture_output=True, text=True, cwd=str(Path(__file__).parent))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must be greater than 0", r.stderr)

    def test_zero_timeout_would_have_hidden_an_open_port(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 19_959))
        srv.listen(1)
        try:
            self.assertEqual(scan.scan_port("127.0.0.1", 19_959, timeout=0),
                             "filtered")     # the reason -w 0 is rejected
            self.assertEqual(scan.scan_port("127.0.0.1", 19_959, timeout=2),
                             "open")
        finally:
            srv.close()

    def test_fractional_timeout_accepted(self):
        p = scan.build_parser()
        self.assertAlmostEqual(p.parse_args(["1.2.3.4", "80", "-w", "0.5"]).timeout,
                               0.5)


class TestProxyAwareClassification(unittest.TestCase):
    """Through a proxy, ECONNREFUSED stops being proof of a closed port.

    proxychains runs the SOCKS handshake inside its hooked connect(); when the
    target is silently dropped it gives up on its own timeout and reports
    ECONNREFUSED. Measured against a stalling SOCKS5 proxy: 15s, then
    ECONNREFUSED for a port that was never refused at all.
    """

    def test_fast_refusal_is_closed(self):
        self.assertEqual(scan._classify_refusal(0.01, 5), "closed")

    def test_refusal_at_or_past_the_budget_is_filtered(self):
        self.assertEqual(scan._classify_refusal(5.0, 5), "filtered")
        self.assertEqual(scan._classify_refusal(15.0, 5), "filtered")

    def test_real_refusal_still_reads_closed(self):
        """The direct path must be unaffected: a genuine RST is immediate."""
        self.assertEqual(scan.scan_port("127.0.0.1", 19_958, timeout=5), "closed")

    def test_detects_proxychains_from_env(self):
        for env, expect in (
            ({"LD_PRELOAD": "/usr/lib/x86_64-linux-gnu/libproxychains.so.4"}, True),
            ({"PROXYCHAINS_CONF_FILE": "/etc/proxychains4.conf"}, True),
            ({"LD_PRELOAD": "/usr/lib/libsomethingelse.so"}, False),
            ({}, False),
        ):
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(scan._under_proxychains(), expect, env)


class TestOutputNaming(unittest.TestCase):
    def test_hostname_is_not_resolved_into_the_filename(self):
        """A hyphen used to route hostnames through the dash-range branch, so
        the state filename became a DNS-dependent IP range."""
        self.assertEqual(scan._make_default_name("my-site.com"), "my-site.com")
        self.assertEqual(scan._make_default_name("example.com"), "example.com")

    def test_cidr_and_ranges_unchanged(self):
        self.assertEqual(scan._make_default_name("10.0.0.0/24"), "10.0.0.0_24")
        self.assertEqual(scan._make_default_name("10.0.0.1-3"), "10.0.0.1-10.0.0.3")

    def test_extra_specs_change_the_name(self):
        """Naming after specs[0] alone made two different scans share a file."""
        one = scan.default_output_name(["10.0.0.0/24"])
        two = scan.default_output_name(["10.0.0.0/24", "10.1.0.0/24"])
        self.assertEqual(one, "10.0.0.0_24")
        self.assertNotEqual(one, two)
        self.assertTrue(two.startswith("10.0.0.0_24+1more-"))

    def test_name_has_no_path_separators(self):
        self.assertNotIn("/", scan._make_default_name("../../etc/passwd"))


if __name__ == "__main__":
    unittest.main()
