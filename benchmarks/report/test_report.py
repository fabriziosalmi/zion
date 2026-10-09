"""Unit tests for the pieces of the report harness that do not need the benchmark host.

    python3 -m unittest benchmarks/report/test_report.py
"""
import hashlib
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "regress"))

import bench  # noqa: E402
import conformance as cf  # noqa: E402
import gen_site  # noqa: E402
import probe_origin  # noqa: E402
try:
    import render  # noqa: E402
except ImportError:     # matplotlib is only needed to render, not to test the rest
    render = None

# If this changes, every report measured a different site: bump bench.PROCEDURE and say so.
SITE_SHA256 = "7873d1c9b2e29573518971eb91102b767a806fda9ff569b85933c8052e654294"


class Site(unittest.TestCase):
    def test_the_site_is_the_same_bytes_everywhere(self):
        with tempfile.TemporaryDirectory() as d:
            r = gen_site.build(Path(d), gen_site.SEED)
            self.assertEqual(hashlib.sha256(r["manifest"].encode()).hexdigest(), SITE_SHA256)
            self.assertEqual(r["files"], 230)
            m = json.loads(r["manifest"])["files"]
            for f in (m[0], m[-1]):
                self.assertEqual(hashlib.sha256((Path(d) / f["path"].lstrip("/")).read_bytes()).hexdigest(), f["sha256"])

    def test_the_prng_is_splitmix64(self):
        # first outputs of SplitMix64 seeded with 0, from the reference implementation
        r = gen_site.Rng(0)
        self.assertEqual([r.next() for _ in range(2)], [0xE220A8397B1DCDAF, 0x6E789E6AA1B965F4])


class Parser(unittest.TestCase):
    def test_content_length(self):
        r, used = cf.parse_one(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA")
        self.assertEqual((r.status, r.body, r.complete, used), (200, b"hello", True, 5 + len(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")))

    def test_short_body_is_not_complete(self):
        r, _ = cf.parse_one(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
        self.assertFalse(r.complete)

    def test_chunked_and_unterminated_chunked(self):
        r, _ = cf.parse_one(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        self.assertEqual((r.body, r.complete), (b"hello", True))
        r, _ = cf.parse_one(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
        self.assertFalse(r.complete)

    def test_interim_responses_are_skipped_and_head_has_no_body(self):
        r, _ = cf.parse_one(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        self.assertEqual((r.status, r.interim, r.body), (200, [100], b"ok"))
        r, _ = cf.parse_one(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n", "HEAD")
        self.assertTrue(r.complete)
        r, _ = cf.parse_one(b'HTTP/1.1 304 Not Modified\r\nETag: "x"\r\n\r\n')
        self.assertEqual((r.status, r.body, r.complete), (304, b"", True))


class Probe(unittest.TestCase):
    def setUp(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); a = s.getsockname()[1]; s.close()
        s = socket.socket(); s.bind(("127.0.0.1", 0)); b = s.getsockname()[1]; s.close()
        self.o = probe_origin.ProbeOrigin(a, b)
        self.o.start()
        self.port = a

    def tearDown(self):
        self.o.stop()

    def test_echo_remembers_what_it_was_sent(self):
        r = cf.exchange(self.port, cf.req("POST", "/p/echo", ["Content-Length: 5", "X-A: b"], b"hello"), tls=False)[-1]
        self.assertEqual(r.status, 200)
        self.assertIn(hashlib.sha256(b"hello").hexdigest().encode(), r.body)
        self.assertEqual(self.o.seen[0]["target"], "/p/echo")
        self.assertEqual(self.o.seen[0]["body_len"], 5)

    def test_it_reads_chunked_bodies_and_pipelines(self):
        body = b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
        rs = cf.exchange(self.port, cf.req("POST", "/p/echo", ["Transfer-Encoding: chunked"], body) + cf.req("GET", "/p/echo?two"),
                         methods=("POST", "GET"), tls=False)
        self.assertEqual([x.status for x in rs], [200, 200])
        self.assertIn(hashlib.sha256(b"abcde").hexdigest().encode(), rs[0].body)
        self.assertEqual([s["target"] for s in self.o.seen], ["/p/echo", "/p/echo?two"])

    def test_crafted_responses(self):
        r = cf.exchange(self.port, cf.req("GET", "/p/resp-short"), tls=False, expect_close=True)[-1]
        self.assertFalse(r.complete)
        self.assertTrue(r.closed)
        r = cf.exchange(self.port, cf.req("GET", "/p/resp-cl-te"), tls=False, expect_close=True)[-1]
        self.assertEqual(r.body, b"hello")
        self.assertIn("content-length", r.names())
        self.assertIn("transfer-encoding", r.names())
        r = cf.exchange(self.port, cf.req("GET", "/p/resp-100"), tls=False)[-1]
        self.assertEqual((r.status, r.interim), (200, [100]))


class RigProcesses(unittest.TestCase):
    @unittest.skipUnless(Path("/proc").exists(), "the rig reads /proc: Linux only")
    def test_stopping_a_variant_stops_the_process_spawned_under_zion(self):
        # In --variants mode every build is spawned as "zion" but stopped by its variant name; a stop
        # that matched nothing left the process alive and, since zion binds with SO_REUSEPORT, the
        # next instance shared the port with it: the measurement saw a fraction of the traffic.
        import subprocess
        rig = bench.Rig(Path("/nonexistent"), Path(tempfile.gettempdir()) / "zion-rig-test")
        bench.VARIANTS["plain"] = Path("/x")
        try:
            proc = rig.procs["zion"] = subprocess.Popen(["sleep", "30"])
            rig.stop("plain")
            self.assertNotIn("zion", rig.procs)
            self.assertIsNotNone(proc.returncode, "the process was left running")
        finally:
            bench.VARIANTS.clear()

    def test_a_listener_left_behind_stops_the_run(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
        try:
            with self.assertRaises(SystemExit):
                bench.refuse_if_listening(s.getsockname()[1], "x")
        finally:
            s.close()
        free = socket.socket(); free.bind(("127.0.0.1", 0)); port = free.getsockname()[1]; free.close()
        bench.refuse_if_listening(port, "x")      # nothing listens: no exit


@unittest.skipIf(render is None, "matplotlib not installed")
class Judge(unittest.TestCase):
    def s(self, cpu, mad=0.0):
        return dict(cpu_us_per_req=cpu, rps_mad_pct=mad)

    def test_noise_widens_the_bar(self):
        self.assertEqual(render.judge(self.s(100), self.s(104))[0], "same")          # under the 5 % tolerance
        self.assertEqual(render.judge(self.s(100), self.s(108))[0], "worse")
        self.assertEqual(render.judge(self.s(100, 4), self.s(108, 4))[0], "same")    # 3 x hypot(4,4) = 17 %
        self.assertEqual(render.judge(self.s(100), self.s(90))[0], "better")


if __name__ == "__main__":
    unittest.main()
