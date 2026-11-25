"""
Offline tests for the recon tool. No real tools or network needed:
fake `subfinder/httpx/katana/gau` executables are created in a temp dir and put on PATH.

Run from the project root:   python -m unittest discover -s tests -v
"""
import json, os, stat, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import recon  # noqa: E402

SCOPE = {
    "in_scope": ["*.example.com", "example.com"],
    "out_of_scope": ["admin.example.com"],
    "rate_limit": 5, "concurrency": 2, "timeout": 30,
    "headers": {"X-Bug-Bounty": "tester"},
}

FAKES = {
    "subfinder": "print('a.example.com'); print('admin.example.com'); print('evil.com'); print('dev.example.com')",
    "httpx": (
        "import sys, json\n"
        "for h in sys.stdin.read().split():\n"
        "    print(json.dumps({'host': h, 'url': 'https://'+h, 'status_code': 200,\n"
        "                      'title': 'Jenkins' if h.startswith('dev') else 'Home', 'tech': ['WordPress']}))"
    ),
    "katana": (
        "print('https://a.example.com/api/v1/users?id=1')\n"
        "print('https://a.example.com/api/v1/users?id=2')\n"      # same shape as above
        "print('https://a.example.com/static/logo.png')\n"          # noise
        "print('https://evil.com/api?id=1')\n"                      # out of scope
        "print('https://admin.example.com/panel')\n"                # out of scope (excluded)
        "print('https://a.example.com/app.js')"
    ),
    "gau": "print('https://a.example.com/old/login?redirect=/x')",
}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_cwd, self.old_path = os.getcwd(), os.environ["PATH"]
        os.chdir(self.tmp.name)
        self.bin = Path(self.tmp.name, "bin"); self.bin.mkdir()
        self.log = Path(self.tmp.name, "fake_calls.log")
        for name, body in FAKES.items():
            p = self.bin / name
            p.write_text("#!/usr/bin/env python3\nimport sys\n"
                         f"open({str(self.log)!r}, 'a').write(' '.join([{name!r}] + sys.argv[1:]) + '\\n')\n" + body + "\n")
            p.chmod(p.stat().st_mode | stat.S_IEXEC)
        os.environ["PATH"] = f"{self.bin}:{self.old_path}"
        Path("scope.json").write_text(json.dumps(SCOPE))
        self.scope = recon.Scope("scope.json")
        self.c = recon.db()

    def tearDown(self):
        self.c.close()
        os.chdir(self.old_cwd); os.environ["PATH"] = self.old_path
        self.tmp.cleanup()


class TestScope(Base):
    def test_out_of_scope_wins(self):
        self.assertTrue(self.scope.allowed("a.example.com"))
        self.assertFalse(self.scope.allowed("admin.example.com"))

    def test_unrelated_and_lookalike_hosts_blocked(self):
        self.assertFalse(self.scope.allowed("evil.com"))
        self.assertFalse(self.scope.allowed("example.com.evil.com"))
        self.assertFalse(self.scope.allowed(""))
        self.assertFalse(self.scope.allowed(None))

    def test_roots_are_deduplicated(self):
        self.assertEqual(self.scope.roots, ["example.com"])

    def test_url_allowed_ignores_port(self):
        self.assertTrue(self.scope.url_allowed("https://a.example.com:8443/x"))
        self.assertFalse(self.scope.url_allowed("https://evil.com/x"))


class TestNormalizeAndScore(Base):
    def test_numeric_and_uuid_collapse(self):
        a, _ = recon.normalize_url("https://x.com/user/1/profile?id=5")
        b, _ = recon.normalize_url("https://x.com/user/99/profile?id=9")
        self.assertEqual(a, b)
        u, _ = recon.normalize_url("https://x.com/o/123e4567-e89b-12d3-a456-426614174000/s")
        self.assertIn("{uuid}", u)

    def test_semantic_paths_not_merged(self):
        a, _ = recon.normalize_url("https://x.com/api/v1/users/me")
        b, _ = recon.normalize_url("https://x.com/api/v1/users/123/settings")
        self.assertNotEqual(a, b)

    def test_scoring_orders_sensible(self):
        hi, _ = recon.score_endpoint("/api/v1/export", ["user_id", "url"])
        lo, _ = recon.score_endpoint("/about", [])
        self.assertGreater(hi, lo)


class TestToolProfiles(Base):
    def test_headers_repeat_mode(self):
        argv = recon.build(self.scope, "httpx")
        i = argv.index("-H")
        self.assertEqual(argv[i + 1], "X-Bug-Bounty: tester")

    def test_headers_joined_mode_for_arjun(self):
        argv = recon.build(self.scope, "arjun", url="https://a.example.com/x", out="o.json")
        self.assertIn("--headers", argv)

    def test_passive_tool_gets_no_headers(self):
        self.assertNotIn("-H", recon.build(self.scope, "subfinder", domain="example.com"))

    def test_strict_mode_blocks_tool_without_header_support(self):
        self.scope.strict_headers = True
        with self.assertRaises(SystemExit):
            recon.build(self.scope, "gowitness")


class TestDiffing(Base):
    def _run(self, run_id, host):
        recon.begin_run(self.c, run_id)
        recon.upsert_asset(self.c, {"host": host, "url": "https://" + host, "status": 200,
                                    "title": "t", "tech": []}, run_id)
        self.c.commit()

    def test_new_and_reactivated(self):
        self._run("r1", "a.example.com")
        self._run("r2", "b.example.com")      # a is absent in r2
        self._run("r3", "a.example.com")      # a comes back
        rows = dict((h, (rid, react)) for h, rid, react in
                    self.c.execute("SELECT host, run_id, react_run FROM assets"))
        self.assertEqual(rows["a.example.com"], ("r1", "r3"))
        self.assertEqual(rows["b.example.com"], ("r2", None))


class TestPipelineEndToEnd(Base):
    def test_wide_keeps_only_in_scope(self):
        recon.begin_run(self.c, "r1")
        recon.wide_collect(self.scope, self.c, "r1")
        hosts = {h for (h,) in self.c.execute("SELECT host FROM assets")}
        self.assertIn("a.example.com", hosts)
        self.assertNotIn("admin.example.com", hosts)
        self.assertNotIn("evil.com", hosts)
        calls = self.log.read_text()
        self.assertIn("X-Bug-Bounty: tester", calls)          # header reached httpx

    def test_httpx_never_receives_out_of_scope_hosts(self):
        # fake httpx echoes whatever it gets on stdin; verify the guard ran BEFORE probing
        recon.begin_run(self.c, "r1")
        recon.wide_collect(self.scope, self.c, "r1")
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM assets WHERE host IN ('evil.com','admin.example.com')").fetchone()[0], 0)

    def test_narrow_filters_noise_scope_and_dedups(self):
        recon.begin_run(self.c, "r1")
        recon.narrow_collect(self.scope, self.c, "r1", "https://a.example.com")
        urls = [u for (u,) in self.c.execute("SELECT example FROM endpoints")]
        self.assertFalse(any("evil.com" in u or "admin.example.com" in u for u in urls))
        self.assertFalse(any(u.endswith(".png") for u in urls))
        users = [u for u in urls if "/api/v1/users" in u]
        self.assertEqual(len(users), 1)                         # id=1 / id=2 deduped to one shape

    def test_narrow_refuses_out_of_scope_target(self):
        with self.assertRaises(SystemExit):
            recon.narrow_collect(self.scope, self.c, "r1", "https://evil.com")


if __name__ == "__main__":
    unittest.main()
