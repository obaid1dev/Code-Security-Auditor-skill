import json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "code-security-auditor" / "scripts" / "scan.py"
REPORT = ROOT / "code-security-auditor" / "scripts" / "report.py"
sys.path.insert(0, str(Path(__file__).parent))
import demo_project  # noqa: E402

MUST_FIND = {
    "SEC-STRIPE", "SEC-AI-KEY", "SEC-DBURL", "SEC-WEAKLIT", "HYG-ENVFILE", "JWT-NOVERIFY", "FIREBASE-OPEN",
    "INJ-SQL-PY", "INJ-SQL-JS", "INJ-CMD-PY", "INJ-CMD-JS", "INJ-SSTI", "PATH-TRAV", "SSRF", "OPEN-REDIR",
    "DESER-UNSAFE", "CRYPTO-WEAKHASH", "CORS-WILDCARD", "IDOR-HINT", "MASS-ASSIGN", "INJ-XSS-DOM",
    "INJ-XSS-REACT", "COOKIE-FLAGS", "CLIENT-SECRET-ENV", "MOBILE-ASYNCSTORAGE", "MOBILE-CLEARTEXT",
    "DOCKER-REMOTE-EXEC", "DEBUG-ON", "LOG-SENSITIVE", "TOKEN-LOCALSTORAGE",
}


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.proj = demo_project.build(Path(cls.tmp.name) / "demo")
        cls.out = Path(cls.tmp.name) / "findings.json"
        subprocess.run([sys.executable, str(SCAN), str(cls.proj), "--out", str(cls.out), "--quiet"], check=True)
        cls.data = json.loads(cls.out.read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_detects_expected_rules(self):
        found = {f["rule"] for f in self.data["findings"]}
        self.assertFalse(MUST_FIND - found, f"missed: {sorted(MUST_FIND - found)}")

    def test_secrets_are_masked(self):
        blob = json.dumps(self.data)
        for needle in ("51HxyzABCDEFGHIJKLMNOPqr", "Sup3rS3cretPw", "abcdefghijklmnopqrstuvwxyz0123456789"):
            self.assertNotIn(needle, blob)

    def test_placeholders_and_tests_ignored(self):
        files = {f["file"] for f in self.data["findings"]}
        self.assertNotIn(".env.example", files)
        self.assertFalse(any(f.startswith("tests/") for f in files))
        self.assertFalse(any("your_api_key_here" in f["snippet"] for f in self.data["findings"]))

    def test_entry_points_and_manifests(self):
        self.assertGreater(len(self.data["entry_points"]), 5)
        self.assertIn("package.json", self.data["manifests"])

    def test_clean_project_has_no_findings(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".gitignore").write_text(".env\n")
            (Path(d) / "a.py").write_text("import os\nKEY = os.environ['KEY']\ncur.execute('SELECT 1 WHERE a=%s', (x,))\n")
            out = Path(d) / "f.json"
            subprocess.run([sys.executable, str(SCAN), d, "--out", str(out), "--quiet"], check=True)
            self.assertEqual(json.loads(out.read_text())["findings"], [])

    def test_report_and_sarif(self):
        data = json.loads(self.out.read_text())
        for f in data["findings"]:
            f["status"] = "Needs verification"
        triaged = Path(self.tmp.name) / "t.json"
        triaged.write_text(json.dumps(data))
        md, sarif = Path(self.tmp.name) / "r.md", Path(self.tmp.name) / "r.sarif"
        subprocess.run([sys.executable, str(REPORT), str(triaged), "--out", str(md), "--sarif", str(sarif)], check=True)
        text = md.read_text()
        for h in ("Executive summary", "Findings", "Details and diffs", "Prevention guidelines"):
            self.assertIn(h, text)
        self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
