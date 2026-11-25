"""End-to-end and negative tests: lab on loopback, full pipeline, scope guard."""

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lab"))

import vulnerable_app
from vulnchain.findings import cvss31_base, redact
from vulnchain.pipeline import run_assessment, write_reports
from vulnchain.scope import Scope, ScopeViolation

LAB_SECRETS = ("s3cr3tP@ss", "Hunter2!", "tok_live_9f8e7d6c5b")


def free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class CvssTest(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), 7.5)
        self.assertEqual(cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"), 5.3)
        self.assertEqual(cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)

    def test_redaction(self):
        self.assertEqual(redact("DB_PASS=Hunter2!"), "DB_PASS=<redacted>")
        self.assertEqual(redact("api_key: abc123"), "api_key=<redacted>")


class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port), vulnerable_app.LabHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _scope(self, **overrides):
        data = {
            "name": "unit-test-lab",
            "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [self.port],
            "verify_credentials": True,
        }
        data.update(overrides)
        fh, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fh, "w") as out:
            json.dump(data, out)
        self.addCleanup(os.unlink, path)
        return Scope.load(path)

    def test_full_pipeline_finds_and_verifies_chain(self):
        scope = self._scope()
        findings, chains, started, finished = run_assessment(scope)

        self.assertTrue(any("Directory listing" in f.title for f in findings))
        self.assertTrue(any("credential" in f.title.lower() for f in findings))
        self.assertTrue(any(f.title.startswith("Exposed .git") for f in findings))
        self.assertTrue(any("Missing security header" in f.title for f in findings))
        self.assertTrue(any("advertised" in f.title for f in findings),
                        "methods must be labeled advertised, not assumed dangerous")
        verified = [f for f in findings if f.verified]
        self.assertTrue(verified, "expected a verified lab credential chain")
        auth = next(f for f in verified if f.id.startswith("VC-AUTH-OK"))
        self.assertIn("Wrong-credential control rejected", auth.evidence)
        self.assertIn("protected", auth.evidence)

        self.assertTrue(chains, "expected at least one attack chain")
        top = chains[0]
        self.assertEqual(top["severity"], "high")
        self.assertTrue(top["verified"])
        self.assertGreaterEqual(len(top["finding_ids"]), 3)

        with tempfile.TemporaryDirectory() as outdir:
            paths = write_reports(scope, findings, chains, started, finished, outdir)
            for path in paths.values():
                self.assertTrue(os.path.getsize(path) > 500)
            md = open(paths["md"]).read()
            self.assertIn("Attack chains", md)
            self.assertIn("Limitations", md)
            self.assertIn("internal severity", md)

    def test_reports_never_contain_lab_secrets(self):
        scope = self._scope()
        findings, chains, started, finished = run_assessment(scope)
        with tempfile.TemporaryDirectory() as outdir:
            paths = write_reports(scope, findings, chains, started, finished, outdir)
            for path in paths.values():
                content = open(path).read()
                for secret in LAB_SECRETS:
                    self.assertNotIn(secret, content, f"secret leaked in {path}")

    def test_findings_evidence_redacted(self):
        scope = self._scope()
        findings, _, _, _ = run_assessment(scope)
        for f in findings:
            for secret in LAB_SECRETS:
                self.assertNotIn(secret, f.evidence)
                self.assertNotIn(secret, json.dumps(f.to_dict()))

    def test_redirect_target_never_touched(self):
        scope = self._scope()
        findings, _, _, _ = run_assessment(scope)
        for f in findings:
            self.assertNotIn("169.254.169.254", f.evidence)
            self.assertNotIn("169.254.169.254", f.target)

    def test_scope_refuses_out_of_scope_host(self):
        scope = self._scope()
        with self.assertRaises(ScopeViolation):
            scope.check("169.254.169.254", self.port)
        with self.assertRaises(ScopeViolation):
            scope.check("127.0.0.1", 22)

    def test_cidr_scope_refuses_outside_ip(self):
        scope = self._scope(allowed_hosts=["10.0.0.0/8"])
        with self.assertRaises(ScopeViolation):
            scope.check("127.0.0.1", self.port)

    def test_verification_skipped_without_opt_in(self):
        scope = self._scope(verify_credentials=False)
        findings, chains, _, _ = run_assessment(scope)
        self.assertFalse(any(f.verified and f.id.startswith("VC-AUTH") for f in findings))

    def test_hostname_scope_pins_and_connects(self):
        scope = self._scope(allowed_hosts=["localhost"])
        findings, _, _, _ = run_assessment(scope)
        self.assertTrue(findings)
        self.assertTrue(all(f.target.startswith("localhost:") for f in findings))
        self.assertIn(scope.pinned_ip("localhost"), ("127.0.0.1", "::1"))

    def test_html_report_escapes_finding_content(self):
        from vulnchain.findings import Finding
        from vulnchain.report import render_html
        from datetime import datetime, timezone
        evil = Finding(id="VC-X-1", title="<script>alert(1)</script>",
                       severity="low", target="127.0.0.1:1",
                       evidence="<img src=x onerror=alert(1)>", remediation="n/a")
        scope = self._scope()
        now = datetime.now(timezone.utc)
        html_out = render_html(scope, [evil], [], now, now)
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertNotIn("<img src=x onerror=alert(1)>", html_out)
        self.assertIn("&lt;script&gt;", html_out)

    def test_request_budget_enforced(self):
        scope = self._scope(max_requests_per_host=5)
        for _ in range(5):
            scope.check("127.0.0.1", self.port)
        with self.assertRaises(ScopeViolation):
            scope.check("127.0.0.1", self.port)

    def test_pinned_ip_requires_prior_check(self):
        scope = self._scope()
        with self.assertRaises(ScopeViolation):
            scope.pinned_ip("127.0.0.1")
        scope.check("127.0.0.1", self.port)
        self.assertEqual(scope.pinned_ip("127.0.0.1"), "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
