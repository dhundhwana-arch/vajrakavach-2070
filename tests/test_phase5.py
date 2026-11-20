"""Phase 5 automated tests: Lawful OSINT, Privacy-Preserving Share, Simulation Labs, Intel Fusion."""
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from backend.app import create_server


class VajrakavachPhase5Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_phase5.db"
        self.server = create_server("127.0.0.1", 0, self.db_path)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        _, reg = self._req("POST", "/api/v1/auth/register-tenant", {
            "tenant_name": "Vajra Intel Fusion Center",
            "sector": "research",
            "full_name": "Divyesh Bambhaniya",
            "email": "phase5@vajrakavach.example",
            "password": "StrongPhase5Password!",
        })
        self.token = reg["token"]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmpdir.cleanup()

    def _req(self, method: str, path: str, body=None, token: str = ""):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            try:
                return err.code, json.loads(err.read().decode("utf-8"))
            finally:
                err.close()

    def test_lawful_osint_boundary_and_dedup(self) -> None:
        # Restricted private scraping must be rejected (400)
        s_bad, _ = self._req("POST", "/api/v1/osint", {
            "subject": "Private Account Dump",
            "classification": "restricted",
            "source_url": "https://example.invalid",
            "content_excerpt": "private data",
        }, self.token)
        self.assertEqual(s_bad, 400)

        # Public advisory accepted
        s1, r1 = self._req("POST", "/api/v1/osint", {
            "subject": "CERT-In Advisory 2026-01",
            "classification": "public",
            "source_url": "https://www.cert-in.org.in/",
            "content_excerpt": "Critical patch released for gateway software.",
        }, self.token)
        self.assertEqual(s1, 201)
        self.assertFalse(r1["duplicate_detected"])

        # Same content triggers automatic duplicate detection
        s2, r2 = self._req("POST", "/api/v1/osint", {
            "subject": "Duplicate Advisory Copy",
            "classification": "public",
            "source_url": "https://www.cert-in.org.in/",
            "content_excerpt": "  Critical   patch released for gateway software. ",
        }, self.token)
        self.assertEqual(s2, 201)
        self.assertTrue(r2["duplicate_detected"])
        self.assertEqual(r2["duplicate_of_id"], r1["id"])

    def test_privacy_preserving_redaction(self) -> None:
        s, res = self._req("POST", "/api/v1/privacy/shares", {
            "title": "Sanitized Phishing Alert",
            "tlp_level": "TLP:GREEN",
            "raw_payload": "User alice@bank.in PAN ABCDE1234F phone 9876543210 host 192.168.10.22 reported phishing.",
        }, self.token)
        self.assertEqual(s, 201)
        self.assertIn("[REDACTED_EMAIL]", res["sanitized_payload"])
        self.assertIn("[REDACTED_PAN]", res["sanitized_payload"])
        self.assertIn("[REDACTED_PHONE]", res["sanitized_payload"])
        self.assertIn("[REDACTED_INTERNAL_IP]", res["sanitized_payload"])
        self.assertNotIn("alice@bank.in", res["sanitized_payload"])
        self.assertNotIn("ABCDE1234F", res["sanitized_payload"])

    def test_simulation_lab_execution(self) -> None:
        s, lab = self._req("POST", "/api/v1/labs/runs", {
            "scenario_id": "ai_prompt_defense_lab",
        }, self.token)
        self.assertEqual(s, 201)
        self.assertEqual(lab["mode"], "SIMULATION_SANDBOX_ONLY")
        self.assertEqual(lab["total_checks"], 5)
        self.assertEqual(len(lab["experiment_sha256"]), 64)

    def test_intel_fusion_readiness(self) -> None:
        self._req("POST", "/api/v1/risks", {
            "title": "High Risk Item",
            "likelihood": 4,
            "impact": 4,
        }, self.token)
        s, fusion = self._req("GET", "/api/v1/intel/fusion", token=self.token)
        self.assertEqual(s, 200)
        self.assertTrue(fusion["audit_chain_valid"])
        self.assertEqual(fusion["signals"]["open_high_risks"], 1)
        self.assertLess(fusion["unified_readiness_score"], 100)


if __name__ == "__main__":
    unittest.main()
