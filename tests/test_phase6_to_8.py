"""Phase 6-8 automated tests: PQC Readiness, Hardware Attestation, Adaptive Defense, 2070 Research Hub."""
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from backend.app import create_server


class VajrakavachPhase6To8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_v1.db"
        self.server = create_server("127.0.0.1", 0, self.db_path)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        _, reg = self._req("POST", "/api/v1/auth/register-tenant", {
            "tenant_name": "Vajrakavach 2070 Quantum Lab",
            "sector": "government",
            "full_name": "Divyesh Bambhaniya",
            "email": "v1@vajrakavach.example",
            "password": "StrongV100Password!",
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

    def test_pqc_readiness_auditor(self) -> None:
        s1, p1 = self._req("POST", "/api/v1/pqc/inventory", {
            "system_name": "Legacy Signer",
            "algorithm": "SHA-1",
            "data_shelf_life_years": 20,
        }, self.token)
        self.assertEqual(s1, 201)
        self.assertEqual(p1["quantum_risk"], "critical")

        s2, p2 = self._req("POST", "/api/v1/pqc/inventory", {
            "system_name": "PQC TLS Gateway",
            "algorithm": "ML-KEM-768",
            "data_shelf_life_years": 25,
        }, self.token)
        self.assertEqual(s2, 201)
        self.assertEqual(p2["quantum_risk"], "quantum_ready")

        s3, inv = self._req("GET", "/api/v1/pqc/inventory", token=self.token)
        self.assertEqual(s3, 200)
        self.assertEqual(inv["pqc_readiness_pct"], 50)

    def test_hardware_firmware_attestation(self) -> None:
        s_ok, ok = self._req("POST", "/api/v1/infra/hardware", {
            "device_name": "Grid-PLC-01",
            "sector": "energy",
            "firmware_version": "2.4.1",
            "expected_sha256": "a" * 64,
            "measured_sha256": "a" * 64,
            "tpm_enabled": True,
        }, self.token)
        self.assertEqual(s_ok, 201)
        self.assertEqual(ok["attestation_status"], "ATTESTATION_VERIFIED")

        s_bad, bad = self._req("POST", "/api/v1/infra/hardware", {
            "device_name": "Grid-PLC-02",
            "sector": "energy",
            "firmware_version": "2.4.1",
            "expected_sha256": "a" * 64,
            "measured_sha256": "b" * 64,
            "tpm_enabled": True,
        }, self.token)
        self.assertEqual(s_bad, 201)
        self.assertEqual(bad["attestation_status"], "ATTESTATION_FAILED")

    def test_adaptive_defense_posture_engine(self) -> None:
        # Trigger failed hardware attestation + broken crypto to escalate posture
        self._req("POST", "/api/v1/infra/hardware", {
            "device_name": "Substation-RTU",
            "sector": "energy",
            "expected_sha256": "1" * 64,
            "measured_sha256": "2" * 64,
        }, self.token)
        self._req("POST", "/api/v1/pqc/inventory", {
            "system_name": "Old Auth",
            "algorithm": "MD5",
        }, self.token)

        s, ad = self._req("POST", "/api/v1/adaptive/evaluate", {}, self.token)
        self.assertEqual(s, 201)
        self.assertFalse(ad["auto_execute"])
        self.assertTrue(ad["human_approval_required"])
        self.assertGreaterEqual(ad["risk_index"], 35)
        self.assertIn("DEFCON-", ad["posture_level"])

    def test_global_2070_research_hub(self) -> None:
        s, prop = self._req("POST", "/api/v1/research/proposals", {
            "title": "Hybrid Post-Quantum Zero-Trust Mesh",
            "domain": "PQC",
            "horizon": "2041-2070",
            "maturity_stage": "hypothesis",
            "summary": "Evaluating ML-KEM-768 handshake latency on low-RAM Android/IoT nodes.",
        }, self.token)
        self.assertEqual(s, 201)
        self.assertEqual(len(prop["provenance_sha256"]), 64)
        self.assertEqual(prop["maturity_stage"], "hypothesis")


if __name__ == "__main__":
    unittest.main()
