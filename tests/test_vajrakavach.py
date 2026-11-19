import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from backend.app import create_server
from backend.core.db import get_connection
from backend.core.security import compute_totp


class VajrakavachEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_vajra.db"
        self.server = create_server("127.0.0.1", 0, self.db_path)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

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
            return err.code, json.loads(err.read().decode("utf-8"))

    def test_health_and_frontend_served(self) -> None:
        status, data = self._req("GET", "/api/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["founder"], "Divyesh Bambhaniya")

        with urllib.request.urlopen(f"{self.base_url}/") as resp:
            html = resp.read().decode("utf-8")
            self.assertEqual(resp.status, 200)
            self.assertIn("VAJRAKAVACH 2070", html)

    def test_tenant_isolation_and_rbac(self) -> None:
        # Register Tenant A
        s1, t1 = self._req("POST", "/api/v1/auth/register-tenant", {
            "tenant_name": "Alpha Bank",
            "sector": "banking",
            "full_name": "Admin Alpha",
            "email": "alpha@bank.example",
            "password": "StrongPassword1!",
        })
        self.assertEqual(s1, 201)
        token_a = t1["token"]

        # Register Tenant B
        s2, t2 = self._req("POST", "/api/v1/auth/register-tenant", {
            "tenant_name": "Beta Gov",
            "sector": "government",
            "full_name": "Admin Beta",
            "email": "beta@gov.example",
            "password": "StrongPassword2!",
        })
        self.assertEqual(s2, 201)
        token_b = t2["token"]

        # Tenant A creates asset & seals evidence
        s_a, asset_a = self._req("POST", "/api/v1/assets", {
            "name": "Alpha Core Ledger",
            "asset_type": "database",
            "criticality": "critical",
        }, token_a)
        self.assertEqual(s_a, 201)

        s_ev, ev_a = self._req("POST", "/api/v1/evidence", {
            "title": "Alpha Auth Log",
            "source": "Alpha SIEM",
            "content_payload": "2026-11-19T10:00:00Z login failed user=test",
        }, token_a)
        self.assertEqual(s_ev, 201)

        # Tenant B MUST NOT see Tenant A's assets or verify Tenant A's evidence
        _, b_assets = self._req("GET", "/api/v1/assets", token=token_b)
        self.assertEqual(len(b_assets["items"]), 0)

        s_cross, _ = self._req("GET", f"/api/v1/evidence/{ev_a['id']}/verify", token=token_b)
        self.assertEqual(s_cross, 404)

        # RBAC: Create read-only executive user in Tenant A and ensure writes are blocked (403)
        s_u, _ = self._req("POST", "/api/v1/auth/users", {
            "email": "exec@bank.example",
            "full_name": "Exec Reader",
            "role": "executive",
            "password": "ExecPassword1!",
        }, token_a)
        self.assertEqual(s_u, 201)

        s_l, exec_login = self._req("POST", "/api/v1/auth/login", {
            "email": "exec@bank.example",
            "password": "ExecPassword1!",
        })
        self.assertEqual(s_l, 200)
        exec_token = exec_login["token"]

        s_block, _ = self._req("POST", "/api/v1/assets", {
            "name": "Unauthorized Asset",
            "asset_type": "server",
        }, exec_token)
        self.assertEqual(s_block, 403)

    def test_mfa_totp_flow(self) -> None:
        _, reg = self._req("POST", "/api/v1/auth/register-tenant", {
            "tenant_name": "MFA Corp",
            "sector": "enterprise",
            "full_name": "MFA Admin",
            "email": "mfa@corp.example",
            "password": "MfaPassword1!",
        })
        tok = reg["token"]

        s_setup, setup_data = self._req("POST", "/api/v1/auth/mfa/setup", {}, tok)
        self.assertEqual(s_setup, 200)
        secret = setup_data["mfa_secret"]

        code = compute_totp(secret)
        s_en, en_data = self._req("POST", "/api/v1/auth/mfa/enable", {"totp_code": code}, tok)
        self.assertEqual(s_en, 200)
        self.assertTrue(en_data["mfa_enabled"])

        # Login without TOTP must fail
        s_fail, _ = self._req("POST", "/api/v1/auth/login", {
            "email": "mfa@corp.example",
            "password": "MfaPassword1!",
        })
        self.assertEqual(s_fail, 401)

        # Login with valid TOTP must succeed
        s_ok, _ = self._req("POST", "/api/v1/auth/login", {
            "email": "mfa@corp.example",
            "password": "MfaPassword1!",
            "totp_code": compute_totp(secret),
        })
        self.assertEqual(s_ok, 200)

    def test_soc_correlation_evidence_integrity_and_audit_tamper_detection(self) -> None:
        _, reg = self._req("POST", "/api/v1/auth/register-tenant", {
            "tenant_name": "Cyber Defense India",
            "sector": "research",
            "full_name": "Divyesh Bambhaniya",
            "email": "founder@vajrakavach.example",
            "password": "FounderPassword1!",
        })
        tok = reg["token"]

        # Risk scoring
        s_r, risk = self._req("POST", "/api/v1/risks", {
            "title": "Unpatched API Gateway",
            "likelihood": 5,
            "impact": 4,
            "mitigation_plan": "Apply vendor patch",
        }, tok)
        self.assertEqual(s_r, 201)
        self.assertEqual(risk["risk_score"], 20)
        self.assertEqual(risk["severity"], "critical")

        # High severity SOC event auto-creates reviewable case
        s_e, ev = self._req("POST", "/api/v1/soc/events", {
            "source": "suricata",
            "event_type": "port_scan_burst",
            "severity": "critical",
            "mitre_tactic": "Discovery",
            "summary": "Critical anomalous burst detected on DMZ interface",
        }, tok)
        self.assertEqual(s_e, 201)
        self.assertIsNotNone(ev["correlated_case_id"])

        # Human approval updates case
        s_c, updated_case = self._req("PATCH", f"/api/v1/soc/cases/{ev['correlated_case_id']}", {
            "status": "contained",
            "analyst_notes": "Human SOC manager verified and isolated host.",
        }, tok)
        self.assertEqual(s_c, 200)
        self.assertEqual(updated_case["human_approved_by"], "founder@vajrakavach.example")

        # Seal & verify evidence
        _, sealed = self._req("POST", "/api/v1/evidence", {
            "title": "PCAP Summary",
            "source": "Zeek Sensor 01",
            "content_payload": "conn_id=99182 src=10.0.0.5 dst=10.0.0.20",
        }, tok)
        _, ver = self._req("GET", f"/api/v1/evidence/{sealed['id']}/verify", token=tok)
        self.assertTrue(ver["intact"])
        self.assertEqual(len(ver["chain_of_custody"]), 2)

        # Verify audit chain is intact
        _, chain_ok = self._req("GET", "/api/v1/audit/verify", token=tok)
        self.assertTrue(chain_ok["valid"])
        self.assertGreaterEqual(chain_ok["checked_entries"], 4)

        # Simulate direct DB tampering and prove audit verifier catches it!
        conn = get_connection(self.db_path)
        conn.execute("UPDATE audit_logs SET action = 'TAMPERED_ACTION' WHERE id = 1")
        conn.commit()
        conn.close()

        _, chain_bad = self._req("GET", "/api/v1/audit/verify", token=tok)
        self.assertFalse(chain_bad["valid"])
        self.assertEqual(chain_bad["reason"], "entry_hash_tampered")


if __name__ == "__main__":
    unittest.main()
