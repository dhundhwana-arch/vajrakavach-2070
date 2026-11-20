import json
import mimetypes
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from backend import config
from backend.core.audit import list_audit_logs, verify_audit_chain
from backend.core.db import get_connection, init_db
from backend.core.security import AuthError, verify_token
from backend.modules import adaptive_defense, ai_sec, assets, auth, banking_fraud, cloud_sec, compliance, evidence, gov_certin, infra_hardware, intel_fusion, knowledge_graph, malware_lab, osint_intel, pqc_readiness, privacy_share, research_hub, risks, sbom, sim_labs, soc, threat_intel, tools, web_api_sec


class VajraHandler(BaseHTTPRequestHandler):
    db_path: Optional[Path] = None

    def log_message(self, format: str, *args: Any) -> None:
        # Clean concise server log
        print(f"[VAJRAKAVACH] {self.address_string()} - {format % args}")

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, rel_path: str) -> None:
        clean_rel = "index.html" if rel_path in {"", "/"} else rel_path.lstrip("/")
        target = (config.FRONTEND_DIR / clean_rel).resolve()
        if not str(target).startswith(str(config.FRONTEND_DIR.resolve())) or not target.is_file():
            self._send_json({"error": "Not found"}, 404)
            return
        mime, _ = mimetypes.guess_type(str(target))
        content = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{mime or 'application/octet-stream'}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > config.MAX_BODY_BYTES:
            raise ValueError("Request payload exceeds 1 MB limit.")
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON request body.") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object.")
        return data

    def _authenticate(self) -> Dict[str, Any]:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise AuthError("Missing Bearer token.", 401)
        return verify_token(header[7:].strip())

    def _handle_request(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if not path.startswith("/api/"):
            if method == "GET":
                self._send_static(path)
            else:
                self._send_json({"error": "Method not allowed"}, 405)
            return

        conn = get_connection(self.db_path)
        try:
            # --- Public Health & Auth Endpoints ---
            if path == "/api/v1/health" and method == "GET":
                self._send_json({
                    "status": "healthy",
                    "app": config.APP_NAME,
                    "version": config.APP_VERSION,
                    "founder": config.FOUNDER,
                    "identity": config.PRODUCT_IDENTITY,
                })
                return

            if path == "/api/v1/auth/register-tenant" and method == "POST":
                result = auth.register_tenant(conn, self._read_json())
                self._send_json(result, 201)
                return

            if path == "/api/v1/auth/login" and method == "POST":
                result = auth.login_user(conn, self._read_json())
                self._send_json(result, 200)
                return

            # --- Authenticated Endpoints ---
            actor = self._authenticate()

            if path == "/api/v1/auth/users" and method == "POST":
                self._send_json(auth.create_tenant_user(conn, actor, self._read_json()), 201)
                return
            if path == "/api/v1/auth/mfa/setup" and method == "POST":
                self._send_json(auth.setup_mfa(conn, actor), 200)
                return
            if path == "/api/v1/auth/mfa/enable" and method == "POST":
                body = self._read_json()
                self._send_json(auth.enable_mfa(conn, actor, body.get("totp_code", "")), 200)
                return

            if path == "/api/v1/dashboard/summary" and method == "GET":
                self._send_json(compliance.dashboard_summary(conn, actor), 200)
                return

            if path == "/api/v1/assets":
                if method == "GET":
                    self._send_json({"items": assets.list_assets(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(assets.create_asset(conn, actor, self._read_json()), 201)
                    return

            if path == "/api/v1/risks":
                if method == "GET":
                    self._send_json({"items": risks.list_risks(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(risks.create_risk(conn, actor, self._read_json()), 201)
                    return

            if path == "/api/v1/soc/events":
                if method == "GET":
                    self._send_json({"items": soc.list_events(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(soc.ingest_event(conn, actor, self._read_json()), 201)
                    return

            if path == "/api/v1/soc/cases" and method == "GET":
                self._send_json({"items": soc.list_cases(conn, actor)}, 200)
                return

            m_case = re.fullmatch(r"/api/v1/soc/cases/(\d+)", path)
            if m_case and method == "PATCH":
                self._send_json(soc.update_case_status(conn, actor, int(m_case.group(1)), self._read_json()), 200)
                return

            if path == "/api/v1/evidence":
                if method == "GET":
                    self._send_json({"items": evidence.list_evidence(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(evidence.intake_evidence(conn, actor, self._read_json()), 201)
                    return

            m_ev = re.fullmatch(r"/api/v1/evidence/(\d+)/verify", path)
            if m_ev and method == "GET":
                self._send_json(evidence.verify_evidence(conn, actor, int(m_ev.group(1))), 200)
                return

            if path == "/api/v1/tools":
                if method == "GET":
                    self._send_json({"items": tools.list_tools(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(tools.register_tool(conn, actor, self._read_json()), 201)
                    return

            m_tool = re.fullmatch(r"/api/v1/tools/(\d+)/status", path)
            if m_tool and method == "PATCH":
                body = self._read_json()
                self._send_json(tools.update_tool_status(conn, actor, int(m_tool.group(1)), body.get("approval_status", "")), 200)
                return

            if path == "/api/v1/compliance" and method == "GET":
                self._send_json({"items": compliance.list_controls(conn, actor)}, 200)
                return

            m_ctrl = re.fullmatch(r"/api/v1/compliance/(\d+)", path)
            if m_ctrl and method == "PATCH":
                self._send_json(compliance.update_control(conn, actor, int(m_ctrl.group(1)), self._read_json()), 200)
                return

            if path == "/api/v1/audit" and method == "GET":
                self._send_json({"items": list_audit_logs(conn, actor["tid"])}, 200)
                return

            if path == "/api/v1/audit/verify" and method == "GET":
                self._send_json(verify_audit_chain(conn, actor["tid"]), 200)
                return

            # --- Phase 3: Web & API Security, Cloud IaC, AI Security, Threat Intel, SBOM ---
            if path == "/api/v1/security/assessments" and method == "GET":
                self._send_json({"items": web_api_sec.list_assessments(conn, actor)}, 200)
                return
            if path == "/api/v1/security/web-headers" and method == "POST":
                self._send_json(web_api_sec.audit_web_headers(conn, actor, self._read_json()), 201)
                return
            if path == "/api/v1/security/api-owasp" and method == "POST":
                self._send_json(web_api_sec.audit_api_spec(conn, actor, self._read_json()), 201)
                return
            if path == "/api/v1/security/cloud-iac" and method == "POST":
                self._send_json(cloud_sec.audit_cloud_config(conn, actor, self._read_json()), 201)
                return
            if path == "/api/v1/ai/models":
                if method == "GET":
                    self._send_json({"items": ai_sec.list_ai_models(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(ai_sec.register_ai_model(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/ai/evaluate" and method == "POST":
                self._send_json(ai_sec.evaluate_ai_text(conn, actor, self._read_json()), 201)
                return
            if path == "/api/v1/threat-intel/iocs":
                if method == "GET":
                    self._send_json({"items": threat_intel.list_iocs(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(threat_intel.add_ioc(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/threat-intel/correlate" and method == "GET":
                self._send_json(threat_intel.correlate_iocs(conn, actor), 200)
                return
            if path == "/api/v1/sbom":
                if method == "GET":
                    self._send_json({"items": sbom.list_sboms(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(sbom.analyze_sbom(conn, actor, self._read_json()), 201)
                    return

            # --- Phase 4: Banking Fraud, Gov CERT-In 6h SLA, Defensive Malware Lab, Security Knowledge Graph ---
            if path == "/api/v1/banking/transactions":
                if method == "GET":
                    self._send_json({"items": banking_fraud.list_transactions(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(banking_fraud.analyze_transaction(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/gov/certin-reports":
                if method == "GET":
                    self._send_json({"items": gov_certin.list_certin_reports(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(gov_certin.create_certin_report(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/malware-lab/analyze":
                if method == "GET":
                    self._send_json({"items": malware_lab.list_analyses(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(malware_lab.analyze_static_sample(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/graph/security" and method == "GET":
                self._send_json(knowledge_graph.build_security_graph(conn, actor), 200)
                return

            # --- Phase 5: Lawful OSINT, Privacy-Preserving Sharing, Simulation Labs, Intel Fusion ---
            if path == "/api/v1/osint":
                if method == "GET":
                    self._send_json({"items": osint_intel.list_osint(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(osint_intel.record_osint(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/privacy/shares":
                if method == "GET":
                    self._send_json({"items": privacy_share.list_shares(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(privacy_share.sanitize_and_share(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/labs/runs":
                if method == "GET":
                    self._send_json({"items": sim_labs.list_lab_runs(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(sim_labs.run_simulation_lab(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/intel/fusion" and method == "GET":
                self._send_json(intel_fusion.compute_intel_fusion(conn, actor), 200)
                return

            # --- Phase 6-8: PQC Readiness, Critical Infra Hardware, Adaptive Defense, Global Research Hub ---
            if path == "/api/v1/pqc/inventory":
                if method == "GET":
                    self._send_json(pqc_readiness.list_pqc_inventory(conn, actor), 200)
                    return
                if method == "POST":
                    self._send_json(pqc_readiness.add_pqc_asset(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/infra/hardware":
                if method == "GET":
                    self._send_json({"items": infra_hardware.list_hardware(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(infra_hardware.attest_hardware(conn, actor, self._read_json()), 201)
                    return
            if path == "/api/v1/adaptive/postures" and method == "GET":
                self._send_json({"items": adaptive_defense.list_postures(conn, actor)}, 200)
                return
            if path == "/api/v1/adaptive/evaluate" and method == "POST":
                self._send_json(adaptive_defense.evaluate_adaptive_posture(conn, actor), 201)
                return
            if path == "/api/v1/research/proposals":
                if method == "GET":
                    self._send_json({"items": research_hub.list_proposals(conn, actor)}, 200)
                    return
                if method == "POST":
                    self._send_json(research_hub.submit_proposal(conn, actor, self._read_json()), 201)
                    return

            self._send_json({"error": "Endpoint not found"}, 404)

        except AuthError as exc:
            self._send_json({"error": str(exc)}, exc.status_code)
        except LookupError as exc:
            self._send_json({"error": str(exc)}, 404)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)
        except Exception as exc:
            self._send_json({"error": f"Internal server error: {type(exc).__name__}"}, 500)
        finally:
            conn.close()

    def do_GET(self) -> None:
        self._handle_request("GET")

    def do_POST(self) -> None:
        self._handle_request("POST")

    def do_PATCH(self) -> None:
        self._handle_request("PATCH")


def create_server(host: str = config.HOST, port: int = config.PORT, db_path: Optional[Path] = None) -> ThreadingHTTPServer:
    init_db(db_path)

    class BoundHandler(VajraHandler):
        pass

    BoundHandler.db_path = db_path
    return ThreadingHTTPServer((host, port), BoundHandler)


def main() -> None:
    server = create_server(config.HOST, config.PORT, config.DB_PATH)
    print(f"============================================================")
    print(f"  {config.APP_NAME} v{config.APP_VERSION} — {config.PRODUCT_IDENTITY}")
    print(f"  Running on: http://{config.HOST}:{config.PORT}")
    print(f"  Database:   {config.DB_PATH}")
    print(f"============================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down VAJRAKAVACH 2070 safely...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
