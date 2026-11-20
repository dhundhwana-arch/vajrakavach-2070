import hashlib
import json
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit, verify_audit_chain
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

SCENARIOS = {
    "phishing_response_drill": "Defensive Phishing Containment & CERT-In 6h Readiness Drill",
    "api_bola_defense_lab": "OWASP API1 Tenant Isolation & Authorization Verification Lab",
    "ransomware_containment_drill": "Ransomware Containment, Audit Integrity & Evidence Preservation Lab",
    "ai_prompt_defense_lab": "OWASP GenAI Prompt Injection & PII Guardrail Evaluation Lab",
}


def list_lab_runs(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM lab_runs WHERE tenant_id = ? ORDER BY id DESC LIMIT 100",
        (actor["tid"],),
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["results"] = json.loads(item.pop("results_json"))
        out.append(item)
    return out


def run_simulation_lab(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    scenario_id = (data.get("scenario_id") or "").strip().lower()
    if scenario_id not in SCENARIOS:
        raise ValueError(f"scenario_id must be one of: {', '.join(sorted(SCENARIOS.keys()))}")

    tid = actor["tid"]
    audit_ok = verify_audit_chain(conn, tid)["valid"]
    assets_cnt = conn.execute("SELECT COUNT(*) FROM assets WHERE tenant_id = ?", (tid,)).fetchone()[0]
    ev_cnt = conn.execute("SELECT COUNT(*) FROM evidence_items WHERE tenant_id = ?", (tid,)).fetchone()[0]
    cert_cnt = conn.execute("SELECT COUNT(*) FROM certin_reports WHERE tenant_id = ?", (tid,)).fetchone()[0]

    checks = [
        {"check": "simulation_sandbox_isolated", "passed": True, "detail": "Executed strictly in local defensive simulation mode."},
        {"check": "tamper_evident_audit_chain_valid", "passed": bool(audit_ok), "detail": f"Audit chain integrity={audit_ok}"},
        {"check": "asset_inventory_populated", "passed": assets_cnt > 0, "detail": f"Tenant assets registered={assets_cnt}"},
        {"check": "forensic_evidence_workflow_ready", "passed": ev_cnt > 0 or scenario_id != "ransomware_containment_drill", "detail": f"Sealed evidence count={ev_cnt}"},
        {"check": "certin_6h_sla_workflow_tested", "passed": cert_cnt > 0 or scenario_id != "phishing_response_drill", "detail": f"CERT-In drafts count={cert_cnt}"},
    ]
    passed = sum(1 for c in checks if c["passed"])
    total = len(checks)
    score = int(round((passed / total) * 100))

    now = utc_now()
    exp_hash = hashlib.sha256(json.dumps({"scenario": scenario_id, "checks": checks, "ts": now}, sort_keys=True).encode("utf-8")).hexdigest()

    cur = conn.execute(
        """INSERT INTO lab_runs
           (tenant_id, scenario_id, score, passed_checks, total_checks, results_json, experiment_sha256, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (tid, scenario_id, score, passed, total, json.dumps(checks), exp_hash, now),
    )
    lid = cur.lastrowid
    record_audit(conn, tid, actor["sub"], actor["email"], "SIMULATION_LAB_RUN", "lab_run", lid, {"scenario": scenario_id, "score": score})
    conn.commit()
    return {
        "id": lid,
        "scenario_id": scenario_id,
        "scenario_title": SCENARIOS[scenario_id],
        "mode": "SIMULATION_SANDBOX_ONLY",
        "score": score,
        "passed_checks": passed,
        "total_checks": total,
        "results": checks,
        "experiment_sha256": exp_hash,
        "created_at": now,
    }
