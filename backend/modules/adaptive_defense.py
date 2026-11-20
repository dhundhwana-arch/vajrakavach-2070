import json
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit, verify_audit_chain
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles


def list_postures(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM adaptive_postures WHERE tenant_id = ? ORDER BY id DESC LIMIT 50",
        (actor["tid"],),
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["recommended_controls"] = json.loads(item.pop("recommended_controls_json"))
        item["signals"] = json.loads(item.pop("signals_json"))
        out.append(item)
    return out


def evaluate_adaptive_posture(conn: sqlite3.Connection, actor: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    tid = actor["tid"]
    audit_valid = verify_audit_chain(conn, tid)["valid"]
    failed_hw = conn.execute("SELECT COUNT(*) FROM infra_hardware WHERE tenant_id = ? AND attestation_status = 'ATTESTATION_FAILED'", (tid,)).fetchone()[0]
    critical_pqc = conn.execute("SELECT COUNT(*) FROM pqc_inventory WHERE tenant_id = ? AND quantum_risk = 'critical'", (tid,)).fetchone()[0]
    open_cases = conn.execute("SELECT COUNT(*) FROM soc_cases WHERE tenant_id = ? AND status != 'resolved'", (tid,)).fetchone()[0]
    overdue_certin = conn.execute("SELECT COUNT(*) FROM certin_reports WHERE tenant_id = ? AND sla_status = 'overdue'", (tid,)).fetchone()[0]

    risk_index = 0
    controls: List[str] = []

    if not audit_valid:
        risk_index += 45
        controls.append("Freeze non-essential mutations and initiate forensic audit-chain investigation.")
    if failed_hw > 0:
        risk_index += min(35, failed_hw * 25)
        controls.append(f"Isolate {failed_hw} critical hardware node(s) failing firmware SHA-256 attestation.")
    if overdue_certin > 0:
        risk_index += 20
        controls.append("Escalate overdue CERT-In 6-hour incident reporting to CISO/Legal immediately.")
    if open_cases > 0:
        risk_index += min(20, open_cases * 8)
        controls.append("Enforce mandatory TOTP MFA and tighten API rate limits during active SOC cases.")
    if critical_pqc > 0:
        risk_index += min(15, critical_pqc * 10)
        controls.append(f"Decommission {critical_pqc} broken cryptographic algorithm(s) flagged in PQC inventory.")

    risk_index = min(100, risk_index)
    if risk_index >= 75:
        posture = "DEFCON-1 EMERGENCY"
    elif risk_index >= 55:
        posture = "DEFCON-2 CONTAINMENT"
    elif risk_index >= 35:
        posture = "DEFCON-3 HARDENED"
    elif risk_index >= 15:
        posture = "DEFCON-4 ELEVATED"
    else:
        posture = "DEFCON-5 NORMAL"
        controls.append("Maintain baseline Zero-Trust verification and scheduled backup drills.")

    signals = {
        "audit_valid": audit_valid,
        "failed_hardware_attestations": failed_hw,
        "critical_broken_crypto": critical_pqc,
        "open_soc_cases": open_cases,
        "overdue_certin_slas": overdue_certin,
    }
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO adaptive_postures
           (tenant_id, posture_level, risk_index, recommended_controls_json, signals_json, human_approval_required, created_at)
           VALUES (?, ?, ?, ?, ?, 1, ?)""",
        (tid, posture, risk_index, json.dumps(controls), json.dumps(signals), now),
    )
    aid = cur.lastrowid
    record_audit(conn, tid, actor["sub"], actor["email"], "ADAPTIVE_POSTURE_EVALUATED", "adaptive_posture", aid, {"posture": posture, "risk_index": risk_index})
    conn.commit()
    return {
        "id": aid,
        "posture_level": posture,
        "risk_index": risk_index,
        "auto_execute": False,
        "human_approval_required": True,
        "recommended_controls": controls,
        "signals": signals,
        "created_at": now,
    }
