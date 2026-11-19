import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit, verify_audit_chain
from backend.core.db import utc_now
from backend.core.security import ADMIN_ROLES, require_roles

VALID_CONTROL_STATUSES = {"implemented", "in_progress", "planned"}


def list_controls(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM compliance_controls WHERE tenant_id = ? ORDER BY framework ASC, control_code ASC",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def update_control(conn: sqlite3.Connection, actor: Dict[str, Any], control_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, ADMIN_ROLES)
    status = (data.get("status") or "").strip().lower()
    evidence_ref = (data.get("evidence_ref") or "").strip()
    if status not in VALID_CONTROL_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(sorted(VALID_CONTROL_STATUSES))}")
    row = conn.execute(
        "SELECT * FROM compliance_controls WHERE id = ? AND tenant_id = ?",
        (control_id, actor["tid"]),
    ).fetchone()
    if not row:
        raise LookupError("Compliance control not found in your tenant.")
    conn.execute(
        "UPDATE compliance_controls SET status = ?, evidence_ref = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
        (status, evidence_ref or row["evidence_ref"], utc_now(), control_id, actor["tid"]),
    )
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "COMPLIANCE_CONTROL_UPDATED",
        "compliance_control",
        control_id,
        {"control_code": row["control_code"], "status": status},
    )
    conn.commit()
    updated = conn.execute(
        "SELECT * FROM compliance_controls WHERE id = ? AND tenant_id = ?",
        (control_id, actor["tid"]),
    ).fetchone()
    return dict(updated)


def dashboard_summary(conn: sqlite3.Connection, actor: Dict[str, Any]) -> Dict[str, Any]:
    tid = actor["tid"]
    assets_count = conn.execute("SELECT COUNT(*) FROM assets WHERE tenant_id = ?", (tid,)).fetchone()[0]
    risks_open = conn.execute("SELECT COUNT(*) FROM risks WHERE tenant_id = ? AND status = 'open'", (tid,)).fetchone()[0]
    risks_critical = conn.execute(
        "SELECT COUNT(*) FROM risks WHERE tenant_id = ? AND severity IN ('critical', 'high') AND status = 'open'",
        (tid,),
    ).fetchone()[0]
    events_count = conn.execute("SELECT COUNT(*) FROM security_events WHERE tenant_id = ?", (tid,)).fetchone()[0]
    cases_open = conn.execute("SELECT COUNT(*) FROM soc_cases WHERE tenant_id = ? AND status != 'resolved'", (tid,)).fetchone()[0]
    evidence_count = conn.execute("SELECT COUNT(*) FROM evidence_items WHERE tenant_id = ?", (tid,)).fetchone()[0]
    tools_total = conn.execute("SELECT COUNT(*) FROM tool_registry WHERE tenant_id = ?", (tid,)).fetchone()[0]
    tools_approved = conn.execute(
        "SELECT COUNT(*) FROM tool_registry WHERE tenant_id = ? AND approval_status = 'approved'",
        (tid,),
    ).fetchone()[0]
    controls_total = conn.execute("SELECT COUNT(*) FROM compliance_controls WHERE tenant_id = ?", (tid,)).fetchone()[0]
    controls_impl = conn.execute(
        "SELECT COUNT(*) FROM compliance_controls WHERE tenant_id = ? AND status = 'implemented'",
        (tid,),
    ).fetchone()[0]
    audit_status = verify_audit_chain(conn, tid)

    return {
        "assets_total": assets_count,
        "risks_open": risks_open,
        "risks_high_critical": risks_critical,
        "events_total": events_count,
        "cases_open": cases_open,
        "evidence_sealed": evidence_count,
        "tools_cataloged": tools_total,
        "tools_approved": tools_approved,
        "compliance_implemented": controls_impl,
        "compliance_total": controls_total,
        "audit_chain": audit_status,
    }
