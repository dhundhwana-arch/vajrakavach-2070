import json
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import APPROVAL_ROLES, SECURITY_WRITE_ROLES, require_roles

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_CASE_STATUSES = {"open", "investigating", "contained", "resolved"}


def list_events(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM security_events WHERE tenant_id = ? ORDER BY id DESC LIMIT 200",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def ingest_event(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    source = (data.get("source") or "manual_soc").strip()
    event_type = (data.get("event_type") or "security_alert").strip()
    severity = (data.get("severity") or "medium").strip().lower()
    mitre_tactic = (data.get("mitre_tactic") or "Initial Access").strip()
    summary = (data.get("summary") or "").strip()
    raw_metadata = json.dumps(data.get("raw_metadata") or {}, sort_keys=True)
    asset_id = data.get("asset_id")

    if not summary:
        raise ValueError("Event summary is required.")
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}")

    if asset_id is not None and str(asset_id).strip() != "":
        asset_id = int(asset_id)
        if not conn.execute("SELECT id FROM assets WHERE id = ? AND tenant_id = ?", (asset_id, actor["tid"])).fetchone():
            raise ValueError("Referenced asset not found in your tenant.")
    else:
        asset_id = None

    now = utc_now()
    cur = conn.execute(
        """INSERT INTO security_events
           (tenant_id, asset_id, source, event_type, severity, mitre_tactic, summary, raw_metadata, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], asset_id, source, event_type, severity, mitre_tactic, summary, raw_metadata, now),
    )
    event_id = cur.lastrowid

    correlated_case_id = None
    # Automatic defensive correlation: critical/high events automatically open a reviewable SOC case
    if severity in {"critical", "high"}:
        case_cur = conn.execute(
            """INSERT INTO soc_cases
               (tenant_id, title, severity, status, related_event_id, assigned_to, analyst_notes, created_at)
               VALUES (?, ?, ?, 'open', ?, ?, ?, ?)""",
            (
                actor["tid"],
                f"[Auto-Correlated] {event_type}: {summary[:80]}",
                severity,
                event_id,
                actor["email"],
                "Automatically escalated by deterministic SOC rule. Human review required before containment/closure.",
                now,
            ),
        )
        correlated_case_id = case_cur.lastrowid

    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "SOC_EVENT_INGESTED",
        "security_event",
        event_id,
        {"severity": severity, "mitre_tactic": mitre_tactic, "correlated_case_id": correlated_case_id},
    )
    conn.commit()
    row = conn.execute("SELECT * FROM security_events WHERE id = ? AND tenant_id = ?", (event_id, actor["tid"])).fetchone()
    result = dict(row)
    result["correlated_case_id"] = correlated_case_id
    return result


def list_cases(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM soc_cases WHERE tenant_id = ? ORDER BY id DESC",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def update_case_status(conn: sqlite3.Connection, actor: Dict[str, Any], case_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, APPROVAL_ROLES)
    status = (data.get("status") or "").strip().lower()
    notes = (data.get("analyst_notes") or "").strip()
    if status not in VALID_CASE_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(sorted(VALID_CASE_STATUSES))}")

    row = conn.execute(
        "SELECT * FROM soc_cases WHERE id = ? AND tenant_id = ?",
        (case_id, actor["tid"]),
    ).fetchone()
    if not row:
        raise LookupError("SOC case not found in your tenant.")

    now = utc_now()
    conn.execute(
        """UPDATE soc_cases
           SET status = ?, human_approved_by = ?, human_approved_at = ?,
               analyst_notes = CASE WHEN ? != '' THEN ? ELSE analyst_notes END
           WHERE id = ? AND tenant_id = ?""",
        (status, actor["email"], now, notes, notes, case_id, actor["tid"]),
    )
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "SOC_CASE_HUMAN_APPROVED_UPDATE",
        "soc_case",
        case_id,
        {"status": status, "approved_by": actor["email"]},
    )
    conn.commit()
    updated = conn.execute("SELECT * FROM soc_cases WHERE id = ? AND tenant_id = ?", (case_id, actor["tid"])).fetchone()
    return dict(updated)
