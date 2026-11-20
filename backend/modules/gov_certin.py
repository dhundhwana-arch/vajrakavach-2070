import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

CERTIN_CATEGORIES = {
    "targeted_scanning",
    "compromise_critical_system",
    "unauthorized_access",
    "defacement",
    "ransomware_malware",
    "data_breach",
    "fake_mobile_app",
    "identity_theft_phishing",
}


def list_certin_reports(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM certin_reports WHERE tenant_id = ? ORDER BY id DESC LIMIT 100",
        (actor["tid"],),
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["report_draft"] = json.loads(item.pop("report_draft_json"))
        out.append(item)
    return out


def create_certin_report(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    category = (data.get("incident_category") or "unauthorized_access").strip().lower()
    affected_service = (data.get("affected_service") or "").strip()
    summary = (data.get("summary") or "").strip()
    detected_raw = (data.get("detected_at") or "").strip()

    if not affected_service or not summary:
        raise ValueError("affected_service and summary are required.")
    if category not in CERTIN_CATEGORIES:
        raise ValueError(f"incident_category must be one of: {', '.join(sorted(CERTIN_CATEGORIES))}")

    now_dt = datetime.now(timezone.utc)
    if detected_raw:
        try:
            detected_dt = datetime.fromisoformat(detected_raw.replace("Z", "+00:00"))
            if detected_dt.tzinfo is None:
                detected_dt = detected_dt.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError("detected_at must be an ISO-8601 UTC timestamp (e.g. 2026-11-20T04:00:00Z).") from exc
    else:
        detected_dt = now_dt

    deadline_dt = detected_dt + timedelta(hours=6)
    remaining_minutes = int((deadline_dt - now_dt).total_seconds() // 60)
    if remaining_minutes < 0:
        sla_status = "overdue"
    elif remaining_minutes <= 60:
        sla_status = "urgent_under_60m"
    else:
        sla_status = "on_track"

    detected_str = detected_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    deadline_str = deadline_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    now_str = utc_now()

    draft = {
        "framework": "CERT-In Directions (28 April 2022) — 6-Hour Reporting Window",
        "incident_category": category,
        "affected_service": affected_service,
        "detected_at_utc": detected_str,
        "mandatory_6h_deadline_utc": deadline_str,
        "remaining_minutes": remaining_minutes,
        "reporter_email": actor["email"],
        "summary": summary,
        "human_verification_required": True,
    }

    cur = conn.execute(
        """INSERT INTO certin_reports
           (tenant_id, incident_category, affected_service, detected_at, deadline_utc,
            sla_status, summary, report_draft_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], category, affected_service, detected_str, deadline_str, sla_status, summary, json.dumps(draft), now_str),
    )
    rid = cur.lastrowid
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "CERTIN_REPORT_DRAFTED",
        "certin_report",
        rid,
        {"category": category, "sla_status": sla_status, "deadline_utc": deadline_str},
    )
    conn.commit()
    return {
        "id": rid,
        "incident_category": category,
        "affected_service": affected_service,
        "detected_at": detected_str,
        "deadline_utc": deadline_str,
        "sla_status": sla_status,
        "remaining_minutes": remaining_minutes,
        "report_draft": draft,
        "created_at": now_str,
    }
