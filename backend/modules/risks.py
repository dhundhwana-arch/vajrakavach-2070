import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles


def _score_to_severity(score: int) -> str:
    if score >= 16:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


def list_risks(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """SELECT r.*, a.name AS asset_name
           FROM risks r
           LEFT JOIN assets a ON a.id = r.asset_id AND a.tenant_id = r.tenant_id
           WHERE r.tenant_id = ?
           ORDER BY r.risk_score DESC, r.id DESC""",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def create_risk(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    mitigation_plan = (data.get("mitigation_plan") or "").strip()
    asset_id = data.get("asset_id")

    try:
        likelihood = int(data.get("likelihood", 3))
        impact = int(data.get("impact", 3))
    except (TypeError, ValueError) as exc:
        raise ValueError("likelihood and impact must be integers between 1 and 5.") from exc

    if not title:
        raise ValueError("Risk title is required.")
    if not (1 <= likelihood <= 5 and 1 <= impact <= 5):
        raise ValueError("likelihood and impact must be between 1 and 5.")

    if asset_id is not None and str(asset_id).strip() != "":
        asset_id = int(asset_id)
        found = conn.execute(
            "SELECT id FROM assets WHERE id = ? AND tenant_id = ?",
            (asset_id, actor["tid"]),
        ).fetchone()
        if not found:
            raise ValueError("Referenced asset not found in your tenant.")
    else:
        asset_id = None

    risk_score = likelihood * impact
    severity = _score_to_severity(risk_score)
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO risks
           (tenant_id, asset_id, title, description, likelihood, impact, risk_score, severity, status, mitigation_plan, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
        (actor["tid"], asset_id, title, description, likelihood, impact, risk_score, severity, mitigation_plan, now),
    )
    risk_id = cur.lastrowid
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "RISK_CREATED",
        "risk",
        risk_id,
        {"title": title, "risk_score": risk_score, "severity": severity},
    )
    conn.commit()
    row = conn.execute("SELECT * FROM risks WHERE id = ? AND tenant_id = ?", (risk_id, actor["tid"])).fetchone()
    return dict(row)
