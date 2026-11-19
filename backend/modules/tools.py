import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import ADMIN_ROLES, SECURITY_WRITE_ROLES, require_roles

VALID_APPROVAL_STATUSES = {"research", "tested", "approved", "disabled"}


def list_tools(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM tool_registry WHERE tenant_id = ? ORDER BY name ASC",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def register_tool(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    name = (data.get("name") or "").strip()
    category = (data.get("category") or "").strip()
    vendor = (data.get("vendor") or "").strip()
    official_source = (data.get("official_source") or "").strip()
    license_name = (data.get("license") or "").strip()
    version = (data.get("version") or "unknown").strip()
    platform = (data.get("platform") or "Linux").strip()
    risk_level = (data.get("risk_level") or "medium").strip().lower()
    notes = (data.get("notes") or "").strip()

    if not name or not category or not official_source or not license_name:
        raise ValueError("name, category, official_source, and license are required.")

    now = utc_now()
    # Security policy: newly cataloged tools ALWAYS enter in 'research' status (Catalog != Execution)
    cur = conn.execute(
        """INSERT INTO tool_registry
           (tenant_id, name, category, vendor, official_source, license, version,
            platform, risk_level, sandbox_required, approval_status, notes, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'research', ?, ?)""",
        (actor["tid"], name, category, vendor, official_source, license_name, version, platform, risk_level, notes, now),
    )
    tool_id = cur.lastrowid
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "TOOL_CATALOGED",
        "tool",
        tool_id,
        {"name": name, "license": license_name, "approval_status": "research"},
    )
    conn.commit()
    row = conn.execute("SELECT * FROM tool_registry WHERE id = ? AND tenant_id = ?", (tool_id, actor["tid"])).fetchone()
    return dict(row)


def update_tool_status(conn: sqlite3.Connection, actor: Dict[str, Any], tool_id: int, status: str) -> Dict[str, Any]:
    require_roles(actor, ADMIN_ROLES)
    cleaned = (status or "").strip().lower()
    if cleaned not in VALID_APPROVAL_STATUSES:
        raise ValueError(f"approval_status must be one of: {', '.join(sorted(VALID_APPROVAL_STATUSES))}")

    row = conn.execute(
        "SELECT * FROM tool_registry WHERE id = ? AND tenant_id = ?",
        (tool_id, actor["tid"]),
    ).fetchone()
    if not row:
        raise LookupError("Tool not found in your tenant catalog.")

    now = utc_now()
    conn.execute(
        "UPDATE tool_registry SET approval_status = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
        (cleaned, now, tool_id, actor["tid"]),
    )
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "TOOL_APPROVAL_CHANGED",
        "tool",
        tool_id,
        {"name": row["name"], "from": row["approval_status"], "to": cleaned},
    )
    conn.commit()
    updated = conn.execute("SELECT * FROM tool_registry WHERE id = ? AND tenant_id = ?", (tool_id, actor["tid"])).fetchone()
    return dict(updated)
