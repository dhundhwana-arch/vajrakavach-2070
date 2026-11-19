import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

VALID_ASSET_TYPES = {"server", "endpoint", "cloud", "domain", "api", "database", "ai_model", "network"}
VALID_CRITICALITY = {"critical", "high", "medium", "low"}


def list_assets(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM assets WHERE tenant_id = ? ORDER BY id DESC",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def create_asset(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    name = (data.get("name") or "").strip()
    asset_type = (data.get("asset_type") or "server").strip().lower()
    owner = (data.get("owner") or actor["email"]).strip()
    environment = (data.get("environment") or "production").strip().lower()
    criticality = (data.get("criticality") or "medium").strip().lower()
    ip_or_uri = (data.get("ip_or_uri") or "").strip()
    nist_function = (data.get("nist_function") or "Identify").strip()

    if not name:
        raise ValueError("Asset name is required.")
    if asset_type not in VALID_ASSET_TYPES:
        raise ValueError(f"asset_type must be one of: {', '.join(sorted(VALID_ASSET_TYPES))}")
    if criticality not in VALID_CRITICALITY:
        raise ValueError(f"criticality must be one of: {', '.join(sorted(VALID_CRITICALITY))}")

    now = utc_now()
    cur = conn.execute(
        """INSERT INTO assets
           (tenant_id, name, asset_type, owner, environment, criticality, ip_or_uri, nist_function, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)""",
        (actor["tid"], name, asset_type, owner, environment, criticality, ip_or_uri, nist_function, now),
    )
    asset_id = cur.lastrowid
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "ASSET_CREATED",
        "asset",
        asset_id,
        {"name": name, "asset_type": asset_type, "criticality": criticality},
    )
    conn.commit()
    row = conn.execute("SELECT * FROM assets WHERE id = ? AND tenant_id = ?", (asset_id, actor["tid"])).fetchone()
    return dict(row)
