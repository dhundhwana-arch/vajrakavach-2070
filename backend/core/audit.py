import hashlib
import json
import sqlite3
from typing import Any, Dict, List, Optional

from backend.core.db import utc_now

GENESIS_HASH = "0" * 64


def _compute_entry_hash(
    prev_hash: str,
    tenant_id: int,
    actor_email: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details_json: str,
    created_at: str,
) -> str:
    canonical = json.dumps(
        {
            "prev_hash": prev_hash,
            "tenant_id": tenant_id,
            "actor_email": actor_email,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details_json": details_json,
            "created_at": created_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_audit(
    conn: sqlite3.Connection,
    tenant_id: int,
    actor_user_id: Optional[int],
    actor_email: str,
    action: str,
    resource_type: str,
    resource_id: Any,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    row = conn.execute(
        "SELECT entry_hash FROM audit_logs WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
        (tenant_id,),
    ).fetchone()
    prev_hash = row["entry_hash"] if row else GENESIS_HASH
    created_at = utc_now()
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    res_id_str = str(resource_id)
    entry_hash = _compute_entry_hash(
        prev_hash,
        tenant_id,
        actor_email,
        action,
        resource_type,
        res_id_str,
        details_json,
        created_at,
    )
    cur = conn.execute(
        """INSERT INTO audit_logs
           (tenant_id, actor_user_id, actor_email, action, resource_type,
            resource_id, details_json, prev_hash, entry_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            tenant_id,
            actor_user_id,
            actor_email,
            action,
            resource_type,
            res_id_str,
            details_json,
            prev_hash,
            entry_hash,
            created_at,
        ),
    )
    return {"id": cur.lastrowid, "entry_hash": entry_hash, "created_at": created_at}


def list_audit_logs(conn: sqlite3.Connection, tenant_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """SELECT id, actor_email, action, resource_type, resource_id,
                  details_json, prev_hash, entry_hash, created_at
           FROM audit_logs
           WHERE tenant_id = ?
           ORDER BY id DESC LIMIT ?""",
        (tenant_id, min(limit, 500)),
    ).fetchall()
    return [dict(r) for r in rows]


def verify_audit_chain(conn: sqlite3.Connection, tenant_id: int) -> Dict[str, Any]:
    rows = conn.execute(
        """SELECT id, tenant_id, actor_email, action, resource_type,
                  resource_id, details_json, prev_hash, entry_hash, created_at
           FROM audit_logs
           WHERE tenant_id = ?
           ORDER BY id ASC""",
        (tenant_id,),
    ).fetchall()
    expected_prev = GENESIS_HASH
    for r in rows:
        if r["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "checked_entries": len(rows),
                "broken_at_id": r["id"],
                "reason": "prev_hash_mismatch",
            }
        recomputed = _compute_entry_hash(
            r["prev_hash"],
            r["tenant_id"],
            r["actor_email"],
            r["action"],
            r["resource_type"],
            r["resource_id"],
            r["details_json"],
            r["created_at"],
        )
        if recomputed != r["entry_hash"]:
            return {
                "valid": False,
                "checked_entries": len(rows),
                "broken_at_id": r["id"],
                "reason": "entry_hash_tampered",
            }
        expected_prev = r["entry_hash"]
    return {
        "valid": True,
        "checked_entries": len(rows),
        "latest_hash": expected_prev if rows else GENESIS_HASH,
    }
