import hashlib
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import FORENSICS_WRITE_ROLES, require_roles


def list_evidence(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """SELECT id, tenant_id, case_id, title, source, acquisition_method,
                  collector_user_id, sha256_hash, sha512_hash, created_at
           FROM evidence_items
           WHERE tenant_id = ?
           ORDER BY id DESC""",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def intake_evidence(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, FORENSICS_WRITE_ROLES)
    title = (data.get("title") or "").strip()
    source = (data.get("source") or "").strip()
    acquisition_method = (data.get("acquisition_method") or "authorized_export").strip()
    content_payload = data.get("content_payload") or ""
    case_id = data.get("case_id")

    if not title or not source or not content_payload:
        raise ValueError("title, source, and content_payload are required.")

    if case_id is not None and str(case_id).strip() != "":
        case_id = int(case_id)
        if not conn.execute("SELECT id FROM soc_cases WHERE id = ? AND tenant_id = ?", (case_id, actor["tid"])).fetchone():
            raise ValueError("Referenced SOC case not found in your tenant.")
    else:
        case_id = None

    raw_bytes = content_payload.encode("utf-8")
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    sha512_hash = hashlib.sha512(raw_bytes).hexdigest()
    now = utc_now()

    cur = conn.execute(
        """INSERT INTO evidence_items
           (tenant_id, case_id, title, source, acquisition_method, collector_user_id,
            content_payload, sha256_hash, sha512_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], case_id, title, source, acquisition_method, actor["sub"], content_payload, sha256_hash, sha512_hash, now),
    )
    ev_id = cur.lastrowid
    conn.execute(
        """INSERT INTO evidence_custody_events
           (tenant_id, evidence_id, actor_user_id, action, notes, created_at)
           VALUES (?, ?, ?, 'INTAKE_SEALED', ?, ?)""",
        (actor["tid"], ev_id, actor["sub"], f"Original sealed via {acquisition_method}. SHA-256={sha256_hash}", now),
    )
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "EVIDENCE_SEALED",
        "evidence",
        ev_id,
        {"title": title, "sha256_hash": sha256_hash},
    )
    conn.commit()
    return {
        "id": ev_id,
        "title": title,
        "source": source,
        "acquisition_method": acquisition_method,
        "sha256_hash": sha256_hash,
        "sha512_hash": sha512_hash,
        "created_at": now,
    }


def verify_evidence(conn: sqlite3.Connection, actor: Dict[str, Any], evidence_id: int) -> Dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM evidence_items WHERE id = ? AND tenant_id = ?",
        (evidence_id, actor["tid"]),
    ).fetchone()
    if not row:
        raise LookupError("Evidence item not found in your tenant.")

    raw_bytes = row["content_payload"].encode("utf-8")
    recomputed_256 = hashlib.sha256(raw_bytes).hexdigest()
    recomputed_512 = hashlib.sha512(raw_bytes).hexdigest()
    intact = (recomputed_256 == row["sha256_hash"]) and (recomputed_512 == row["sha512_hash"])

    now = utc_now()
    conn.execute(
        """INSERT INTO evidence_custody_events
           (tenant_id, evidence_id, actor_user_id, action, notes, created_at)
           VALUES (?, ?, ?, 'INTEGRITY_VERIFIED', ?, ?)""",
        (actor["tid"], evidence_id, actor["sub"], f"Hash verification intact={intact}", now),
    )
    conn.commit()

    custody = conn.execute(
        """SELECT c.id, c.action, c.notes, c.created_at, u.email AS actor_email
           FROM evidence_custody_events c
           JOIN users u ON u.id = c.actor_user_id
           WHERE c.evidence_id = ? AND c.tenant_id = ?
           ORDER BY c.id ASC""",
        (evidence_id, actor["tid"]),
    ).fetchall()

    return {
        "evidence_id": evidence_id,
        "title": row["title"],
        "intact": intact,
        "stored_sha256": row["sha256_hash"],
        "computed_sha256": recomputed_256,
        "chain_of_custody": [dict(c) for c in custody],
    }
