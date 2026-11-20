import hashlib
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

LAWFUL_CLASSIFICATIONS = {"public", "licensed"}


def list_osint(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM osint_records WHERE tenant_id = ? ORDER BY id DESC LIMIT 100",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def record_osint(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    subject = (data.get("subject") or "").strip()
    classification = (data.get("classification") or "public").strip().lower()
    source_url = (data.get("source_url") or "").strip()
    source_reliability = (data.get("source_reliability") or "B").strip().upper()
    content_excerpt = (data.get("content_excerpt") or "").strip()

    if not subject or not source_url or not content_excerpt:
        raise ValueError("subject, source_url, and content_excerpt are required.")
    if classification not in LAWFUL_CLASSIFICATIONS:
        raise ValueError("Lawful OSINT policy: classification must be 'public' or 'licensed' (private/restricted scraping is prohibited).")

    normalized = " ".join(content_excerpt.lower().split())
    dedup_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    existing = conn.execute(
        "SELECT id FROM osint_records WHERE tenant_id = ? AND dedup_hash = ? ORDER BY id ASC LIMIT 1",
        (actor["tid"], dedup_hash),
    ).fetchone()
    duplicate_of_id = existing["id"] if existing else None

    now = utc_now()
    cur = conn.execute(
        """INSERT INTO osint_records
           (tenant_id, subject, classification, source_url, source_reliability,
            content_excerpt, dedup_hash, duplicate_of_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], subject, classification, source_url, source_reliability, content_excerpt, dedup_hash, duplicate_of_id, now),
    )
    oid = cur.lastrowid
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "LAWFUL_OSINT_RECORDED",
        "osint_record",
        oid,
        {"subject": subject, "classification": classification, "duplicate_of_id": duplicate_of_id},
    )
    conn.commit()
    return {
        "id": oid,
        "subject": subject,
        "classification": classification,
        "source_url": source_url,
        "source_reliability": source_reliability,
        "dedup_hash": dedup_hash,
        "duplicate_detected": duplicate_of_id is not None,
        "duplicate_of_id": duplicate_of_id,
        "created_at": now,
    }
