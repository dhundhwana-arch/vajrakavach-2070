import hashlib
import json
import re
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

VALID_TLP = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"}

REDACTION_RULES = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    ("indian_pan", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), "[REDACTED_PAN]"),
    ("aadhaar_12digit", re.compile(r"\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"), "[REDACTED_ID]"),
    ("phone_in", re.compile(r"\b(?:\+91[\s-]?)?[6-9][0-9]{9}\b"), "[REDACTED_PHONE]"),
    ("private_ipv4", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), "[REDACTED_INTERNAL_IP]"),
]


def list_shares(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM privacy_shares WHERE tenant_id = ? ORDER BY id DESC LIMIT 100",
        (actor["tid"],),
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["redactions"] = json.loads(item.pop("redactions_json"))
        out.append(item)
    return out


def sanitize_and_share(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    title = (data.get("title") or "").strip()
    tlp_level = (data.get("tlp_level") or "TLP:GREEN").strip().upper()
    raw_payload = data.get("raw_payload") or ""

    if not title or not raw_payload.strip():
        raise ValueError("title and raw_payload are required.")
    if tlp_level not in VALID_TLP:
        raise ValueError(f"tlp_level must be one of: {', '.join(sorted(VALID_TLP))}")

    sanitized = raw_payload
    redactions: Dict[str, int] = {}
    for label, pat, repl in REDACTION_RULES:
        sanitized, count = pat.subn(repl, sanitized)
        if count > 0:
            redactions[label] = count

    package_sha256 = hashlib.sha256(f"{tlp_level}|{sanitized}".encode("utf-8")).hexdigest()
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO privacy_shares
           (tenant_id, title, tlp_level, sanitized_payload, redactions_json, package_sha256, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], title, tlp_level, sanitized, json.dumps(redactions), package_sha256, now),
    )
    sid = cur.lastrowid
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "PRIVACY_SHARE_SANITIZED",
        "privacy_share",
        sid,
        {"title": title, "tlp_level": tlp_level, "redacted_categories": list(redactions.keys())},
    )
    conn.commit()
    return {
        "id": sid,
        "title": title,
        "tlp_level": tlp_level,
        "sanitized_payload": sanitized,
        "redactions": redactions,
        "package_sha256": package_sha256,
        "created_at": now,
    }
