import hashlib
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

VALID_MATURITY = {"hypothesis", "prototype", "peer_reviewed", "production_standard"}


def list_proposals(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM research_proposals WHERE tenant_id = ? ORDER BY id DESC LIMIT 100",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def submit_proposal(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    title = (data.get("title") or "").strip()
    domain = (data.get("domain") or "PQC").strip()
    horizon = (data.get("horizon") or "2041-2070").strip()
    maturity = (data.get("maturity_stage") or "hypothesis").strip().lower()
    summary = (data.get("summary") or "").strip()
    reference_url = (data.get("reference_url") or "").strip()

    if not title or not summary:
        raise ValueError("title and summary are required.")
    if maturity not in VALID_MATURITY:
        raise ValueError(f"maturity_stage must be one of: {', '.join(sorted(VALID_MATURITY))}")

    now = utc_now()
    prov_hash = hashlib.sha256(f"{title}|{domain}|{maturity}|{summary}|{now}".encode("utf-8")).hexdigest()

    cur = conn.execute(
        """INSERT INTO research_proposals
           (tenant_id, title, domain, horizon, maturity_stage, summary, reference_url, provenance_sha256, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], title, domain, horizon, maturity, summary, reference_url, prov_hash, now),
    )
    rid = cur.lastrowid
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "RESEARCH_PROPOSAL_RECORDED", "research_proposal", rid, {"title": title, "maturity": maturity})
    conn.commit()
    return {
        "id": rid,
        "title": title,
        "domain": domain,
        "horizon": horizon,
        "maturity_stage": maturity,
        "summary": summary,
        "reference_url": reference_url,
        "provenance_sha256": prov_hash,
        "created_at": now,
    }
