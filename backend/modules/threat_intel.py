import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

VALID_IOC_TYPES = {"ip", "domain", "sha256", "url", "cve"}


def list_iocs(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute("SELECT * FROM threat_iocs WHERE tenant_id = ? ORDER BY id DESC LIMIT 200", (actor["tid"],)).fetchall()
    return [dict(r) for r in rows]


def add_ioc(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    ioc_type = (data.get("ioc_type") or "ip").strip().lower()
    indicator = (data.get("indicator") or "").strip()
    mitre_tactic = (data.get("mitre_tactic") or "Command and Control").strip()
    source_reliability = (data.get("source_reliability") or "B").strip().upper()
    source_name = (data.get("source_name") or "public_advisory").strip()
    expires_at = (data.get("expires_at") or "").strip()
    try:
        confidence = max(0, min(100, int(data.get("confidence", 80))))
    except (TypeError, ValueError) as exc:
        raise ValueError("confidence must be an integer between 0 and 100.") from exc

    if ioc_type not in VALID_IOC_TYPES:
        raise ValueError(f"ioc_type must be one of: {', '.join(sorted(VALID_IOC_TYPES))}")
    if not indicator:
        raise ValueError("indicator value is required.")

    now = utc_now()
    cur = conn.execute(
        """INSERT INTO threat_iocs
           (tenant_id, ioc_type, indicator, mitre_tactic, confidence, source_reliability, source_name, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], ioc_type, indicator, mitre_tactic, confidence, source_reliability, source_name, expires_at, now),
    )
    iid = cur.lastrowid
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "THREAT_IOC_ADDED", "threat_ioc", iid, {"ioc_type": ioc_type, "indicator": indicator})
    conn.commit()
    row = conn.execute("SELECT * FROM threat_iocs WHERE id = ? AND tenant_id = ?", (iid, actor["tid"])).fetchone()
    return dict(row)


def correlate_iocs(conn: sqlite3.Connection, actor: Dict[str, Any]) -> Dict[str, Any]:
    iocs = conn.execute("SELECT * FROM threat_iocs WHERE tenant_id = ?", (actor["tid"],)).fetchall()
    events = conn.execute("SELECT id, summary, raw_metadata, severity, created_at FROM security_events WHERE tenant_id = ?", (actor["tid"],)).fetchall()
    assets = conn.execute("SELECT id, name, ip_or_uri, criticality FROM assets WHERE tenant_id = ?", (actor["tid"],)).fetchall()

    matches: List[Dict[str, Any]] = []
    for ioc in iocs:
        needle = ioc["indicator"].lower()
        for ev in events:
            haystack = f"{ev['summary']} {ev['raw_metadata']}".lower()
            if needle in haystack:
                matches.append({
                    "match_target": "security_event",
                    "target_id": ev["id"],
                    "ioc_id": ioc["id"],
                    "ioc_type": ioc["ioc_type"],
                    "indicator": ioc["indicator"],
                    "mitre_tactic": ioc["mitre_tactic"],
                    "confidence": ioc["confidence"],
                })
        for asset in assets:
            haystack = f"{asset['name']} {asset['ip_or_uri']}".lower()
            if needle in haystack:
                matches.append({
                    "match_target": "asset",
                    "target_id": asset["id"],
                    "ioc_id": ioc["id"],
                    "ioc_type": ioc["ioc_type"],
                    "indicator": ioc["indicator"],
                    "mitre_tactic": ioc["mitre_tactic"],
                    "confidence": ioc["confidence"],
                })
    return {"checked_iocs": len(iocs), "matches_found": len(matches), "matches": matches}
