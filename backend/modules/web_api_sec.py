import json
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

REQUIRED_HEADERS = {
    "strict-transport-security": ("high", "Add Strict-Transport-Security (HSTS) header with max-age>=31536000."),
    "content-security-policy": ("high", "Define a restrictive Content-Security-Policy (CSP) to mitigate XSS."),
    "x-content-type-options": ("medium", "Set X-Content-Type-Options: nosniff."),
    "x-frame-options": ("medium", "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking."),
    "referrer-policy": ("low", "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin."),
    "permissions-policy": ("low", "Define Permissions-Policy to restrict browser camera/mic/geo APIs."),
}

SENSITIVE_FIELD_MARKERS = {"password", "passwd", "secret", "token", "ssn", "aadhaar", "pan_number", "credit_card", "cvv"}


def list_assessments(conn: sqlite3.Connection, actor: Dict[str, Any], assessment_type: str = "") -> List[Dict[str, Any]]:
    if assessment_type:
        rows = conn.execute(
            "SELECT * FROM security_assessments WHERE tenant_id = ? AND assessment_type = ? ORDER BY id DESC LIMIT 100",
            (actor["tid"], assessment_type),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM security_assessments WHERE tenant_id = ? ORDER BY id DESC LIMIT 100",
            (actor["tid"],),
        ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["findings"] = json.loads(item.pop("findings_json"))
        out.append(item)
    return out


def audit_web_headers(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    target_name = (data.get("target_name") or "").strip()
    raw_headers = data.get("headers_text") or ""
    if not target_name or not raw_headers.strip():
        raise ValueError("target_name and headers_text are required.")

    parsed: Dict[str, str] = {}
    for line in raw_headers.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            parsed[k.strip().lower()] = v.strip()

    findings: List[Dict[str, str]] = []
    deductions = 0
    weights = {"high": 25, "medium": 15, "low": 10}

    for hdr, (sev, rec) in REQUIRED_HEADERS.items():
        if hdr not in parsed:
            deductions += weights[sev]
            findings.append({"check": hdr, "severity": sev, "status": "missing", "recommendation": rec})

    if "server" in parsed and any(ch.isdigit() for ch in parsed["server"]):
        deductions += 5
        findings.append({
            "check": "server-version-disclosure",
            "severity": "low",
            "status": "exposed",
            "recommendation": f"Remove version banner from Server header ('{parsed['server']}').",
        })

    score = max(0, 100 - deductions)
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO security_assessments
           (tenant_id, assessment_type, target_name, score, findings_json, created_at)
           VALUES (?, 'web_headers', ?, ?, ?, ?)""",
        (actor["tid"], target_name, score, json.dumps(findings), now),
    )
    aid = cur.lastrowid
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "WEB_HEADER_AUDIT", "assessment", aid, {"target": target_name, "score": score})
    conn.commit()
    return {"id": aid, "assessment_type": "web_headers", "target_name": target_name, "score": score, "findings": findings, "created_at": now}


def audit_api_spec(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    target_name = (data.get("target_name") or "").strip()
    endpoint_url = (data.get("endpoint_url") or "").strip()
    auth_scheme = (data.get("auth_scheme") or "none").strip().lower()
    rate_limit_enabled = bool(data.get("rate_limit_enabled", False))
    response_fields = [f.strip().lower() for f in (data.get("response_fields") or "").split(",") if f.strip()]

    if not target_name or not endpoint_url:
        raise ValueError("target_name and endpoint_url are required.")

    findings: List[Dict[str, str]] = []
    deductions = 0

    if endpoint_url.lower().startswith("http://"):
        deductions += 25
        findings.append({"owasp": "API8:2023 Security Misconfiguration", "severity": "high", "issue": "Plaintext HTTP endpoint detected; enforce HTTPS/TLS."})

    if auth_scheme in {"none", "", "basic"}:
        deductions += 30
        findings.append({"owasp": "API2:2023 Broken Authentication", "severity": "critical", "issue": f"Weak or missing authentication scheme ('{auth_scheme or 'none'}'). Use OAuth2/OIDC or signed Bearer tokens."})

    if not rate_limit_enabled:
        deductions += 20
        findings.append({"owasp": "API4:2023 Unrestricted Resource Consumption", "severity": "high", "issue": "Rate limiting is disabled. Enforce per-tenant/per-IP quotas."})

    exposed = sorted(SENSITIVE_FIELD_MARKERS.intersection(set(response_fields)))
    if exposed:
        deductions += 25
        findings.append({"owasp": "API3:2023 Broken Object Property Level Authorization", "severity": "critical", "issue": f"Sensitive fields exposed in response schema: {', '.join(exposed)}."})

    score = max(0, 100 - deductions)
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO security_assessments
           (tenant_id, assessment_type, target_name, score, findings_json, created_at)
           VALUES (?, 'api_owasp', ?, ?, ?, ?)""",
        (actor["tid"], target_name, score, json.dumps(findings), now),
    )
    aid = cur.lastrowid
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "API_OWASP_AUDIT", "assessment", aid, {"target": target_name, "score": score})
    conn.commit()
    return {"id": aid, "assessment_type": "api_owasp", "target_name": target_name, "score": score, "findings": findings, "created_at": now}
