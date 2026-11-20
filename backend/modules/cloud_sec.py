import json
import re
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

IAC_RULES = [
    (
        "public_bucket",
        "critical",
        re.compile(r'public-read|allUsers|"Principal"\s*:\s*"\*"', re.I),
        "Public storage bucket or wildcard principal detected; restrict to least-privilege IAM.",
    ),
    (
        "wildcard_iam",
        "high",
        re.compile(r'"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"', re.I),
        "Wildcard IAM policy detected; scope actions and resources explicitly.",
    ),
    (
        "open_cidr_mgmt_port",
        "critical",
        re.compile(r"0\.0\.0\.0/0.{0,60}(22|3389|3306|5432|27017)|(22|3389|3306|5432|27017).{0,60}0\.0\.0\.0/0", re.I | re.S),
        "Management/DB port exposed to 0.0.0.0/0; restrict CIDR or place behind private VPC.",
    ),
    (
        "docker_root_user",
        "medium",
        re.compile(r"^\s*USER\s+root\b", re.I | re.M),
        "Container runs as root; switch to a non-root user.",
    ),
    (
        "hardcoded_secret",
        "critical",
        re.compile(r"""(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|BEGIN\s+(RSA\s+)?PRIVATE\s+KEY|(password|secret_key|api_key)\s*[:=]\s*['"][^'"]{6,}['"])""", re.I),
        "Potential hardcoded secret or private key detected in config; move to secrets manager.",
    ),
]


def audit_cloud_config(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    target_name = (data.get("target_name") or "").strip()
    config_text = data.get("config_text") or ""
    if not target_name or not config_text.strip():
        raise ValueError("target_name and config_text are required.")

    findings: List[Dict[str, str]] = []
    deductions = 0
    weights = {"critical": 30, "high": 20, "medium": 10}

    for rule_id, sev, pattern, rec in IAC_RULES:
        if pattern.search(config_text):
            deductions += weights[sev]
            findings.append({"rule_id": rule_id, "severity": sev, "recommendation": rec})

    score = max(0, 100 - deductions)
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO security_assessments
           (tenant_id, assessment_type, target_name, score, findings_json, created_at)
           VALUES (?, 'cloud_iac', ?, ?, ?, ?)""",
        (actor["tid"], target_name, score, json.dumps(findings), now),
    )
    aid = cur.lastrowid
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "CLOUD_IAC_AUDIT",
        "assessment",
        aid,
        {"target": target_name, "score": score, "issues": len(findings)},
    )
    conn.commit()
    return {
        "id": aid,
        "assessment_type": "cloud_iac",
        "target_name": target_name,
        "score": score,
        "findings": findings,
        "created_at": now,
    }
