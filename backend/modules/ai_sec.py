import json
import re
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

INJECTION_PATTERNS = [
    ("instruction_override", re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I)),
    ("system_prompt_exfil", re.compile(r"(reveal|print|show|dump)\s+(your\s+)?(system\s+prompt|hidden\s+instructions)", re.I)),
    ("safety_bypass", re.compile(r"(bypass|disable|jailbreak)\s+(safety|guardrails|filters|policy)", re.I)),
    ("unrestricted_exec", re.compile(r"(execute|run)\s+(arbitrary|unrestricted)\s+(shell|bash|sql|command)", re.I)),
]

PII_PATTERNS = [
    ("indian_pan", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("aadhaar_like_12digit", re.compile(r"\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b")),
    ("api_token_leak", re.compile(r"\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b")),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]


def list_ai_models(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute("SELECT * FROM ai_models WHERE tenant_id = ? ORDER BY id DESC", (actor["tid"],)).fetchall()
    return [dict(r) for r in rows]


def register_ai_model(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    name = (data.get("name") or "").strip()
    provider = (data.get("provider") or "internal").strip()
    risk_tier = (data.get("risk_tier") or "medium").strip().lower()
    rag_enabled = 1 if data.get("rag_enabled") else 0
    human_approval = 1 if data.get("human_approval_required", True) else 0
    allowed_tools = (data.get("allowed_tools") or "none").strip()

    if not name:
        raise ValueError("AI model name is required.")

    now = utc_now()
    cur = conn.execute(
        """INSERT INTO ai_models
           (tenant_id, name, provider, risk_tier, rag_enabled, human_approval_required, allowed_tools, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], name, provider, risk_tier, rag_enabled, human_approval, allowed_tools, now),
    )
    mid = cur.lastrowid
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "AI_MODEL_REGISTERED", "ai_model", mid, {"name": name, "risk_tier": risk_tier})
    conn.commit()
    row = conn.execute("SELECT * FROM ai_models WHERE id = ? AND tenant_id = ?", (mid, actor["tid"])).fetchone()
    return dict(row)


def evaluate_ai_text(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    model_name = (data.get("model_name") or "general-llm").strip()
    sample_text = data.get("sample_text") or ""
    if not sample_text.strip():
        raise ValueError("sample_text is required for AI security evaluation.")

    inj_hits = [name for name, pat in INJECTION_PATTERNS if pat.search(sample_text)]
    pii_hits = [name for name, pat in PII_PATTERNS if pat.search(sample_text)]

    inj_risk = "high" if inj_hits else "low"
    pii_risk = "high" if pii_hits else "low"
    findings = {"prompt_injection_triggers": inj_hits, "sensitive_data_triggers": pii_hits}

    now = utc_now()
    cur = conn.execute(
        """INSERT INTO ai_evaluations
           (tenant_id, model_name, prompt_injection_risk, pii_leakage_risk, findings_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (actor["tid"], model_name, inj_risk, pii_risk, json.dumps(findings), now),
    )
    eid = cur.lastrowid
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "AI_SECURITY_EVALUATED", "ai_evaluation", eid, {"model": model_name, "inj_risk": inj_risk, "pii_risk": pii_risk})
    conn.commit()
    return {
        "id": eid,
        "model_name": model_name,
        "prompt_injection_risk": inj_risk,
        "pii_leakage_risk": pii_risk,
        "findings": findings,
        "created_at": now,
    }
