import json
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

VALID_CHANNELS = {"UPI", "NEFT", "RTGS", "IMPS", "CARD", "WIRE"}


def list_transactions(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM banking_transactions WHERE tenant_id = ? ORDER BY id DESC LIMIT 100",
        (actor["tid"],),
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["triggered_rules"] = json.loads(item.pop("triggered_rules_json"))
        out.append(item)
    return out


def analyze_transaction(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    account_alias = (data.get("account_alias") or "").strip()
    channel = (data.get("channel") or "UPI").strip().upper()
    counterparty = (data.get("counterparty") or "").strip()

    try:
        amount_inr = float(data.get("amount_inr", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("amount_inr must be a valid number.") from exc

    if not account_alias or amount_inr <= 0:
        raise ValueError("account_alias and positive amount_inr are required.")
    if channel not in VALID_CHANNELS:
        raise ValueError(f"channel must be one of: {', '.join(sorted(VALID_CHANNELS))}")

    rules: List[str] = []
    score = 0

    if channel == "UPI" and amount_inr >= 95_000:
        score += 35
        rules.append("HIGH_VALUE_UPI_LIMIT_PROXIMITY")
    if amount_inr >= 500_000:
        score += 35
        rules.append("LARGE_SINGLE_TRANSFER_5L_PLUS")
    if 45_000 <= amount_inr < 50_000:
        score += 30
        rules.append("STRUCTURING_THRESHOLD_PROXIMITY_50K")

    # Check velocity against existing tenant ledger for same account alias
    recent_cnt = conn.execute(
        "SELECT COUNT(*) FROM banking_transactions WHERE tenant_id = ? AND account_alias = ?",
        (actor["tid"], account_alias),
    ).fetchone()[0]
    if recent_cnt >= 3:
        score += 25
        rules.append("ELEVATED_ACCOUNT_VELOCITY")

    if data.get("new_device_or_geo"):
        score += 20
        rules.append("NEW_DEVICE_OR_GEO_ANOMALY")

    score = min(100, score)
    risk_level = "critical" if score >= 70 else ("high" if score >= 45 else ("medium" if score >= 25 else "low"))
    now = utc_now()

    cur = conn.execute(
        """INSERT INTO banking_transactions
           (tenant_id, account_alias, amount_inr, channel, counterparty,
            anomaly_score, risk_level, triggered_rules_json, review_status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_human_review', ?)""",
        (actor["tid"], account_alias, amount_inr, channel, counterparty, score, risk_level, json.dumps(rules), now),
    )
    tx_id = cur.lastrowid
    record_audit(
        conn,
        actor["tid"],
        actor["sub"],
        actor["email"],
        "BANKING_TX_ANALYZED",
        "banking_transaction",
        tx_id,
        {"account_alias": account_alias, "anomaly_score": score, "risk_level": risk_level},
    )
    conn.commit()
    return {
        "id": tx_id,
        "account_alias": account_alias,
        "amount_inr": amount_inr,
        "channel": channel,
        "anomaly_score": score,
        "risk_level": risk_level,
        "triggered_rules": rules,
        "advisory_only": True,
        "review_status": "pending_human_review",
        "created_at": now,
    }
