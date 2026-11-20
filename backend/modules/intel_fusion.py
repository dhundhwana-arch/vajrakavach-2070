import sqlite3
from typing import Any, Dict, List

from backend.core.audit import verify_audit_chain


def compute_intel_fusion(conn: sqlite3.Connection, actor: Dict[str, Any]) -> Dict[str, Any]:
    tid = actor["tid"]
    open_high_risks = conn.execute("SELECT COUNT(*) FROM risks WHERE tenant_id = ? AND status = 'open' AND severity IN ('critical', 'high')", (tid,)).fetchone()[0]
    open_cases = conn.execute("SELECT COUNT(*) FROM soc_cases WHERE tenant_id = ? AND status != 'resolved'", (tid,)).fetchone()[0]
    high_fraud = conn.execute("SELECT COUNT(*) FROM banking_transactions WHERE tenant_id = ? AND risk_level IN ('critical', 'high')", (tid,)).fetchone()[0]
    high_malware = conn.execute("SELECT COUNT(*) FROM malware_analyses WHERE tenant_id = ? AND risk_level IN ('critical', 'high')", (tid,)).fetchone()[0]
    overdue_certin = conn.execute("SELECT COUNT(*) FROM certin_reports WHERE tenant_id = ? AND sla_status = 'overdue'", (tid,)).fetchone()[0]
    osint_count = conn.execute("SELECT COUNT(*) FROM osint_records WHERE tenant_id = ?", (tid,)).fetchone()[0]
    shares_count = conn.execute("SELECT COUNT(*) FROM privacy_shares WHERE tenant_id = ?", (tid,)).fetchone()[0]
    audit_valid = verify_audit_chain(conn, tid)["valid"]

    readiness = 100
    recommendations: List[str] = []

    if not audit_valid:
        readiness -= 40
        recommendations.append("CRITICAL: Investigate broken SHA-256 audit hash chain immediately.")
    if overdue_certin > 0:
        readiness -= min(25, overdue_certin * 15)
        recommendations.append(f"URGENT: {overdue_certin} CERT-In 6-hour incident report(s) overdue.")
    if open_high_risks > 0:
        readiness -= min(20, open_high_risks * 5)
        recommendations.append(f"Mitigate {open_high_risks} open high/critical risk(s) in Risk Register.")
    if open_cases > 0:
        readiness -= min(15, open_cases * 5)
        recommendations.append(f"Review and resolve {open_cases} open SOC incident case(s) with human approval.")
    if high_fraud > 0:
        readiness -= min(10, high_fraud * 5)
        recommendations.append(f"Investigate {high_fraud} high/critical banking anomaly alert(s).")
    if high_malware > 0:
        readiness -= min(10, high_malware * 5)
        recommendations.append(f"Triage {high_malware} high-risk static malware artifact(s) in Defensive Lab.")

    if not recommendations:
        recommendations.append("All active cross-domain security indicators are within healthy baseline.")

    return {
        "unified_readiness_score": max(0, readiness),
        "audit_chain_valid": audit_valid,
        "signals": {
            "open_high_risks": open_high_risks,
            "open_soc_cases": open_cases,
            "high_banking_anomalies": high_fraud,
            "high_malware_alerts": high_malware,
            "overdue_certin_slas": overdue_certin,
            "lawful_osint_records": osint_count,
            "privacy_sanitized_shares": shares_count,
        },
        "prioritized_recommendations": recommendations,
    }
