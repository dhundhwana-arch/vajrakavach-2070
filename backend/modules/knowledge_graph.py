import sqlite3
from typing import Any, Dict, List


def build_security_graph(conn: sqlite3.Connection, actor: Dict[str, Any]) -> Dict[str, Any]:
    tid = actor["tid"]
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    assets = conn.execute("SELECT id, name, asset_type, criticality, ip_or_uri FROM assets WHERE tenant_id = ?", (tid,)).fetchall()
    for a in assets:
        nodes.append({"id": f"asset:{a['id']}", "type": "Asset", "label": a["name"], "meta": a["criticality"]})

    risks = conn.execute("SELECT id, asset_id, title, severity, risk_score FROM risks WHERE tenant_id = ?", (tid,)).fetchall()
    for r in risks:
        nodes.append({"id": f"risk:{r['id']}", "type": "Risk", "label": r["title"], "meta": f"{r['severity']} ({r['risk_score']})"})
        if r["asset_id"]:
            edges.append({"source": f"asset:{r['asset_id']}", "target": f"risk:{r['id']}", "relation": "HAS_RISK"})

    events = conn.execute("SELECT id, asset_id, event_type, severity, summary FROM security_events WHERE tenant_id = ?", (tid,)).fetchall()
    for e in events:
        nodes.append({"id": f"event:{e['id']}", "type": "SecurityEvent", "label": e["event_type"], "meta": e["severity"]})
        if e["asset_id"]:
            edges.append({"source": f"asset:{e['asset_id']}", "target": f"event:{e['id']}", "relation": "GENERATED_EVENT"})

    cases = conn.execute("SELECT id, related_event_id, title, status FROM soc_cases WHERE tenant_id = ?", (tid,)).fetchall()
    for c in cases:
        nodes.append({"id": f"case:{c['id']}", "type": "SOCCase", "label": c["title"][:45], "meta": c["status"]})
        if c["related_event_id"]:
            edges.append({"source": f"event:{c['related_event_id']}", "target": f"case:{c['id']}", "relation": "ESCALATED_TO"})

    evidences = conn.execute("SELECT id, case_id, title, sha256_hash FROM evidence_items WHERE tenant_id = ?", (tid,)).fetchall()
    for ev in evidences:
        nodes.append({"id": f"evidence:{ev['id']}", "type": "Evidence", "label": ev["title"], "meta": ev["sha256_hash"][:10]})
        if ev["case_id"]:
            edges.append({"source": f"case:{ev['case_id']}", "target": f"evidence:{ev['id']}", "relation": "HAS_EVIDENCE"})

    iocs = conn.execute("SELECT id, ioc_type, indicator FROM threat_iocs WHERE tenant_id = ?", (tid,)).fetchall()
    for i in iocs:
        nodes.append({"id": f"ioc:{i['id']}", "type": "ThreatIOC", "label": i["indicator"], "meta": i["ioc_type"]})
        needle = i["indicator"].lower()
        for e in events:
            if needle in e["summary"].lower():
                edges.append({"source": f"ioc:{i['id']}", "target": f"event:{e['id']}", "relation": "MATCHES_IOC"})

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {"total_nodes": len(nodes), "total_edges": len(edges)},
    }
