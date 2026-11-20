import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

BROKEN_ALGOS = {"MD5", "SHA-1", "SHA1", "DES", "3DES", "RC4", "RSA-1024"}
QUANTUM_VULNERABLE_PKI = {"RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "ED25519", "DH-2048", "ECDH"}
QUANTUM_READY_ALGOS = {"ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87", "SLH-DSA", "AES-256", "SHA-256", "SHA-384", "SHA-512"}


def _classify_pqc(algorithm: str, shelf_life_years: int) -> tuple[str, str]:
    algo = algorithm.strip().upper()
    if algo in BROKEN_ALGOS:
        return "critical", "Replace immediately with SHA-256/AES-256 or NIST PQC (FIPS 203/204)."
    if algo in QUANTUM_VULNERABLE_PKI:
        note = "High HNDL risk (long data shelf-life)" if shelf_life_years >= 10 else "Quantum-vulnerable public-key crypto"
        return "high", f"{note}: plan hybrid migration to NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)."
    if algo == "AES-128":
        return "medium", "Upgrade symmetric key size to AES-256 for post-quantum Grover security margin."
    if algo in QUANTUM_READY_ALGOS:
        return "quantum_ready", "Aligned with current post-quantum / NIST FIPS 203-205 readiness baseline."
    return "medium", "Unclassified algorithm: conduct formal cryptographic agility review."


def list_pqc_inventory(conn: sqlite3.Connection, actor: Dict[str, Any]) -> Dict[str, Any]:
    rows = conn.execute(
        "SELECT * FROM pqc_inventory WHERE tenant_id = ? ORDER BY id DESC LIMIT 100",
        (actor["tid"],),
    ).fetchall()
    items = [dict(r) for r in rows]
    total = len(items)
    ready = sum(1 for i in items if i["quantum_risk"] == "quantum_ready")
    readiness_pct = int(round((ready / total) * 100)) if total else 0
    return {"items": items, "total": total, "quantum_ready_count": ready, "pqc_readiness_pct": readiness_pct}


def add_pqc_asset(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    system_name = (data.get("system_name") or "").strip()
    algorithm = (data.get("algorithm") or "").strip().upper()
    usage_context = (data.get("usage_context") or "TLS").strip()
    try:
        shelf_life = max(1, int(data.get("data_shelf_life_years", 10)))
    except (TypeError, ValueError) as exc:
        raise ValueError("data_shelf_life_years must be a positive integer.") from exc

    if not system_name or not algorithm:
        raise ValueError("system_name and algorithm are required.")

    risk, target = _classify_pqc(algorithm, shelf_life)
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO pqc_inventory
           (tenant_id, system_name, algorithm, usage_context, data_shelf_life_years, quantum_risk, migration_target, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], system_name, algorithm, usage_context, shelf_life, risk, target, now),
    )
    pid = cur.lastrowid
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "PQC_CRYPTO_INVENTORIED", "pqc_inventory", pid, {"system": system_name, "algorithm": algorithm, "quantum_risk": risk})
    conn.commit()
    return {
        "id": pid,
        "system_name": system_name,
        "algorithm": algorithm,
        "usage_context": usage_context,
        "data_shelf_life_years": shelf_life,
        "quantum_risk": risk,
        "migration_target": target,
        "created_at": now,
    }
