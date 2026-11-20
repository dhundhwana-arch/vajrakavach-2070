import hmac
import sqlite3
from typing import Any, Dict, List

from backend.core.audit import record_audit
from backend.core.db import utc_now
from backend.core.security import SECURITY_WRITE_ROLES, require_roles

VALID_SECTORS = {"energy", "telecom", "banking_core", "transport", "healthcare", "water", "space_defense", "enterprise_hw"}


def list_hardware(conn: sqlite3.Connection, actor: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM infra_hardware WHERE tenant_id = ? ORDER BY id DESC LIMIT 100",
        (actor["tid"],),
    ).fetchall()
    return [dict(r) for r in rows]


def attest_hardware(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, SECURITY_WRITE_ROLES)
    device_name = (data.get("device_name") or "").strip()
    sector = (data.get("sector") or "energy").strip().lower()
    firmware_version = (data.get("firmware_version") or "1.0.0").strip()
    expected_sha256 = (data.get("expected_sha256") or "").strip().lower()
    measured_sha256 = (data.get("measured_sha256") or "").strip().lower()
    tpm_enabled = 1 if data.get("tpm_enabled", True) else 0

    if not device_name or not expected_sha256 or not measured_sha256:
        raise ValueError("device_name, expected_sha256, and measured_sha256 are required.")
    if sector not in VALID_SECTORS:
        raise ValueError(f"sector must be one of: {', '.join(sorted(VALID_SECTORS))}")

    hashes_match = hmac.compare_digest(expected_sha256, measured_sha256)
    if not hashes_match:
        status = "ATTESTATION_FAILED"
    elif not tpm_enabled:
        status = "VERIFIED_NO_TPM"
    else:
        status = "ATTESTATION_VERIFIED"

    now = utc_now()
    cur = conn.execute(
        """INSERT INTO infra_hardware
           (tenant_id, device_name, sector, firmware_version, expected_sha256, measured_sha256,
            tpm_enabled, attestation_status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor["tid"], device_name, sector, firmware_version, expected_sha256, measured_sha256, tpm_enabled, status, now),
    )
    hid = cur.lastrowid
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "HARDWARE_ATTESTATION_RECORDED", "infra_hardware", hid, {"device": device_name, "status": status})
    conn.commit()
    return {
        "id": hid,
        "device_name": device_name,
        "sector": sector,
        "firmware_version": firmware_version,
        "tpm_enabled": bool(tpm_enabled),
        "attestation_status": status,
        "created_at": now,
    }
