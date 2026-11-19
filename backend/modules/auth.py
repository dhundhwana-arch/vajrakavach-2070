import sqlite3
from typing import Any, Dict

from backend.core.audit import record_audit
from backend.core.db import seed_tenant_defaults, utc_now
from backend.core.security import (
    ADMIN_ROLES,
    AuthError,
    VALID_ROLES,
    create_token,
    generate_totp_secret,
    hash_password,
    require_roles,
    verify_password,
    verify_totp,
)

VALID_SECTORS = {"government", "banking", "enterprise", "research"}


def register_tenant(conn: sqlite3.Connection, data: Dict[str, Any]) -> Dict[str, Any]:
    tenant_name = (data.get("tenant_name") or "").strip()
    sector = (data.get("sector") or "enterprise").strip().lower()
    email = (data.get("email") or "").strip().lower()
    full_name = (data.get("full_name") or "").strip()
    password = data.get("password") or ""

    if not tenant_name or not email or not full_name:
        raise ValueError("tenant_name, full_name, and email are required.")
    if sector not in VALID_SECTORS:
        raise ValueError(f"sector must be one of: {', '.join(sorted(VALID_SECTORS))}")

    salt, pw_hash = hash_password(password)
    now = utc_now()
    try:
        cur_t = conn.execute(
            "INSERT INTO tenants (name, sector, created_at) VALUES (?, ?, ?)",
            (tenant_name, sector, now),
        )
        tenant_id = cur_t.lastrowid
        cur_u = conn.execute(
            """INSERT INTO users
               (tenant_id, email, full_name, role, password_salt, password_hash, created_at)
               VALUES (?, ?, ?, 'org_admin', ?, ?, ?)""",
            (tenant_id, email, full_name, salt, pw_hash, now),
        )
        user_id = cur_u.lastrowid
        seed_tenant_defaults(conn, tenant_id)
        record_audit(
            conn,
            tenant_id,
            user_id,
            email,
            "TENANT_REGISTERED",
            "tenant",
            tenant_id,
            {"tenant_name": tenant_name, "sector": sector},
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ValueError("Tenant name or email already exists.") from exc

    token = create_token(user_id, tenant_id, email, "org_admin")
    return {
        "token": token,
        "user": {
            "id": user_id,
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "sector": sector,
            "email": email,
            "full_name": full_name,
            "role": "org_admin",
            "mfa_enabled": False,
        },
    }


def login_user(conn: sqlite3.Connection, data: Dict[str, Any]) -> Dict[str, Any]:
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    totp_code = (data.get("totp_code") or "").strip()

    row = conn.execute(
        """SELECT u.*, t.name AS tenant_name, t.sector
           FROM users u JOIN tenants t ON t.id = u.tenant_id
           WHERE u.email = ? AND u.is_active = 1""",
        (email,),
    ).fetchone()
    if not row or not verify_password(password, row["password_salt"], row["password_hash"]):
        raise AuthError("Invalid email or password.", 401)

    if row["mfa_enabled"]:
        if not totp_code:
            raise AuthError("MFA TOTP code is required for this account.", 401)
        if not verify_totp(row["mfa_secret"], totp_code):
            raise AuthError("Invalid MFA TOTP code.", 401)

    token = create_token(row["id"], row["tenant_id"], row["email"], row["role"])
    record_audit(
        conn,
        row["tenant_id"],
        row["id"],
        row["email"],
        "USER_LOGIN",
        "user",
        row["id"],
        {"mfa_used": bool(row["mfa_enabled"])},
    )
    conn.commit()
    return {
        "token": token,
        "user": {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "tenant_name": row["tenant_name"],
            "sector": row["sector"],
            "email": row["email"],
            "full_name": row["full_name"],
            "role": row["role"],
            "mfa_enabled": bool(row["mfa_enabled"]),
        },
    }


def create_tenant_user(conn: sqlite3.Connection, actor: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    require_roles(actor, ADMIN_ROLES)
    email = (data.get("email") or "").strip().lower()
    full_name = (data.get("full_name") or "").strip()
    role = (data.get("role") or "security_analyst").strip().lower()
    password = data.get("password") or ""

    if not email or not full_name:
        raise ValueError("email and full_name are required.")
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of: {', '.join(sorted(VALID_ROLES))}")

    salt, pw_hash = hash_password(password)
    try:
        cur = conn.execute(
            """INSERT INTO users
               (tenant_id, email, full_name, role, password_salt, password_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (actor["tid"], email, full_name, role, salt, pw_hash, utc_now()),
        )
        new_id = cur.lastrowid
        record_audit(
            conn,
            actor["tid"],
            actor["sub"],
            actor["email"],
            "USER_CREATED",
            "user",
            new_id,
            {"email": email, "role": role},
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ValueError("Email already exists.") from exc
    return {"id": new_id, "email": email, "full_name": full_name, "role": role, "tenant_id": actor["tid"]}


def setup_mfa(conn: sqlite3.Connection, actor: Dict[str, Any]) -> Dict[str, Any]:
    secret = generate_totp_secret()
    conn.execute(
        "UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ? AND tenant_id = ?",
        (secret, actor["sub"], actor["tid"]),
    )
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "MFA_SECRET_GENERATED", "user", actor["sub"], {})
    conn.commit()
    otpauth_uri = f"otpauth://totp/VAJRAKAVACH2070:{actor['email']}?secret={secret}&issuer=VAJRAKAVACH2070"
    return {"mfa_secret": secret, "otpauth_uri": otpauth_uri}


def enable_mfa(conn: sqlite3.Connection, actor: Dict[str, Any], code: str) -> Dict[str, Any]:
    row = conn.execute(
        "SELECT mfa_secret FROM users WHERE id = ? AND tenant_id = ?",
        (actor["sub"], actor["tid"]),
    ).fetchone()
    if not row or not row["mfa_secret"]:
        raise ValueError("Run MFA setup first.")
    if not verify_totp(row["mfa_secret"], code):
        raise ValueError("Invalid 6-digit TOTP code.")
    conn.execute(
        "UPDATE users SET mfa_enabled = 1 WHERE id = ? AND tenant_id = ?",
        (actor["sub"], actor["tid"]),
    )
    record_audit(conn, actor["tid"], actor["sub"], actor["email"], "MFA_ENABLED", "user", actor["sub"], {})
    conn.commit()
    return {"mfa_enabled": True}
