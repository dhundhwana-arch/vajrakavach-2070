import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from typing import Any, Dict, Optional, Set, Tuple

from backend import config

VALID_ROLES = {
    "platform_owner",
    "org_admin",
    "security_analyst",
    "soc_manager",
    "investigator",
    "auditor",
    "researcher",
    "executive",
}

ADMIN_ROLES = {"platform_owner", "org_admin"}
APPROVAL_ROLES = {"platform_owner", "org_admin", "soc_manager"}
SECURITY_WRITE_ROLES = {
    "platform_owner",
    "org_admin",
    "security_analyst",
    "soc_manager",
    "investigator",
    "researcher",
}
FORENSICS_WRITE_ROLES = {"platform_owner", "org_admin", "soc_manager", "investigator"}


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.status_code = status_code


def hash_password(password: str, salt_hex: Optional[str] = None) -> Tuple[str, str]:
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    try:
        _, computed = hash_password(password, salt_hex)
    except ValueError:
        return False
    return hmac.compare_digest(computed, expected_hash_hex)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_token(user_id: int, tenant_id: int, email: str, role: str, secret_key: Optional[str] = None) -> str:
    now = int(time.time())
    payload = {
        "sub": user_id,
        "tid": tenant_id,
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + config.TOKEN_TTL_SECONDS,
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    key = (secret_key or config.SECRET_KEY).encode("utf-8")
    sig = hmac.new(key, payload_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64url_encode(sig)}"


def verify_token(token: str, secret_key: Optional[str] = None) -> Dict[str, Any]:
    if not token or "." not in token:
        raise AuthError("Missing or malformed authorization token.", 401)
    parts = token.split(".", 1)
    payload_b64, sig_b64 = parts[0], parts[1]
    key = (secret_key or config.SECRET_KEY).encode("utf-8")
    expected_sig = _b64url_encode(hmac.new(key, payload_b64.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(sig_b64, expected_sig):
        raise AuthError("Invalid token signature.", 401)
    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        raise AuthError("Corrupt token payload.", 401) from exc
    if int(payload.get("exp", 0)) < int(time.time()):
        raise AuthError("Session token has expired.", 401)
    return payload


def require_roles(user: Dict[str, Any], allowed_roles: Set[str]) -> None:
    if user.get("role") not in allowed_roles:
        raise AuthError(
            f"Access denied: role '{user.get('role')}' lacks permission for this action.",
            403,
        )


# --- RFC 6238 TOTP Multi-Factor Authentication (Pure Python Stdlib) ---
def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def compute_totp(secret_b32: str, for_time: Optional[int] = None, interval: int = 30) -> str:
    padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int((for_time if for_time is not None else time.time()) // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    cleaned = (code or "").strip()
    if len(cleaned) != 6 or not cleaned.isdigit():
        return False
    now = int(time.time())
    for delta in range(-window, window + 1):
        if hmac.compare_digest(compute_totp(secret_b32, now + delta * 30), cleaned):
            return True
    return False
