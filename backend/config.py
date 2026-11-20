import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DEFAULT_DB_PATH = BASE_DIR / "data" / "vajrakavach.db"

HOST = os.environ.get("VAJRA_HOST", "127.0.0.1")
PORT = int(os.environ.get("VAJRA_PORT", os.environ.get("PORT", "8080")))
DB_PATH = Path(os.environ.get("VAJRA_DB_PATH", str(DEFAULT_DB_PATH)))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# Ephemeral strong secret fallback for local dev; set VAJRA_SECRET_KEY in production.
SECRET_KEY = os.environ.get("VAJRA_SECRET_KEY") or secrets.token_hex(32)
TOKEN_TTL_SECONDS = int(os.environ.get("VAJRA_TOKEN_TTL", "43200"))  # 12 hours
MAX_BODY_BYTES = 1_048_576  # 1 MB safety cap

APP_VERSION = "1.2.0"
APP_NAME = "VAJRAKAVACH 2070"
FOUNDER = "Divyesh Bambhaniya"
PRODUCT_IDENTITY = "Developer by Divyesh Bambhaniya"
