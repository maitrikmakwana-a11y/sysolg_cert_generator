import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = os.getenv("DATABASE_PATH", str(DATA_DIR / "cert_store.db"))
API_PREFIX = "/api/v1"
API_KEY = os.getenv("CERT_FACTORY_API_KEY", "").strip()
ADMIN_API_KEY = os.getenv("CERT_FACTORY_ADMIN_API_KEY", API_KEY).strip()
READONLY_API_KEY = os.getenv("CERT_FACTORY_READONLY_API_KEY", "").strip()
ENCRYPTION_KEY = os.getenv("CERT_FACTORY_ENCRYPTION_KEY", "").strip()

DATA_DIR.mkdir(parents=True, exist_ok=True)
