from fastapi import Header, HTTPException

from .config import ADMIN_API_KEY, API_KEY, READONLY_API_KEY


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Protect deployments that set CERT_FACTORY_API_KEY; local mode stays open."""
    if (ADMIN_API_KEY or READONLY_API_KEY) and x_api_key not in {ADMIN_API_KEY, READONLY_API_KEY}:
        raise HTTPException(status_code=401, detail="A valid X-API-Key header is required")


def is_read_only_key(x_api_key: str | None) -> bool:
    return bool(READONLY_API_KEY and x_api_key == READONLY_API_KEY and x_api_key != ADMIN_API_KEY)
