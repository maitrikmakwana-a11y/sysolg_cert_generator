from cryptography.fernet import Fernet, InvalidToken

from .config import ENCRYPTION_KEY

_fernet = None
if ENCRYPTION_KEY:
    try:
        _fernet = Fernet(ENCRYPTION_KEY.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("CERT_FACTORY_ENCRYPTION_KEY must be a valid Fernet key") from exc


def protect_secret(value: str) -> str:
    if _fernet is None or value.startswith("enc:"):
        return value
    return "enc:" + _fernet.encrypt(value.encode("utf-8")).decode("ascii")


def reveal_secret(value: str) -> str:
    if not value.startswith("enc:") or _fernet is None:
        return value
    try:
        return _fernet.decrypt(value[4:].encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Unable to decrypt stored private key; check CERT_FACTORY_ENCRYPTION_KEY") from exc
