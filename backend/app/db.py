import sqlite3
from contextlib import closing
from typing import Any, Dict, List

from .config import DB_PATH, ENCRYPTION_KEY
from .crypto import protect_secret, reveal_secret


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                environment TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                key_pem TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ca_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                template_name TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                key_pem TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        if ENCRYPTION_KEY:
            for table in ("cas", "certificates"):
                rows = conn.execute(f"SELECT id, key_pem FROM {table} WHERE key_pem NOT LIKE 'enc:%'").fetchall()
                for row_id, key_pem in rows:
                    conn.execute(f"UPDATE {table} SET key_pem = ? WHERE id = ?", (protect_secret(key_pem), row_id))
        for table in ("cas", "certificates"):
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if "status" not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bundles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                mode TEXT NOT NULL,
                bundle_pem TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trust_materials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                environment TEXT NOT NULL,
                material_type TEXT NOT NULL,
                pem TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def save_ca(name: str, environment: str, cert_pem: str, key_pem: str) -> Dict[str, Any]:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "INSERT INTO cas (name, environment, cert_pem, key_pem) VALUES (?, ?, ?, ?)",
            (name, environment, cert_pem, protect_secret(key_pem)),
        )
        conn.commit()
    return {"id": cursor.lastrowid, "name": name, "environment": environment}


def list_cas() -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM cas ORDER BY id DESC").fetchall()
    result = [dict(row) for row in rows]
    for row in result:
        row["key_pem"] = reveal_secret(row["key_pem"])
    return result


def save_certificate(ca_id: int, domain: str, template_name: str, cert_pem: str, key_pem: str) -> Dict[str, Any]:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "INSERT INTO certificates (ca_id, domain, template_name, cert_pem, key_pem) VALUES (?, ?, ?, ?, ?)",
            (ca_id, domain, template_name, cert_pem, protect_secret(key_pem)),
        )
        conn.commit()
    return {"id": cursor.lastrowid, "ca_id": ca_id, "domain": domain, "template_name": template_name}


def list_certificates() -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM certificates ORDER BY id DESC").fetchall()
    result = [dict(row) for row in rows]
    for row in result:
        row["key_pem"] = reveal_secret(row["key_pem"])
    return result


def update_ca(ca_id: int, name: str | None = None, status: str | None = None) -> bool:
    changes, values = [], []
    if name is not None:
        changes.append("name = ?"); values.append(name)
    if status is not None:
        changes.append("status = ?"); values.append(status)
    if not changes:
        return False
    values.append(ca_id)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(f"UPDATE cas SET {', '.join(changes)} WHERE id = ?", values)
        conn.commit()
    return cursor.rowcount > 0


def update_certificate_status(certificate_id: int, status: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("UPDATE certificates SET status = ? WHERE id = ?", (status, certificate_id))
        conn.commit()
    return cursor.rowcount > 0


def save_bundle(name: str, mode: str, bundle_pem: str) -> Dict[str, Any]:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "INSERT INTO bundles (name, mode, bundle_pem) VALUES (?, ?, ?)",
            (name, mode, bundle_pem),
        )
        conn.commit()
    return {"id": cursor.lastrowid, "name": name, "mode": mode}


def list_bundles() -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM bundles ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def list_bundles_with_pem() -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM bundles ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def save_trust_material(name: str, environment: str, material_type: str, pem: str) -> Dict[str, Any]:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "INSERT INTO trust_materials (name, environment, material_type, pem) VALUES (?, ?, ?, ?)",
            (name, environment, material_type, pem),
        )
        conn.commit()
    return {"id": cursor.lastrowid, "name": name, "environment": environment, "material_type": material_type}


def list_trust_materials() -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT id, name, environment, material_type, created_at FROM trust_materials ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def get_trust_material(material_id: int) -> Dict[str, Any] | None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM trust_materials WHERE id = ?", (material_id,)).fetchone()
    return dict(row) if row else None


def save_audit_event(method: str, path: str, status_code: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT INTO audit_log (method, path, status_code) VALUES (?, ?, ?)", (method, path, status_code))
        conn.commit()


def list_audit_events(limit: int = 100) -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


init_db()
