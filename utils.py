import asyncio
import hashlib
import json
import os
import secrets
import sqlite3
import time
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

try:
    import redis.asyncio as redis
except ImportError:  # pragma: no cover - redis might not be installed yet.
    redis = None


class InvalidDecryptionKey(Exception):
    """Raised when a provided Fernet key cannot decrypt the ciphertext."""


def generate_key() -> str:
    """Return a fresh Fernet key as a UTF-8 string."""
    return Fernet.generate_key().decode("utf-8")


def encrypt_text(plain_text: str, key: str) -> bytes:
    """Encrypt plain text using the supplied Fernet key."""
    fernet = Fernet(_ensure_bytes(key))
    return fernet.encrypt(plain_text.encode("utf-8"))


def decrypt_text(cipher_text: bytes, key: str) -> str:
    """Decrypt cipher text using the supplied Fernet key."""
    fernet = Fernet(_ensure_bytes(key))
    try:
        decrypted = fernet.decrypt(cipher_text)
    except InvalidToken as exc:
        raise InvalidDecryptionKey("Invalid decryption key provided") from exc
    return decrypted.decode("utf-8")


def _ensure_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def hash_password(password: str) -> str:
    """Hash a password using SHA-256 with a random salt."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    try:
        salt, hashed = stored_hash.split(":")
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except ValueError:
        return False


class SecretStore:
    """Stores encrypted payloads in Redis when available, otherwise SQLite."""

    def __init__(self, redis_url: Optional[str] = None, sqlite_path: str = "vault.db"):
        self.redis_url = redis_url or os.getenv("REDIS_URL")
        self.sqlite_path = sqlite_path
        self.redis_client = None
        self._sqlite_initialized = False
        self._init_lock = asyncio.Lock()

        if self.redis_url and redis is not None:
            self.redis_client = redis.from_url(
                self.redis_url,
                decode_responses=False,
            )

    @property
    def using_redis(self) -> bool:
        return self.redis_client is not None

    async def save_secret(
        self,
        secret_id: str,
        cipher_text: bytes,
        ttl_seconds: int,
        password_hash: Optional[str] = None,
    ) -> None:
        """Save a secret with optional password protection."""
        if ttl_seconds <= 0:
            raise ValueError("TTL must be a positive integer")

        if self.using_redis:
            data = json.dumps({
                "payload": cipher_text.decode("latin-1"),
                "password_hash": password_hash,
            })
            await self.redis_client.set(secret_id, data.encode(), ex=ttl_seconds)
            return

        await self._save_sqlite(secret_id, cipher_text, ttl_seconds, password_hash)

    async def check_secret(self, secret_id: str) -> Optional[dict]:
        """Check if a secret exists and get metadata (without consuming it)."""
        if self.using_redis:
            data = await self.redis_client.get(secret_id)
            if data is None:
                return None
            parsed = json.loads(data.decode())
            return {"password_protected": parsed.get("password_hash") is not None}

        return await self._check_sqlite(secret_id)

    async def consume_secret(self, secret_id: str) -> Optional[tuple[bytes, Optional[str]]]:
        """Fetch and delete the secret. Returns (cipher_text, password_hash) or None."""
        if self.using_redis:
            pipeline = self.redis_client.pipeline()
            pipeline.get(secret_id)
            pipeline.delete(secret_id)
            result = await pipeline.execute()
            if result[0] is None:
                return None
            parsed = json.loads(result[0].decode())
            return (parsed["payload"].encode("latin-1"), parsed.get("password_hash"))

        return await self._consume_sqlite(secret_id)

    async def close(self) -> None:
        if self.using_redis:
            await self.redis_client.aclose()

    # SQLite helpers -----------------------------------------------------------------
    async def _ensure_sqlite(self) -> None:
        if self._sqlite_initialized:
            return

        async with self._init_lock:
            if self._sqlite_initialized:
                return
            await asyncio.to_thread(self._initialize_sqlite)
            self._sqlite_initialized = True

    def _initialize_sqlite(self) -> None:
        conn = sqlite3.connect(self.sqlite_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                password_hash TEXT,
                expires_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

    async def _save_sqlite(
        self,
        secret_id: str,
        cipher_text: bytes,
        ttl_seconds: int,
        password_hash: Optional[str] = None,
    ) -> None:
        await self._ensure_sqlite()
        expires_at = int(time.time()) + ttl_seconds

        def _persist() -> None:
            conn = sqlite3.connect(self.sqlite_path)
            conn.execute(
                """
                INSERT OR REPLACE INTO secrets (id, payload, password_hash, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (secret_id, sqlite3.Binary(cipher_text), password_hash, expires_at),
            )
            conn.commit()
            conn.close()

        await asyncio.to_thread(_persist)

    async def _check_sqlite(self, secret_id: str) -> Optional[dict]:
        await self._ensure_sqlite()

        def _check() -> Optional[dict]:
            now = int(time.time())
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.execute(
                "SELECT password_hash, expires_at FROM secrets WHERE id = ?",
                (secret_id,),
            )
            row = cursor.fetchone()
            conn.close()
            if not row or row[1] < now:
                return None
            return {"password_protected": row[0] is not None}

        return await asyncio.to_thread(_check)

    async def _consume_sqlite(self, secret_id: str) -> Optional[tuple[bytes, Optional[str]]]:
        await self._ensure_sqlite()

        def _fetch_and_delete() -> Optional[tuple[bytes, Optional[str]]]:
            now = int(time.time())
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.execute(
                "SELECT payload, password_hash, expires_at FROM secrets WHERE id = ?",
                (secret_id,),
            )
            row = cursor.fetchone()
            if not row:
                conn.close()
                return None

            payload, password_hash, expires_at = row
            conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
            conn.commit()
            conn.close()

            if expires_at < now:
                return None
            return (payload, password_hash)

        return await asyncio.to_thread(_fetch_and_delete)
