# 📖 CODE.md - The Vault Codebase Documentation

> A comprehensive guide to understanding every aspect of The Vault's codebase.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [File-by-File Breakdown](#2-file-by-file-breakdown)
   - [utils.py](#utilspy---core-utilities)
   - [config.py](#configpy---configuration-management)
   - [backend.py](#backendpy---fastapi-rest-api)
   - [frontend.py](#frontendpy---streamlit-ui)
3. [Data Flow](#3-data-flow)
4. [Key Design Decisions](#4-key-design-decisions)
5. [Security Implementation](#5-security-implementation)
6. [Testing Strategy](#6-testing-strategy)
7. [Common Patterns](#7-common-patterns)
8. [Extending the Codebase](#8-extending-the-codebase)

---

## 1. Project Overview

The Vault is a **zero-knowledge secret sharing application** built with:

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend | Streamlit | User interface |
| Backend | FastAPI | REST API |
| Storage | Redis/SQLite | Data persistence |
| Crypto | Fernet (cryptography) | Encryption |

### Core Principle

The server **never stores the encryption key**. It only stores encrypted blobs that are meaningless without the key, which only the user possesses.

---

## 2. File-by-File Breakdown

---

### `utils.py` - Core Utilities

This is the **heart of the application**. It contains all cryptographic operations and storage logic.

#### Imports Explained

```python
import asyncio          # For async SQLite operations
import hashlib          # SHA-256 password hashing
import json             # Serialize data for Redis storage
import os               # Environment variable access
import secrets          # Cryptographically secure random values
import sqlite3          # Fallback database
import time             # TTL expiration calculations
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken  # Core encryption

# Redis is optional - graceful fallback to SQLite
try:
    import redis.asyncio as redis
except ImportError:
    redis = None
```

**Why these choices?**
- `secrets` over `random`: Cryptographically secure randomness for salts
- `asyncio.to_thread`: Runs blocking SQLite in thread pool to avoid blocking async
- Optional Redis: Makes development easier without Redis dependency

---

#### Exception Class

```python
class InvalidDecryptionKey(Exception):
    """Raised when a provided Fernet key cannot decrypt the ciphertext."""
```

**Why a custom exception?**
- Separates cryptographic errors from other exceptions
- Allows specific handling in the API layer (returns 400 vs 500)

---

#### Encryption Functions

```python
def generate_key() -> str:
    """Return a fresh Fernet key as a UTF-8 string."""
    return Fernet.generate_key().decode("utf-8")
```

**What happens here:**
1. `Fernet.generate_key()` creates a **32-byte random key**
2. The key is **base64-encoded** (44 characters)
3. We decode to UTF-8 string for JSON serialization

**Why Fernet?**
- Built on AES-128-CBC + HMAC-SHA256
- Includes timestamp for optional expiration
- Authenticated encryption (detects tampering)

---

```python
def encrypt_text(plain_text: str, key: str) -> bytes:
    """Encrypt plain text using the supplied Fernet key."""
    fernet = Fernet(_ensure_bytes(key))
    return fernet.encrypt(plain_text.encode("utf-8"))
```

**What happens:**
1. Create Fernet instance with the key
2. Encode plaintext to UTF-8 bytes
3. Fernet adds: `version || timestamp || IV || ciphertext || HMAC`

**Important:** Each encryption produces **different output** even for the same input (random IV).

---

```python
def decrypt_text(cipher_text: bytes, key: str) -> str:
    """Decrypt cipher text using the supplied Fernet key."""
    fernet = Fernet(_ensure_bytes(key))
    try:
        decrypted = fernet.decrypt(cipher_text)
    except InvalidToken as exc:
        raise InvalidDecryptionKey("Invalid decryption key provided") from exc
    return decrypted.decode("utf-8")
```

**Error handling:**
- `InvalidToken` is raised for: wrong key, corrupted data, tampered data
- We wrap it in our custom exception for cleaner API handling

---

#### Password Hashing

```python
def hash_password(password: str) -> str:
    """Hash a password using SHA-256 with a random salt."""
    salt = secrets.token_hex(16)  # 32 hex characters = 16 bytes
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"
```

**Format:** `salt:hash` (e.g., `a1b2c3d4...:e5f6g7h8...`)

**Why salt?**
- Prevents rainbow table attacks
- Same password → different hashes each time

**Why SHA-256 (not bcrypt)?**
- Passwords are temporary (secrets expire)
- Performance: Many concurrent requests
- Trade-off accepted for this use case

---

```python
def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    try:
        salt, hashed = stored_hash.split(":")
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except ValueError:
        return False  # Invalid format = automatic failure
```

**Security note:** The `try/except` prevents timing attacks on malformed hashes.

---

#### SecretStore Class

This is the **storage abstraction layer** that handles both Redis and SQLite.

```python
class SecretStore:
    """Stores encrypted payloads in Redis when available, otherwise SQLite."""

    def __init__(self, redis_url: Optional[str] = None, sqlite_path: str = "vault.db"):
        self.redis_url = redis_url or os.getenv("REDIS_URL")
        self.sqlite_path = sqlite_path
        self.redis_client = None
        self._sqlite_initialized = False
        self._init_lock = asyncio.Lock()  # Prevents race condition on table creation

        if self.redis_url and redis is not None:
            self.redis_client = redis.from_url(
                self.redis_url,
                decode_responses=False,  # We handle bytes ourselves
            )
```

**Design pattern:** Strategy pattern - same interface, different backends.

**Why `decode_responses=False`?**
- We store binary encrypted data
- Auto-decoding would corrupt binary payloads

---

##### save_secret Method

```python
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
        # Redis: Store as JSON with native TTL
        data = json.dumps({
            "payload": cipher_text.decode("latin-1"),  # Binary-safe encoding
            "password_hash": password_hash,
        })
        await self.redis_client.set(secret_id, data.encode(), ex=ttl_seconds)
        return

    await self._save_sqlite(secret_id, cipher_text, ttl_seconds, password_hash)
```

**Why `latin-1` encoding?**
- Preserves all byte values (0-255)
- JSON can't handle raw bytes
- Alternative: base64 (but larger)

**Redis vs SQLite TTL:**
- Redis: Native `ex` (expiration) parameter
- SQLite: Manual `expires_at` timestamp check

---

##### consume_secret Method

```python
async def consume_secret(self, secret_id: str) -> Optional[tuple[bytes, Optional[str]]]:
    """Fetch and delete the secret. Returns (cipher_text, password_hash) or None."""
    if self.using_redis:
        # Atomic get-and-delete using pipeline
        pipeline = self.redis_client.pipeline()
        pipeline.get(secret_id)
        pipeline.delete(secret_id)
        result = await pipeline.execute()
        # ... parse and return
```

**Critical: Pipeline for atomicity**
- `GET` then `DELETE` must be atomic
- Prevents race condition where two requests get the same secret
- Pipeline executes both commands in single round-trip

---

##### SQLite Implementation

```python
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
```

**Schema design:**
- `id`: UUID string (36 chars)
- `payload`: Binary blob (encrypted data)
- `password_hash`: Nullable (optional feature)
- `expires_at`: Unix timestamp for TTL

**Why `BLOB` type?**
- SQLite BLOB stores exact bytes without encoding issues

---

```python
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
        # DELETE regardless of expiration (cleanup)
        conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
        conn.commit()
        conn.close()

        # Check expiration AFTER delete
        if expires_at < now:
            return None
        return (payload, password_hash)

    return await asyncio.to_thread(_fetch_and_delete)
```

**Why delete even if expired?**
- Cleans up expired records
- User sees "not found" either way
- Reduces database bloat

---

### `config.py` - Configuration Management

```python
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_title: str = "The Vault API"
    api_version: str = "1.0.0"

    # ... more settings ...

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False  # API_HOST == api_host


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
```

**Why Pydantic Settings?**
- Type validation for config values
- Automatic `.env` file loading
- Environment variable override support

**Why `@lru_cache`?**
- Settings are immutable at runtime
- Avoids repeated file I/O
- Single source of truth

---

### `backend.py` - FastAPI REST API

#### Application Setup

```python
settings = get_settings()

limiter = Limiter(key_func=get_remote_address, enabled=settings.rate_limit_enabled)

# ... Pydantic models ...

store = SecretStore(redis_url=settings.redis_url, sqlite_path=settings.sqlite_path)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Application lifecycle management."""
    try:
        yield
    finally:
        await store.close()  # Clean up Redis connection


app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    lifespan=lifespan,
    description="Zero-knowledge, one-time secret sharing API.",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permissive for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Why lifespan context manager?**
- Modern FastAPI pattern (replaces deprecated `on_startup`/`on_shutdown`)
- Ensures cleanup even on crashes

**CORS settings:**
- `allow_origins=["*"]` is permissive for development
- In production, restrict to specific domains

---

#### Request/Response Models

```python
class GenerateRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="Plaintext secret.")
    ttl_minutes: int = Field(default=10, ge=1, le=1440, description="Time to live in minutes.")
    password: Optional[str] = Field(default=None, description="Optional password for additional protection.")
    copy_enabled: bool = Field(default=True, description="Whether recipients can copy the message.")

class GenerateResponse(BaseModel):
    uuid: str
    key: str
    expires_in: int
    password_protected: bool
    copy_enabled: bool
```

**Validation built-in:**
- `min_length=1`: No empty secrets
- `max_length=50000`: Prevent memory abuse
- `ge=1, le=1440`: TTL between 1 min and 24 hours
- `copy_enabled` defaults to True for backward compatibility

---

#### Endpoint: Generate Secret

```python
@app.post("/generate", response_model=GenerateResponse, tags=["Secrets"])
@limiter.limit(f"{settings.rate_limit_requests}/minute")
async def generate_secret(request: Request, payload: GenerateRequest) -> GenerateResponse:
    """Generate a new one-time secret with optional password protection."""
    ttl_seconds = payload.ttl_minutes * 60
    secret_id = str(uuid.uuid4())
    key = generate_key()
    cipher_text = encrypt_text(payload.text, key)

    password_hash = hash_password(payload.password) if payload.password else None

    await store.save_secret(
        secret_id=secret_id,
        cipher_text=cipher_text,
        ttl_seconds=ttl_seconds,
        password_hash=password_hash,
    )

    return GenerateResponse(
        uuid=secret_id,
        key=key,  # KEY IS RETURNED, NOT STORED!
        expires_in=ttl_seconds,
        password_protected=payload.password is not None,
    )
```

**Critical flow:**
1. Generate fresh key (never reused)
2. Encrypt user's text
3. Store ONLY encrypted blob
4. Return key to user (server forgets it)

---

#### Endpoint: Retrieve Secret

```python
@app.post("/retrieve/{secret_id}", response_model=RetrieveResponse, tags=["Secrets"])
@limiter.limit(f"{settings.rate_limit_requests}/minute")
async def retrieve_secret(
    request: Request,
    retrieve_payload: RetrieveRequest,
    secret_id: str = Path(..., min_length=1),
) -> RetrieveResponse:
    """Retrieve and destroy a one-time secret."""
    result = await store.consume_secret(secret_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Secret not found or expired.")

    cipher_text, password_hash = result

    # Password check AFTER consuming (burned either way)
    if password_hash:
        if not retrieve_payload.password:
            raise HTTPException(status_code=401, detail="This secret requires a password.")
        if not verify_password(retrieve_payload.password, password_hash):
            raise HTTPException(status_code=401, detail="Incorrect password.")

    try:
        decrypted = decrypt_text(cipher_text, retrieve_payload.key)
    except InvalidDecryptionKey as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RetrieveResponse(decrypted_message=decrypted)
```

**Security decision: Consume first, validate later**
- Even wrong password = secret is burned
- Prevents brute-force password guessing
- User must have link + password correct on first try

---

### `frontend.py` - Streamlit UI

#### Caching Strategy

```python
@st.cache_data(ttl=30)
def get_api_health() -> Optional[dict]:
    """Check API health status with caching."""
    try:
        response = httpx.get(f"{API_BASE_URL}/health", timeout=3)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError:
        return None
```

**Why cache health checks?**
- Prevents hammering the API on every Streamlit rerun
- 30-second TTL balances freshness vs performance

---

#### Dynamic Tab Order

```python
def main() -> None:
    # ... setup ...
    
    params = st.query_params
    has_secret_in_url = bool(params.get("uuid") and params.get("key"))
    
    if has_secret_in_url:
        # User clicked a share link - show View tab first
        tab_names = ["👁️ View Secret", "📝 Create Secret", "ℹ️ About"]
        view_tab, create_tab, about_tab = st.tabs(tab_names)
    else:
        # Normal visit - show Create tab first
        tab_names = ["📝 Create Secret", "👁️ View Secret", "ℹ️ About"]
        create_tab, view_tab, about_tab = st.tabs(tab_names)
```

**UX improvement:**
- When user clicks a share link (`?uuid=...&key=...`)
- View tab is shown first (what they need)
- No confusion about navigation

---

#### Progress Feedback

```python
with st.status("🔄 Creating your secure secret...", expanded=True) as status:
    st.write("Generating encryption key...")
    st.write("Encrypting your secret...")
    
    try:
        data = post_generate_secret(secret_text, ttl_minutes, password)
        st.write("Storing encrypted data...")
        status.update(label="✅ Secret created successfully!", state="complete")
    except httpx.HTTPError as exc:
        status.update(label="❌ Failed to create secret", state="error")
        st.error(f"Error: {exc}")
        return
```

**Why `st.status`?**
- Modern Streamlit component for multi-step operations
- Shows progress without blocking
- Clear success/failure states

---

#### Helper Functions

##### Display Secret Content

```python
def display_secret_content(decrypted_message: str, allow_copy: bool = True) -> None:
```

A reusable helper function that displays the decrypted secret with optional copy restriction.

**What it does:**
- Escapes HTML to prevent rendering issues
- Displays a warning if copy is disabled: "🔒 **Message copying is disabled** - This message cannot be copied or selected."
- Applies the `no-copy` CSS class if copying is disabled (prevents text selection via CSS)
- Renders the message in a styled container with appropriate styling

---

#### Streamlit UI Components → Code Map (Quick Navigation)

This section is a practical index: **which UI component lives in which function**, and where to change it.

##### Entry point

```python
def main() -> None:
```

- Controls page config (`st.set_page_config`) and tab order.
- Decides whether the user is arriving from a share-link by checking `st.query_params`.

##### Header + API status

```python
def render_header() -> None:
```

- Shows the app title and an Online/Offline indicator.
- Uses:
  - `get_api_health()` (cached)
  - `st.columns()` layout

##### Create Secret tab (sender flow)

```python
def render_create_tab() -> None:
```

- **Secret input**: `st.text_area(...)`
- **TTL selection**: `st.selectbox(...)` with human-friendly options
- **Password protection**: `st.checkbox(...)` + `st.text_input(type="password")`
- **Message copy control**: `st.checkbox("📋 Enable Message Copy", value=True)`
  - When enabled, recipients can select and copy the message
  - When disabled, CSS prevents text selection on the recipient's view
  - This setting is stored with the secret and enforced on retrieval
- **Self-destruct UI timer**:
  - `st.number_input("⏲️ Set timer", min_value=3, max_value=60, ...)`
  - This value is embedded into the share-link query string as `sd=<seconds>`.

##### Share-link construction

```python
def build_share_link(secret_id: str, key: str, self_destruct_seconds: Optional[int] = None) -> str:
```

- Generates `http://.../?uuid=<id>&key=<fernet_key>&sd=<seconds>`
- `sd` is **frontend-only** (it does not affect server TTL). It only controls how long the decrypted text is shown on-screen.

##### View Secret tab (recipient flow)

```python
def render_view_tab(has_secret_in_url: bool) -> None:
```

- Reads these query parameters:
  - `uuid` (secret id)
  - `key` (decryption key)
  - `sd` (self-destruct display seconds; optional)

- When the secret is successfully retrieved, it calls:
  - `run_self_destruct_sequence(payload["decrypted_message"], self_destruct_seconds)`

##### Mission-Impossible self-destruct sequence (UI effect)

```python
def run_self_destruct_sequence(decrypted_message: str, seconds: int, allow_copy: bool = True) -> None:
```

What it does:
- Shows the decrypted secret immediately (HTML-escaped to avoid rendering issues).
- If message copying is disabled, displays a warning: "🔒 **Message copying is disabled** - This message cannot be copied or selected."
- Applies CSS class `no-copy` to prevent text selection if copying is disabled.
- Starts a countdown banner: "⏳ Secure display timer: {remaining}s".
- After the countdown completes (reaches 0):
  - Clears the message and countdown banner
  - Displays the self-destruct GIF centered on the page
  - The GIF remains visible

Assets and defaults:
- `SELF_DESTRUCT_GIF_PATH`: Points to `selfish-quotes.gif` (resolved next to `frontend.py`)
- Default timer: `DEFAULT_SELF_DESTRUCT_SECONDS` (overridable by env var `VAULT_SELF_DESTRUCT_SECONDS`)
- `allow_copy` parameter controls whether the message can be selected/copied

**Note:** Audio effects have been removed. Previously, a countdown audio track would play during the timer; this functionality is no longer included.

---

## 3. Data Flow

### Create Secret Flow

```
User Input          Frontend              Backend              Storage
    │                   │                    │                    │
    │  "my secret"      │                    │                    │
    │──────────────────►│                    │                    │
    │                   │                    │                    │
    │                   │  POST /generate    │                    │
    │                   │  {text, ttl}       │                    │
    │                   │───────────────────►│                    │
    │                   │                    │                    │
    │                   │                    │ key = generate()   │
    │                   │                    │ blob = encrypt()   │
    │                   │                    │                    │
    │                   │                    │ save(id, blob)     │
    │                   │                    │───────────────────►│
    │                   │                    │                    │
    │                   │  {uuid, key}       │                    │
    │                   │◄───────────────────│                    │
    │                   │                    │                    │
    │  Share Link       │                    │                    │
    │◄──────────────────│                    │                    │
```

### Retrieve Secret Flow

```
User Click          Frontend              Backend              Storage
    │                   │                    │                    │
    │  ?uuid=&key=      │                    │                    │
    │──────────────────►│                    │                    │
    │                   │                    │                    │
    │                   │ POST /retrieve     │                    │
    │                   │ {key}              │                    │
    │                   │───────────────────►│                    │
    │                   │                    │                    │
    │                   │                    │ consume(id)        │
    │                   │                    │───────────────────►│
    │                   │                    │                    │
    │                   │                    │◄── blob (deleted)  │
    │                   │                    │                    │
    │                   │                    │ decrypt(blob, key) │
    │                   │                    │                    │
    │                   │  {message}         │                    │
    │                   │◄───────────────────│                    │
    │                   │                    │                    │
    │  "my secret"      │                    │                    │
    │◄──────────────────│                    │                    │
```

---

## 4. Key Design Decisions

### Decision 1: Key in URL vs Separate Input

**Chosen:** Key embedded in shareable URL

**Why:**
- Single link = complete access (better UX)
- User doesn't need to manage separate key
- Password protection adds security layer if needed

**Trade-off:**
- Link exposure = secret exposure
- Mitigated by: password protection, short TTL

---

### Decision 2: Burn on Read vs Burn on Decrypt

**Chosen:** Delete from DB before decryption attempt

```python
result = await store.consume_secret(secret_id)  # DELETED HERE
# ... then try to decrypt
```

**Why:**
- Prevents brute-force key guessing
- Even failed attempts burn the secret
- More secure than allowing retries

---

### Decision 3: POST for Retrieve (not GET)

**Chosen:** `POST /retrieve/{id}` with key in body

**Why:**
- Keys don't end up in server access logs
- GET parameters are logged by default
- Body data is typically not logged

---

### Decision 4: No User Accounts

**Chosen:** Anonymous operation only

**Why:**
- Zero-knowledge = no tracking
- Accounts would require storing user data
- Simplicity over features

---

## 5. Security Implementation

### Encryption Details

| Component | Implementation |
|-----------|---------------|
| Algorithm | AES-128-CBC |
| Key Size | 128 bits (32 bytes base64) |
| IV | Random 128 bits per encryption |
| Authentication | HMAC-SHA256 |
| Library | cryptography.fernet |

### Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Brute-force keys | 128-bit key space = infeasible |
| Brute-force passwords | Burn after single attempt |
| Replay attacks | Secret deleted after read |
| Server compromise | No keys stored to steal |
| Traffic analysis | HTTPS + minimal metadata |
| Rate limiting bypass | IP-based limiting |

---

## 6. Testing Strategy

### Unit Tests (`test_utils.py`)

```python
class TestEncryption:
    def test_generate_key_returns_valid_fernet_key(self):
        key = generate_key()
        assert len(key) == 44  # Base64-encoded 32-byte key

    def test_encrypt_decrypt_roundtrip(self):
        key = generate_key()
        plaintext = "Hello, secret world!"
        cipher = encrypt_text(plaintext, key)
        decrypted = decrypt_text(cipher, key)
        assert decrypted == plaintext

    def test_decrypt_with_wrong_key_raises_error(self):
        key1 = generate_key()
        key2 = generate_key()
        cipher = encrypt_text("secret", key1)
        with pytest.raises(InvalidDecryptionKey):
            decrypt_text(cipher, key2)
```

**Coverage:**
- Key generation validity
- Encryption/decryption roundtrip
- Wrong key handling
- Unicode support
- Empty string handling

---

### Integration Tests (`test_api.py`)

```python
class TestRetrieveEndpoint:
    def test_retrieve_secret_burned_after_read(self, client):
        # Create secret
        gen_response = client.post("/generate", json={"text": "one time only", "ttl_minutes": 5})
        data = gen_response.json()

        # First read succeeds
        client.post(f"/retrieve/{data['uuid']}", json={"key": data["key"]})

        # Second read fails (burned)
        second_response = client.post(f"/retrieve/{data['uuid']}", json={"key": data["key"]})
        assert second_response.status_code == 404
```

**Coverage:**
- All endpoints (health, generate, check, retrieve)
- Error conditions (404, 400, 401)
- Password protection flow
- Burn-after-read verification

---

## 7. Common Patterns

### Pattern 1: Async with Thread Pool

```python
async def _consume_sqlite(self, secret_id: str):
    def _blocking_operation():
        # SQLite operations here
        pass
    return await asyncio.to_thread(_blocking_operation)
```

**Why:** SQLite is synchronous, but FastAPI is async. Thread pool prevents blocking.

---

### Pattern 2: Pipeline for Atomicity

```python
pipeline = self.redis_client.pipeline()
pipeline.get(secret_id)
pipeline.delete(secret_id)
result = await pipeline.execute()
```

**Why:** Both operations execute atomically, preventing race conditions.

---

### Pattern 3: Early Return on Error

```python
if result is None:
    raise HTTPException(status_code=404, detail="...")
    # Function exits here

# Only reaches here if result exists
cipher_text, password_hash = result
```

**Why:** Cleaner code, avoids deep nesting.

---

## 8. Extending the Codebase

### Adding a New Storage Backend

1. Create new class implementing same interface as `SecretStore`
2. Required methods:
   - `save_secret(id, cipher_text, ttl, password_hash)`
   - `consume_secret(id) -> (cipher_text, password_hash)`
   - `check_secret(id) -> {"password_protected": bool}`
   - `close()`

### Adding a New Endpoint

1. Define Pydantic request/response models
2. Add async route function with decorators:
   ```python
   @app.post("/new-endpoint", response_model=ResponseModel)
   @limiter.limit("30/minute")
   async def new_endpoint(request: Request, payload: RequestModel):
       pass
   ```
3. Add tests in `tests/test_api.py`

### Adding Frontend Features

1. Create new render function: `def render_new_tab():`
2. Add to tab list in `main()`
3. Use `st.status()` for operations with loading states
4. Cache expensive operations with `@st.cache_data`

---

## Questions?

This documentation covers the core implementation. For specific questions:

1. Check inline comments in source files
2. Run tests with `-v` for verbose output
3. Use FastAPI's `/docs` endpoint for API exploration

---

<p align="center">
  <strong>Happy Coding! 🚀</strong>
</p>
