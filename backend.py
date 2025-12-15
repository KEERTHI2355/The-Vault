import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Path, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from config import get_settings
from utils import (
    InvalidDecryptionKey,
    SecretStore,
    decrypt_text,
    encrypt_text,
    generate_key,
    hash_password,
    verify_password,
)

settings = get_settings()

limiter = Limiter(key_func=get_remote_address, enabled=settings.rate_limit_enabled)


class GenerateRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="Plaintext secret.")
    ttl_minutes: int = Field(default=10, ge=1, le=1440, description="Time to live in minutes.")
    password: Optional[str] = Field(default=None, description="Optional password for additional protection.")


class GenerateResponse(BaseModel):
    uuid: str
    key: str
    expires_in: int
    password_protected: bool


class RetrieveRequest(BaseModel):
    key: str = Field(..., min_length=1, description="Fernet key needed for decryption.")
    password: Optional[str] = Field(
        default=None,
        description="Password if the secret is password-protected.",
    )


class RetrieveResponse(BaseModel):
    decrypted_message: str


class HealthResponse(BaseModel):
    status: str
    storage_backend: str
    timestamp: str
    version: str


class SecretCheckResponse(BaseModel):
    exists: bool
    password_protected: bool


store = SecretStore(redis_url=settings.redis_url, sqlite_path=settings.sqlite_path)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"},
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        yield
    finally:
        await store.close()


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
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """Check API health and storage backend status."""
    return HealthResponse(
        status="healthy",
        storage_backend="redis" if store.using_redis else "sqlite",
        timestamp=datetime.now(timezone.utc).isoformat(),
        version=settings.api_version,
    )


@app.get("/check/{secret_id}", response_model=SecretCheckResponse, tags=["Secrets"])
@limiter.limit(f"{settings.rate_limit_requests}/minute")
async def check_secret(request: Request, secret_id: str = Path(..., min_length=1)) -> SecretCheckResponse:
    """Check if a secret exists and whether it's password-protected (without consuming it)."""
    metadata = await store.check_secret(secret_id)
    if metadata is None:
        return SecretCheckResponse(exists=False, password_protected=False)
    return SecretCheckResponse(exists=True, password_protected=metadata.get("password_protected", False))


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
        key=key,
        expires_in=ttl_seconds,
        password_protected=payload.password is not None,
    )


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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )
