"""FastAPI application — Next-Level Crypto API."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.api.routes import audit, decrypt, encrypt, keys
from src.api.schemas import ErrorResponse, HealthResponse
from src.exceptions import (
    AlgorithmDisabledError,
    AuthTagError,
    CryptoError,
    KMSError,
)
from src.fips import FIPSMode

_start_time = time.time()

app = FastAPI(
    title="🔐 Next-Level Crypto API",
    description="Enterprise-grade encryption/decryption REST API with post-quantum support",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(encrypt.router, prefix="/v1", tags=["Encryption"])
app.include_router(decrypt.router, prefix="/v1", tags=["Decryption"])
app.include_router(keys.router, prefix="/v1/keys", tags=["Key Management"])
app.include_router(audit.router, prefix="/v1", tags=["Audit"])


# === Exception Handlers ===


@app.exception_handler(AuthTagError)
async def auth_tag_error_handler(request: Request, exc: AuthTagError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": "authentication_failed", "message": str(exc), "detail": None},
    )


@app.exception_handler(AlgorithmDisabledError)
async def algorithm_disabled_handler(request: Request, exc: AlgorithmDisabledError) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "error": "algorithm_disabled",
            "message": str(exc),
            "detail": f"Algorithm '{exc.algorithm}' is not permitted",
        },
    )


@app.exception_handler(KMSError)
async def kms_error_handler(request: Request, exc: KMSError) -> JSONResponse:
    return JSONResponse(
        status_code=502,
        content={
            "error": "kms_error",
            "message": str(exc),
            "detail": f"KMS provider: {exc.provider}",
        },
    )


@app.exception_handler(CryptoError)
async def crypto_error_handler(request: Request, exc: CryptoError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": "crypto_error", "message": str(exc), "detail": None},
    )


# === Health & Info Endpoints ===


@app.get("/v1/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Liveness and readiness check."""
    return HealthResponse(
        status="healthy",
        version="2.0.0",
        fips_mode=FIPSMode.is_enabled(),
        algorithms_available=8,
        uptime_seconds=round(time.time() - _start_time, 2),
    )


@app.get("/v1/algorithms")
async def list_algorithms() -> list[dict]:
    """List available algorithms with security ratings and use-case guidance."""
    algorithms = [
        {
            "name": "AES-256-GCM",
            "family": "symmetric",
            "key_size_bits": 256,
            "security_level": "very-high",
            "use_case": "General-purpose authenticated encryption. Best with AES-NI hardware.",
            "fips_approved": True,
            "nist_recommendation": "SP 800-38D",
        },
        {
            "name": "ChaCha20-Poly1305",
            "family": "symmetric",
            "key_size_bits": 256,
            "security_level": "very-high",
            "use_case": "Authenticated encryption without AES hardware. Constant-time.",
            "fips_approved": True,
            "nist_recommendation": "RFC 8439",
        },
        {
            "name": "RSA-4096-OAEP",
            "family": "asymmetric",
            "key_size_bits": 4096,
            "security_level": "very-high",
            "use_case": "Key exchange, digital signatures. Max 446 bytes plaintext.",
            "fips_approved": True,
            "nist_recommendation": "SP 800-56B",
        },
        {
            "name": "X25519-ECDH",
            "family": "key-agreement",
            "key_size_bits": 256,
            "security_level": "high",
            "use_case": "Ephemeral key agreement with forward secrecy.",
            "fips_approved": True,
            "nist_recommendation": "SP 800-56A",
        },
        {
            "name": "Hybrid RSA+AES",
            "family": "hybrid",
            "key_size_bits": 4096,
            "security_level": "very-high",
            "use_case": "Encrypt large data with RSA key distribution + AES bulk encryption.",
            "fips_approved": True,
            "nist_recommendation": "SP 800-56B + SP 800-38D",
        },
        {
            "name": "Fernet",
            "family": "symmetric",
            "key_size_bits": 256,
            "security_level": "high",
            "use_case": "Simple token encryption with key rotation. AES-128-CBC + HMAC.",
            "fips_approved": True,
            "nist_recommendation": "N/A (higher-level construct)",
        },
        {
            "name": "Argon2id + AES-256-GCM",
            "family": "password-based",
            "key_size_bits": 256,
            "security_level": "high",
            "use_case": "Password-based encryption. Memory-hard KDF resists GPU attacks.",
            "fips_approved": True,
            "nist_recommendation": "RFC 9106",
        },
        {
            "name": "Hybrid X25519 + Kyber-768",
            "family": "post-quantum",
            "key_size_bits": 768,
            "security_level": "post-quantum",
            "use_case": "Quantum-resistant encryption. Belt-and-suspenders with classical crypto.",
            "fips_approved": False,
            "nist_recommendation": "FIPS 203 (ML-KEM)",
        },
    ]
    return algorithms


# === Frontend (production build) ===

_dist_dir = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if _dist_dir.exists():
    @app.get("/", include_in_schema=False)
    async def serve_frontend():
        return FileResponse(_dist_dir / "index.html")

    app.mount("/", StaticFiles(directory=str(_dist_dir), html=True), name="frontend-static")

