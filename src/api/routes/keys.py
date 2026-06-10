"""Key management route handlers."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from src.algorithms.aes import AESEncryptor
from src.algorithms.chacha import ChaChaEncryptor
from src.algorithms.ecdh import ECDHEncryptor
from src.algorithms.fernet import FernetEncryptor
from src.algorithms.rsa import RSAEncryptor
from src.api.schemas import (
    KeyGenerateRequest,
    KeyResponse,
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)
from src.audit import audit_logger

router = APIRouter()


@router.post("/generate", response_model=KeyResponse)
async def generate_key(request: KeyGenerateRequest) -> KeyResponse:
    """Generate a new cryptographic key pair or symmetric key."""
    now = datetime.now(UTC)

    if request.algorithm == "aes-256":
        key = AESEncryptor.generate_key()
        key_id = base64.b64encode(key).decode()
        public_key = None

    elif request.algorithm == "chacha20":
        key = ChaChaEncryptor.generate_key()
        key_id = base64.b64encode(key).decode()
        public_key = None

    elif request.algorithm == "rsa-4096":
        _rsa_private, rsa_public = RSAEncryptor.generate_keypair()
        key_id = "rsa-" + base64.b64encode(b"rsa-key")[:8].decode()
        public_key = RSAEncryptor.export_public_key(rsa_public).decode()

    elif request.algorithm == "x25519":
        _x25519_private, x25519_public = ECDHEncryptor.generate_keypair()
        key_id = (
            "x25519-"
            + base64.b64encode(ECDHEncryptor.export_public_key(x25519_public)[:4]).decode()
        )
        public_key = base64.b64encode(ECDHEncryptor.export_public_key(x25519_public)).decode()

    elif request.algorithm == "fernet":
        key = FernetEncryptor.generate_key()
        key_id = key.decode()
        public_key = None

    else:
        raise HTTPException(status_code=400, detail=f"Unknown algorithm: {request.algorithm}")

    await audit_logger.audit(
        operation="key_generate",
        algorithm=request.algorithm,
        key_id=key_id[:16] + "...",
        data_size=0,
        success=True,
    )

    return KeyResponse(
        key_id=key_id,
        algorithm=request.algorithm,
        public_key=public_key,
        created_at=now,
        expires_at=None,
    )


@router.post("/sign", response_model=SignResponse)
async def sign_message(request: SignRequest) -> SignResponse:
    """Create a digital signature."""
    try:
        message = base64.b64decode(request.message)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 message") from exc

    if request.algorithm == "rsa-pss":
        if not request.private_key:
            raise HTTPException(
                status_code=400,
                detail="private_key required for RSA-PSS signing",
            )
        private_key = RSAEncryptor.import_private_key(request.private_key.encode())
        signature = RSAEncryptor.sign(message, private_key)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported sign algorithm: {request.algorithm}",
        )

    await audit_logger.audit(
        operation="sign",
        algorithm=request.algorithm,
        key_id=request.key_id or "provided",
        data_size=len(message),
        success=True,
    )

    return SignResponse(
        signature=base64.b64encode(signature).decode(),
        algorithm=request.algorithm,
        key_id=request.key_id,
    )


@router.post("/verify", response_model=VerifyResponse)
async def verify_signature(request: VerifyRequest) -> VerifyResponse:
    """Verify a digital signature."""
    try:
        message = base64.b64decode(request.message)
        signature = base64.b64decode(request.signature)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 data") from exc

    if request.algorithm == "rsa-pss":
        if not request.public_key:
            raise HTTPException(
                status_code=400,
                detail="public_key required for verification",
            )
        public_key = RSAEncryptor.import_public_key(request.public_key.encode())
        try:
            valid = RSAEncryptor.verify(message, signature, public_key)
        except Exception:
            valid = False
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported verify algorithm: {request.algorithm}",
        )

    await audit_logger.audit(
        operation="verify",
        algorithm=request.algorithm,
        key_id=request.key_id or "provided",
        data_size=len(message),
        success=valid,
    )

    return VerifyResponse(valid=valid, algorithm=request.algorithm)
