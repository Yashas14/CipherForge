"""Encryption route handlers."""

from __future__ import annotations

import base64

from fastapi import APIRouter, File, HTTPException, UploadFile

from src.algorithms.aes import AESEncryptor
from src.algorithms.chacha import ChaChaEncryptor
from src.algorithms.ecdh import ECDHEncryptor
from src.algorithms.hybrid import HybridEncryptor
from src.algorithms.rsa import RSAEncryptor
from src.api.schemas import EncryptRequest, EncryptResponse
from src.audit import AuditTimer, audit_logger
from src.fips import FIPSMode

router = APIRouter()


@router.post("/encrypt/text", response_model=EncryptResponse)
async def encrypt_text(request: EncryptRequest) -> EncryptResponse:
    """Encrypt a text string using the specified algorithm."""
    FIPSMode.check_algorithm(request.algorithm)

    try:
        plaintext = base64.b64decode(request.plaintext)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 plaintext") from exc

    aad = base64.b64decode(request.aad) if request.aad else None

    with AuditTimer() as timer:
        if request.algorithm == "aes-gcm":
            if request.key_id:
                # TODO: fetch from keystore
                raise HTTPException(status_code=501, detail="Key store lookup not yet wired")
            key = AESEncryptor.generate_key()
            ciphertext = AESEncryptor.encrypt(plaintext, key, aad)
            key_b64 = base64.b64encode(key).decode()
            metadata = {"key": key_b64, "nonce_size": 12, "tag_size": 16}

        elif request.algorithm == "chacha20":
            key = ChaChaEncryptor.generate_key()
            ciphertext = ChaChaEncryptor.encrypt(plaintext, key, aad)
            key_b64 = base64.b64encode(key).decode()
            metadata = {"key": key_b64, "nonce_size": 12, "tag_size": 16}

        elif request.algorithm == "rsa-oaep":
            if not request.recipient_public_key:
                raise HTTPException(
                    status_code=400,
                    detail="recipient_public_key required for RSA-OAEP",
                )
            public_key = RSAEncryptor.import_public_key(
                request.recipient_public_key.encode()
            )
            ciphertext = RSAEncryptor.encrypt(plaintext, public_key)
            metadata = {"key_size_bits": 4096, "padding": "OAEP-SHA256"}

        elif request.algorithm == "hybrid":
            if not request.recipient_public_key:
                raise HTTPException(
                    status_code=400,
                    detail="recipient_public_key required for hybrid encryption",
                )
            public_key = RSAEncryptor.import_public_key(
                request.recipient_public_key.encode()
            )
            ciphertext = HybridEncryptor.encrypt(plaintext, public_key, aad)
            metadata = {"rsa_key_bits": 4096, "aes_key_bits": 256}

        elif request.algorithm == "ecdh":
            if not request.recipient_public_key:
                raise HTTPException(
                    status_code=400,
                    detail="recipient_public_key required for ECDH",
                )
            pub_bytes = base64.b64decode(request.recipient_public_key)
            public_key = ECDHEncryptor.import_public_key(pub_bytes)
            ciphertext = ECDHEncryptor.encrypt(plaintext, public_key, aad)
            metadata = {"curve": "X25519", "aes_key_bits": 256}

        else:
            raise HTTPException(status_code=400, detail=f"Unknown algorithm: {request.algorithm}")

    await audit_logger.audit(
        operation="encrypt",
        algorithm=request.algorithm,
        key_id=request.key_id or "ephemeral",
        data_size=len(plaintext),
        success=True,
        duration_ms=timer.duration_ms,
    )

    return EncryptResponse(
        ciphertext=base64.b64encode(ciphertext).decode(),
        algorithm=request.algorithm,
        key_id=request.key_id,
        metadata=metadata,
    )


@router.post("/encrypt/file")
async def encrypt_file(
    file: UploadFile = File(...),  # noqa: B008
    algorithm: str = "aes-gcm",
) -> EncryptResponse:
    """Encrypt an uploaded file."""
    FIPSMode.check_algorithm(algorithm)

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    with AuditTimer() as timer:
        if algorithm == "aes-gcm":
            key = AESEncryptor.generate_key()
            ciphertext = AESEncryptor.encrypt(content, key)
            metadata = {
                "key": base64.b64encode(key).decode(),
                "original_filename": file.filename,
                "original_size": len(content),
            }
        elif algorithm == "chacha20":
            key = ChaChaEncryptor.generate_key()
            ciphertext = ChaChaEncryptor.encrypt(content, key)
            metadata = {
                "key": base64.b64encode(key).decode(),
                "original_filename": file.filename,
                "original_size": len(content),
            }
        else:
            raise HTTPException(
                status_code=400,
                detail=f"File encryption supports aes-gcm or chacha20, got: {algorithm}",
            )

    await audit_logger.audit(
        operation="encrypt",
        algorithm=algorithm,
        key_id="ephemeral",
        data_size=len(content),
        success=True,
        duration_ms=timer.duration_ms,
    )

    return EncryptResponse(
        ciphertext=base64.b64encode(ciphertext).decode(),
        algorithm=algorithm,
        key_id=None,
        metadata=metadata,
    )
