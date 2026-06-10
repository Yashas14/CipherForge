"""Decryption route handlers."""

from __future__ import annotations

import base64

from fastapi import APIRouter, File, HTTPException, UploadFile

from src.algorithms.aes import AESEncryptor
from src.algorithms.chacha import ChaChaEncryptor
from src.algorithms.ecdh import ECDHEncryptor
from src.algorithms.hybrid import HybridEncryptor
from src.algorithms.rsa import RSAEncryptor
from src.api.schemas import DecryptRequest, DecryptResponse
from src.audit import AuditTimer, audit_logger
from src.fips import FIPSMode

router = APIRouter()


@router.post("/decrypt/text", response_model=DecryptResponse)
async def decrypt_text(request: DecryptRequest) -> DecryptResponse:
    """Decrypt ciphertext using the specified algorithm."""
    FIPSMode.check_algorithm(request.algorithm)

    try:
        ciphertext = base64.b64decode(request.ciphertext)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 ciphertext") from exc

    aad = base64.b64decode(request.aad) if request.aad else None

    with AuditTimer() as timer:
        if request.algorithm == "aes-gcm":
            if not request.key_id:
                raise HTTPException(
                    status_code=400, detail="key_id or key required for AES-GCM decryption"
                )
            # Key is passed as key_id (base64-encoded key for demo purposes)
            try:
                key = base64.b64decode(request.key_id)
            except Exception as exc:
                raise HTTPException(status_code=400, detail="Invalid key format") from exc
            plaintext = AESEncryptor.decrypt(ciphertext, key, aad)

        elif request.algorithm == "chacha20":
            if not request.key_id:
                raise HTTPException(status_code=400, detail="key_id required for ChaCha20")
            key = base64.b64decode(request.key_id)
            plaintext = ChaChaEncryptor.decrypt(ciphertext, key, aad)

        elif request.algorithm == "rsa-oaep":
            if not request.private_key:
                raise HTTPException(
                    status_code=400, detail="private_key required for RSA-OAEP decryption"
                )
            rsa_private_key = RSAEncryptor.import_private_key(request.private_key.encode())
            plaintext = RSAEncryptor.decrypt(ciphertext, rsa_private_key)

        elif request.algorithm == "hybrid":
            if not request.private_key:
                raise HTTPException(
                    status_code=400, detail="private_key required for hybrid decryption"
                )
            rsa_private_key = RSAEncryptor.import_private_key(request.private_key.encode())
            plaintext = HybridEncryptor.decrypt(ciphertext, rsa_private_key, aad)

        elif request.algorithm == "ecdh":
            if not request.private_key:
                raise HTTPException(
                    status_code=400, detail="private_key required for ECDH decryption"
                )
            priv_bytes = base64.b64decode(request.private_key)
            x25519_private_key = ECDHEncryptor.import_private_key(priv_bytes)
            plaintext = ECDHEncryptor.decrypt(ciphertext, x25519_private_key, aad)

        else:
            raise HTTPException(status_code=400, detail=f"Unknown algorithm: {request.algorithm}")

    await audit_logger.audit(
        operation="decrypt",
        algorithm=request.algorithm,
        key_id=request.key_id or "provided",
        data_size=len(ciphertext),
        success=True,
        duration_ms=timer.duration_ms,
    )

    return DecryptResponse(
        plaintext=base64.b64encode(plaintext).decode(),
        algorithm=request.algorithm,
        metadata={"decrypted_size": len(plaintext)},
    )


@router.post("/decrypt/file")
async def decrypt_file(
    file: UploadFile = File(...),  # noqa: B008
    algorithm: str = "aes-gcm",
    key: str = "",
) -> DecryptResponse:
    """Decrypt an uploaded encrypted file."""
    FIPSMode.check_algorithm(algorithm)

    if not key:
        raise HTTPException(status_code=400, detail="key query parameter required")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    try:
        key_bytes = base64.b64decode(key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 key") from exc

    with AuditTimer() as timer:
        if algorithm == "aes-gcm":
            plaintext = AESEncryptor.decrypt(content, key_bytes)
        elif algorithm == "chacha20":
            plaintext = ChaChaEncryptor.decrypt(content, key_bytes)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"File decryption supports aes-gcm or chacha20, got: {algorithm}",
            )

    await audit_logger.audit(
        operation="decrypt",
        algorithm=algorithm,
        key_id="provided",
        data_size=len(content),
        success=True,
        duration_ms=timer.duration_ms,
    )

    return DecryptResponse(
        plaintext=base64.b64encode(plaintext).decode(),
        algorithm=algorithm,
        metadata={"decrypted_size": len(plaintext)},
    )
