"""Pydantic v2 schemas for the Crypto API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# === Request Models ===

class EncryptRequest(BaseModel):
    """Request body for text encryption."""

    plaintext: str = Field(..., description="Base64-encoded plaintext")
    algorithm: Literal["aes-gcm", "chacha20", "rsa-oaep", "hybrid", "ecdh"] = Field(
        default="aes-gcm", description="Encryption algorithm"
    )
    key_id: str | None = Field(None, description="Key ID from key store")
    aad: str | None = Field(None, description="Base64-encoded AAD for AEAD modes")
    recipient_public_key: str | None = Field(
        None, description="PEM-encoded public key for asymmetric modes"
    )


class DecryptRequest(BaseModel):
    """Request body for text decryption."""

    ciphertext: str = Field(..., description="Base64-encoded ciphertext")
    algorithm: Literal["aes-gcm", "chacha20", "rsa-oaep", "hybrid", "ecdh"] = Field(
        default="aes-gcm", description="Encryption algorithm used"
    )
    key_id: str | None = Field(None, description="Key ID from key store")
    aad: str | None = Field(None, description="Base64-encoded AAD for AEAD modes")
    private_key: str | None = Field(
        None, description="PEM-encoded private key for asymmetric modes"
    )


class SignRequest(BaseModel):
    """Request body for digital signature."""

    message: str = Field(..., description="Base64-encoded message to sign")
    algorithm: Literal["rsa-pss", "ed25519"] = Field(
        default="rsa-pss", description="Signature algorithm"
    )
    key_id: str | None = Field(None, description="Signing key ID")
    private_key: str | None = Field(None, description="PEM-encoded private key")


class VerifyRequest(BaseModel):
    """Request body for signature verification."""

    message: str = Field(..., description="Base64-encoded original message")
    signature: str = Field(..., description="Base64-encoded signature")
    algorithm: Literal["rsa-pss", "ed25519"] = Field(
        default="rsa-pss", description="Signature algorithm"
    )
    key_id: str | None = Field(None, description="Verification key ID")
    public_key: str | None = Field(None, description="PEM-encoded public key")


class KeyGenerateRequest(BaseModel):
    """Request body for key generation."""

    algorithm: Literal["aes-256", "chacha20", "rsa-4096", "x25519", "fernet"] = Field(
        default="aes-256", description="Key type to generate"
    )
    key_size: int | None = Field(None, description="Key size in bits (for RSA)")
    expires_in_days: int | None = Field(None, description="Key expiry in days")


class KeyImportRequest(BaseModel):
    """Request body for key import."""

    key_data: str = Field(..., description="PEM or base64-encoded key material")
    algorithm: str = Field(..., description="Algorithm this key is for")
    format: Literal["pem", "raw", "jwk"] = Field(default="pem", description="Key format")


# === Response Models ===

class EncryptResponse(BaseModel):
    """Response for encryption operations."""

    ciphertext: str = Field(..., description="Base64-encoded ciphertext")
    algorithm: str = Field(..., description="Algorithm used")
    key_id: str | None = Field(None, description="Key ID used")
    metadata: dict = Field(default_factory=dict, description="Operation metadata")


class DecryptResponse(BaseModel):
    """Response for decryption operations."""

    plaintext: str = Field(..., description="Base64-encoded decrypted plaintext")
    algorithm: str = Field(..., description="Algorithm used")
    metadata: dict = Field(default_factory=dict, description="Operation metadata")


class SignResponse(BaseModel):
    """Response for signing operations."""

    signature: str = Field(..., description="Base64-encoded signature")
    algorithm: str = Field(..., description="Algorithm used")
    key_id: str | None = Field(None, description="Signing key ID")


class VerifyResponse(BaseModel):
    """Response for verification operations."""

    valid: bool = Field(..., description="Whether signature is valid")
    algorithm: str = Field(..., description="Algorithm used")


class KeyResponse(BaseModel):
    """Response for key operations."""

    key_id: str = Field(..., description="Generated key ID")
    algorithm: str = Field(..., description="Key algorithm")
    public_key: str | None = Field(None, description="PEM-encoded public key (if asymmetric)")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: datetime | None = Field(None, description="Expiry timestamp")


class KeyMetadata(BaseModel):
    """Key metadata (no key material)."""

    key_id: str
    algorithm: str
    key_size: int
    status: str
    created_at: str
    expires_at: str | None = None


class AlgorithmInfo(BaseModel):
    """Information about a supported algorithm."""

    name: str
    family: str
    key_size_bits: int
    security_level: Literal["high", "very-high", "post-quantum"]
    use_case: str
    fips_approved: bool
    nist_recommendation: str


class HealthResponse(BaseModel):
    """Health check response."""

    status: Literal["healthy", "degraded", "unhealthy"]
    version: str
    fips_mode: bool
    algorithms_available: int
    uptime_seconds: float


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Human-readable error message")
    detail: str | None = Field(None, description="Additional detail")
