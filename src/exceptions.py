"""Custom exception hierarchy for the encryption suite."""

from __future__ import annotations


class CryptoError(Exception):
    """Base exception for all cryptographic operations."""

    def __init__(self, message: str, *, operation: str | None = None) -> None:
        self.operation = operation
        super().__init__(message)


class AuthTagError(CryptoError):
    """Authentication tag verification failed — ciphertext tampered or wrong key."""

    def __init__(self, message: str = "Authentication tag verification failed") -> None:
        super().__init__(message, operation="verify_tag")


class KeyError_(CryptoError):
    """Key-related error (generation, derivation, import, rotation)."""

    def __init__(self, message: str, *, key_id: str | None = None) -> None:
        self.key_id = key_id
        super().__init__(message, operation="key_management")


class NonceReuseError(CryptoError):
    """Nonce/IV reuse detected — catastrophic for GCM/CTR modes."""

    def __init__(self, message: str = "Nonce reuse detected") -> None:
        super().__init__(message, operation="nonce_generation")


class AlgorithmDisabledError(CryptoError):
    """Algorithm is disabled (e.g., not FIPS-approved in FIPS mode)."""

    def __init__(self, algorithm: str, reason: str = "disabled by policy") -> None:
        self.algorithm = algorithm
        super().__init__(f"Algorithm '{algorithm}' is {reason}", operation="algorithm_check")


class KMSError(CryptoError):
    """Error communicating with a Key Management Service."""

    def __init__(self, message: str, *, provider: str | None = None) -> None:
        self.provider = provider
        super().__init__(message, operation="kms")


class StreamingError(CryptoError):
    """Error during streaming encryption/decryption."""

    def __init__(self, message: str, *, chunk_index: int | None = None) -> None:
        self.chunk_index = chunk_index
        super().__init__(message, operation="streaming")


class KeyRotationError(CryptoError):
    """Error during key rotation."""

    def __init__(self, message: str) -> None:
        super().__init__(message, operation="key_rotation")
