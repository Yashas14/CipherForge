"""Fernet symmetric encryption with key rotation support.

Security notes:
- Fernet uses AES-128-CBC + HMAC-SHA256 (encrypt-then-MAC)
- Includes timestamp for TTL-based expiry
- MultiFernet supports transparent key rotation
- Lower security margin than AES-256-GCM but simpler API
- Suitable for token-based scenarios (session tokens, API keys at rest)
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from src.exceptions import AuthTagError, CryptoError


class FernetEncryptor:
    """Fernet encryption with built-in key rotation.

    Uses MultiFernet internally to support transparent key rotation:
    - New encryptions always use the first (newest) key
    - Decryption tries all keys in order
    - rotate() re-encrypts with the newest key
    """

    def __init__(self, keys: list[bytes] | None = None) -> None:
        """Initialize with one or more Fernet keys.

        Args:
            keys: List of Fernet keys (newest first). If None, generates one.
        """
        if keys is None:
            keys = [Fernet.generate_key()]
        self._keys = keys
        self._fernets = [Fernet(k) for k in keys]
        self._multi = MultiFernet(self._fernets)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new Fernet key (URL-safe base64-encoded).

        Returns:
            32-byte URL-safe base64-encoded Fernet key.
        """
        return Fernet.generate_key()

    @property
    def keys(self) -> list[bytes]:
        """Return list of active keys (newest first)."""
        return list(self._keys)

    def add_key(self, key: bytes) -> None:
        """Add a new key as the primary (newest) key.

        Args:
            key: New Fernet key to add as primary.
        """
        self._keys.insert(0, key)
        self._fernets.insert(0, Fernet(key))
        self._multi = MultiFernet(self._fernets)

    def remove_key(self, key: bytes) -> None:
        """Remove a retired key from the rotation set.

        Args:
            key: Fernet key to remove.

        Raises:
            CryptoError: If trying to remove the last key.
        """
        if len(self._keys) <= 1:
            raise CryptoError("Cannot remove the last key", operation="fernet_key_mgmt")
        idx = self._keys.index(key)
        self._keys.pop(idx)
        self._fernets.pop(idx)
        self._multi = MultiFernet(self._fernets)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using the newest key.

        Args:
            plaintext: Data to encrypt.

        Returns:
            Fernet token (URL-safe base64-encoded).
        """
        return self._multi.encrypt(plaintext)

    def decrypt(self, token: bytes, ttl: int | None = None) -> bytes:
        """Decrypt a Fernet token.

        Args:
            token: Fernet-encrypted token.
            ttl: Optional time-to-live in seconds. If set, tokens older than
                 this will be rejected even if otherwise valid.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthTagError: If token is invalid, expired, or tampered.
        """
        try:
            return self._multi.decrypt(token, ttl=ttl)
        except InvalidToken as e:
            raise AuthTagError(
                "Fernet decryption failed — invalid token, expired, or tampered"
            ) from e

    def rotate(self, token: bytes) -> bytes:
        """Re-encrypt a token using the newest key.

        Useful during key rotation: decrypt with any valid key,
        re-encrypt with the current primary key.

        Args:
            token: Existing Fernet token.

        Returns:
            New token encrypted with the primary key.

        Raises:
            AuthTagError: If the existing token is invalid.
        """
        try:
            return self._multi.rotate(token)
        except InvalidToken as e:
            raise AuthTagError("Cannot rotate — invalid token") from e
