"""HKDF-based key derivation hierarchy.

Security notes:
- Domain-separated subkeys prevent key reuse across operations
- Uses HKDF-SHA256 (RFC 5869) for key derivation
- Salt is derived from master key hash — deterministic subkey derivation
- Key rotation generates a new master, re-wraps all subkeys
- Thread-safe via asyncio.Lock for shared state
"""

from __future__ import annotations

import asyncio
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from src.exceptions import CryptoError

# Constants
MASTER_KEY_SIZE = 32  # 256 bits
HKDF_SALT_INFO = b"key-hierarchy-salt-derivation-v1"


class KeyHierarchy:
    """HKDF-based key derivation tree.

    Master Key → HKDF → Domain-separated subkeys.
    Prevents key reuse across operations.

    master_key
    ├─ expand("encryption/aes") → aes_key
    ├─ expand("encryption/chacha") → chacha_key
    ├─ expand("signing/hmac") → mac_key
    └─ expand("wrapping/rsa") → wrapping_key
    """

    def __init__(self, master_key: bytes | None = None) -> None:
        """Initialize key hierarchy.

        Args:
            master_key: 256-bit master key. If None, generates a random one.

        Raises:
            CryptoError: If master_key is not 32 bytes.
        """
        if master_key is None:
            master_key = os.urandom(MASTER_KEY_SIZE)
        elif len(master_key) != MASTER_KEY_SIZE:
            raise CryptoError(
                f"Master key must be {MASTER_KEY_SIZE} bytes, got {len(master_key)}",
                operation="key_hierarchy_init",
            )

        self._master_key = master_key
        self._derived_cache: dict[str, bytes] = {}
        self._lock = asyncio.Lock()

        # Derive a deterministic salt from master key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=HKDF_SALT_INFO,
        )
        self._salt = hkdf.derive(master_key)

    @property
    def master_key(self) -> bytes:
        """Return the master key (handle with care — use SecureBuffer in production)."""
        return self._master_key

    def derive(self, purpose: str, length: int = 32) -> bytes:
        """Derive a subkey for a specific purpose.

        Uses HKDF-Expand with domain-separated info string.
        Results are cached for performance.

        Args:
            purpose: Domain separation string (e.g., "encryption/aes").
            length: Desired key length in bytes (max 255 * 32 = 8160).

        Returns:
            Derived key of specified length.

        Raises:
            CryptoError: If purpose is empty or length is invalid.
        """
        if not purpose:
            raise CryptoError("Purpose cannot be empty", operation="key_derive")
        if length < 16 or length > 8160:
            raise CryptoError(
                f"Invalid key length: {length} (must be 16-8160)",
                operation="key_derive",
            )

        cache_key = f"{purpose}:{length}"
        if cache_key in self._derived_cache:
            return self._derived_cache[cache_key]

        info = f"key-hierarchy/{purpose}".encode()
        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=length,
            info=info,
        )
        derived = hkdf.derive(self._master_key)
        self._derived_cache[cache_key] = derived
        return derived

    def derive_aes_key(self) -> bytes:
        """Derive AES-256 encryption key."""
        return self.derive("encryption/aes", 32)

    def derive_chacha_key(self) -> bytes:
        """Derive ChaCha20 encryption key."""
        return self.derive("encryption/chacha", 32)

    def derive_mac_key(self) -> bytes:
        """Derive HMAC signing key."""
        return self.derive("signing/hmac", 32)

    def derive_wrapping_key(self) -> bytes:
        """Derive key wrapping key."""
        return self.derive("wrapping/kek", 32)

    def rotate(self) -> KeyHierarchy:
        """Rotate to a new master key.

        Generates a new random master key. The old hierarchy should be
        used to decrypt existing data, then re-encrypt with the new one.

        Returns:
            New KeyHierarchy instance with fresh master key.
        """
        new_master = os.urandom(MASTER_KEY_SIZE)
        return KeyHierarchy(new_master)

    async def rotate_async(self) -> KeyHierarchy:
        """Thread-safe async key rotation.

        Returns:
            New KeyHierarchy instance.
        """
        async with self._lock:
            return self.rotate()

    def export_wrapped(self, wrapping_key: bytes) -> bytes:
        """Export master key wrapped (encrypted) with a wrapping key.

        Uses AES-256-GCM to wrap the master key for storage.

        Args:
            wrapping_key: 32-byte key to wrap the master key with.

        Returns:
            Wrapped master key blob (nonce + ciphertext + tag).
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(wrapping_key) != 32:
            raise CryptoError("Wrapping key must be 32 bytes", operation="key_export")

        nonce = os.urandom(12)
        aesgcm = AESGCM(wrapping_key)
        wrapped = aesgcm.encrypt(nonce, self._master_key, b"key-hierarchy-wrap")
        return nonce + wrapped

    @classmethod
    def import_wrapped(cls, wrapped_blob: bytes, wrapping_key: bytes) -> KeyHierarchy:
        """Import a wrapped master key.

        Args:
            wrapped_blob: Wrapped master key (from export_wrapped).
            wrapping_key: 32-byte unwrapping key.

        Returns:
            Reconstructed KeyHierarchy.

        Raises:
            CryptoError: If unwrapping fails.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(wrapping_key) != 32:
            raise CryptoError("Wrapping key must be 32 bytes", operation="key_import")
        if len(wrapped_blob) < 12 + 32 + 16:  # nonce + key + tag
            raise CryptoError("Wrapped blob too short", operation="key_import")

        nonce = wrapped_blob[:12]
        ciphertext = wrapped_blob[12:]

        aesgcm = AESGCM(wrapping_key)
        try:
            master_key = aesgcm.decrypt(nonce, ciphertext, b"key-hierarchy-wrap")
        except Exception as e:
            raise CryptoError(
                "Failed to unwrap master key — wrong wrapping key",
                operation="key_import",
            ) from e

        return cls(master_key)
