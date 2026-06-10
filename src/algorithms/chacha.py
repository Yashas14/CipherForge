"""ChaCha20-Poly1305 authenticated encryption implementation.

Security notes:
- Uses 96-bit (12-byte) random nonces
- Provides AEAD with 128-bit Poly1305 authentication tag
- Key size: 256 bits (32 bytes)
- Preferred over AES-GCM on platforms without AES hardware acceleration
- Constant-time implementation — resistant to cache-timing side channels
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from src.exceptions import AuthTagError, CryptoError

# Constants
KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits
TAG_SIZE = 16  # 128 bits (Poly1305)


class ChaChaEncryptor:
    """ChaCha20-Poly1305 authenticated encryption.

    Software-friendly AEAD cipher. Constant-time on all platforms — no
    timing side-channel risk from cache misses (unlike AES without AES-NI).

    Wire format: [nonce (12 bytes)][ciphertext + tag (variable)]
    """

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure 256-bit key.

        Returns:
            32 bytes of cryptographically random data.
        """
        return ChaCha20Poly1305.generate_key()

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, aad: bytes | None = None) -> bytes:
        """Encrypt plaintext using ChaCha20-Poly1305.

        Args:
            plaintext: Data to encrypt.
            key: 256-bit (32-byte) encryption key.
            aad: Optional additional authenticated data.

        Returns:
            Encrypted blob: nonce (12B) || ciphertext || tag (16B).

        Raises:
            CryptoError: If key size is invalid.
        """
        if len(key) != KEY_SIZE:
            raise CryptoError(
                f"Invalid key size: {len(key)} bytes, expected {KEY_SIZE}",
                operation="chacha_encrypt",
            )

        nonce = os.urandom(NONCE_SIZE)
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    @staticmethod
    def decrypt(blob: bytes, key: bytes, aad: bytes | None = None) -> bytes:
        """Decrypt a ChaCha20-Poly1305 encrypted blob.

        Args:
            blob: Encrypted data (nonce || ciphertext || tag).
            key: 256-bit (32-byte) decryption key.
            aad: Optional additional authenticated data.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthTagError: If Poly1305 tag verification fails.
            CryptoError: If blob is too short or key is invalid.
        """
        if len(key) != KEY_SIZE:
            raise CryptoError(
                f"Invalid key size: {len(key)} bytes, expected {KEY_SIZE}",
                operation="chacha_decrypt",
            )

        if len(blob) < NONCE_SIZE + TAG_SIZE:
            raise CryptoError(
                "Ciphertext too short — missing nonce or auth tag",
                operation="chacha_decrypt",
            )

        nonce = blob[:NONCE_SIZE]
        ciphertext = blob[NONCE_SIZE:]

        chacha = ChaCha20Poly1305(key)
        try:
            return chacha.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise AuthTagError(
                "ChaCha20-Poly1305 decryption failed — data tampered or wrong key"
            ) from e
