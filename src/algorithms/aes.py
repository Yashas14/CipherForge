"""AES-256-GCM authenticated encryption implementation.

Security notes:
- Uses 96-bit (12-byte) random nonces as recommended by NIST SP 800-38D
- Provides authenticated encryption with associated data (AEAD)
- Authentication tag is 128 bits (16 bytes)
- Key size: 256 bits (32 bytes)
- Never reuse a nonce with the same key — nonce collision breaks GCM security
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.exceptions import AuthTagError, CryptoError

# Constants
KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits — NIST recommended for GCM
TAG_SIZE = 16  # 128 bits
HEADER_FORMAT = f"!{NONCE_SIZE}s"  # Network byte order, nonce
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class AESEncryptor:
    """AES-256-GCM authenticated encryption.

    Provides confidentiality and integrity through AEAD construction.
    Each encryption generates a unique random nonce prepended to the ciphertext.

    Wire format: [nonce (12 bytes)][ciphertext + tag (variable)]
    """

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure 256-bit key.

        Returns:
            32 bytes of cryptographically random data suitable for AES-256.
        """
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, aad: bytes | None = None) -> bytes:
        """Encrypt plaintext using AES-256-GCM.

        Args:
            plaintext: Data to encrypt (arbitrary length).
            key: 256-bit (32-byte) encryption key.
            aad: Optional additional authenticated data — authenticated but not encrypted.

        Returns:
            Encrypted blob: nonce (12B) || ciphertext || tag (16B).

        Raises:
            CryptoError: If key size is invalid.
        """
        if len(key) != KEY_SIZE:
            raise CryptoError(
                f"Invalid key size: {len(key)} bytes, expected {KEY_SIZE}",
                operation="aes_encrypt",
            )

        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    @staticmethod
    def decrypt(blob: bytes, key: bytes, aad: bytes | None = None) -> bytes:
        """Decrypt an AES-256-GCM encrypted blob.

        Args:
            blob: Encrypted data (nonce || ciphertext || tag).
            key: 256-bit (32-byte) decryption key.
            aad: Optional AAD — must match what was used during encryption.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthTagError: If authentication tag verification fails (tampered data or wrong key).
            CryptoError: If blob is too short or key is invalid.
        """
        if len(key) != KEY_SIZE:
            raise CryptoError(
                f"Invalid key size: {len(key)} bytes, expected {KEY_SIZE}",
                operation="aes_decrypt",
            )

        if len(blob) < NONCE_SIZE + TAG_SIZE:
            raise CryptoError(
                "Ciphertext too short — missing nonce or auth tag",
                operation="aes_decrypt",
            )

        nonce = blob[:NONCE_SIZE]
        ciphertext = blob[NONCE_SIZE:]

        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise AuthTagError(
                "AES-GCM decryption failed — data may be tampered or key is incorrect"
            ) from e

