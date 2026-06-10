"""Argon2id password-based encryption (Argon2id KDF + AES-256-GCM).

Security notes:
- Argon2id is the recommended password hashing algorithm (OWASP, RFC 9106)
- Combines Argon2i (memory-hard) and Argon2d (data-dependent) for resistance
  against both side-channel and GPU/ASIC attacks
- Parameters: memory=64MB, iterations=3, parallelism=4 (OWASP minimum recommendations)
- Random 16-byte salt per encryption — stored with ciphertext
- Derives 256-bit key for AES-256-GCM
"""

from __future__ import annotations

import os
import struct

import argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.exceptions import AuthTagError, CryptoError

# Argon2id parameters (OWASP recommendations for 2024+)
ARGON2_TIME_COST = 3  # iterations
ARGON2_MEMORY_COST = 65536  # 64 MB in KiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32  # 256-bit key
ARGON2_SALT_LEN = 16  # 128-bit salt
ARGON2_TYPE = argon2.Type.ID  # Argon2id

# AES-GCM parameters
NONCE_SIZE = 12

# Wire format header
# [salt_len(1)][salt][time_cost(4)][memory_cost(4)][parallelism(4)][nonce(12)][ciphertext+tag]
PARAM_HEADER_FORMAT = "!BIII"  # salt_len, time_cost, memory_cost, parallelism
PARAM_HEADER_SIZE = struct.calcsize(PARAM_HEADER_FORMAT)


class Argon2Encryptor:
    """Password-based encryption using Argon2id + AES-256-GCM.

    Derives a 256-bit key from a password using Argon2id, then encrypts
    data with AES-256-GCM. Parameters are stored alongside the ciphertext
    for future-proofing (allows adjusting cost parameters over time).

    Wire format:
        [salt_len (1B)][salt (16B)][time_cost (4B)][memory_cost (4B)]
        [parallelism (4B)][nonce (12B)][ciphertext + tag]
    """

    def __init__(
        self,
        time_cost: int = ARGON2_TIME_COST,
        memory_cost: int = ARGON2_MEMORY_COST,
        parallelism: int = ARGON2_PARALLELISM,
    ) -> None:
        """Initialize with KDF parameters.

        Args:
            time_cost: Number of iterations (higher = slower, more secure).
            memory_cost: Memory usage in KiB (higher = more GPU-resistant).
            parallelism: Number of parallel threads.
        """
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive a 256-bit AES key from password using Argon2id.

        Args:
            password: User password (any bytes).
            salt: Random 16-byte salt.

        Returns:
            32-byte derived key.
        """
        hasher = argon2.low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=ARGON2_HASH_LEN,
            type=ARGON2_TYPE,
        )
        return hasher

    def encrypt(self, plaintext: bytes, password: bytes, aad: bytes | None = None) -> bytes:
        """Encrypt data with a password.

        Args:
            plaintext: Data to encrypt.
            password: Password to derive encryption key from.
            aad: Optional additional authenticated data.

        Returns:
            Encrypted blob with embedded KDF parameters.
        """
        if not password:
            raise CryptoError("Password cannot be empty", operation="argon2_encrypt")

        # Generate random salt
        salt = os.urandom(ARGON2_SALT_LEN)

        # Derive key
        key = self._derive_key(password, salt)

        # Encrypt with AES-256-GCM
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Build wire format
        header = struct.pack(
            PARAM_HEADER_FORMAT,
            len(salt),
            self.time_cost,
            self.memory_cost,
            self.parallelism,
        )
        return header + salt + nonce + ciphertext

    def decrypt(self, blob: bytes, password: bytes, aad: bytes | None = None) -> bytes:
        """Decrypt password-encrypted data.

        Args:
            blob: Encrypted blob with KDF parameters.
            password: Password used during encryption.
            aad: Optional additional authenticated data.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthTagError: If password is wrong or data is tampered.
            CryptoError: If blob is malformed.
        """
        if len(blob) < PARAM_HEADER_SIZE + ARGON2_SALT_LEN + NONCE_SIZE + 16:
            raise CryptoError("Argon2 blob too short", operation="argon2_decrypt")

        # Parse header
        offset = 0
        salt_len, time_cost, memory_cost, parallelism = struct.unpack(
            PARAM_HEADER_FORMAT, blob[offset : offset + PARAM_HEADER_SIZE]
        )
        offset += PARAM_HEADER_SIZE

        # Extract salt
        salt = blob[offset : offset + salt_len]
        offset += salt_len

        # Extract nonce
        nonce = blob[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE

        # Remaining is ciphertext + tag
        ciphertext = blob[offset:]

        # Derive key with stored parameters
        key = argon2.low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=ARGON2_HASH_LEN,
            type=ARGON2_TYPE,
        )

        # Decrypt
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise AuthTagError(
                "Argon2+AES-GCM decryption failed — wrong password or tampered data"
            ) from e
