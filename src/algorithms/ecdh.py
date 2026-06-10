"""X25519 Elliptic Curve Diffie-Hellman + AES-256-GCM encryption.

Security notes:
- X25519 provides ~128-bit security level (equivalent to RSA-3072)
- Ephemeral key pair generated per encryption — forward secrecy
- Shared secret is passed through HKDF-SHA256 to derive AES key
- Combined with AES-256-GCM for authenticated encryption
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.exceptions import AuthTagError, CryptoError

# Constants
X25519_PUBLIC_KEY_SIZE = 32
NONCE_SIZE = 12
AES_KEY_SIZE = 32
HKDF_INFO = b"x25519-ecdh-aes256gcm-v1"


class ECDHEncryptor:
    """X25519 ECDH + AES-256-GCM hybrid encryption.

    Uses ephemeral X25519 key agreement combined with AES-256-GCM.
    Each encryption uses a fresh ephemeral key — provides forward secrecy.

    Wire format:
        [ephemeral_public_key (32B)][nonce (12B)][ciphertext + tag (variable)]
    """

    @staticmethod
    def generate_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
        """Generate an X25519 key pair.

        Returns:
            Tuple of (private_key, public_key).
        """
        private_key = X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def export_private_key(private_key: X25519PrivateKey) -> bytes:
        """Export X25519 private key as raw 32 bytes.

        Args:
            private_key: X25519 private key.

        Returns:
            Raw 32-byte private key.
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def export_public_key(public_key: X25519PublicKey) -> bytes:
        """Export X25519 public key as raw 32 bytes.

        Args:
            public_key: X25519 public key.

        Returns:
            Raw 32-byte public key.
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def import_private_key(raw_key: bytes) -> X25519PrivateKey:
        """Import X25519 private key from raw bytes.

        Args:
            raw_key: 32-byte raw private key.

        Returns:
            X25519PrivateKey object.
        """
        return X25519PrivateKey.from_private_bytes(raw_key)

    @staticmethod
    def import_public_key(raw_key: bytes) -> X25519PublicKey:
        """Import X25519 public key from raw bytes.

        Args:
            raw_key: 32-byte raw public key.

        Returns:
            X25519PublicKey object.
        """
        return X25519PublicKey.from_public_bytes(raw_key)

    @staticmethod
    def _derive_key(shared_secret: bytes, salt: bytes | None = None) -> bytes:
        """Derive AES-256 key from shared secret using HKDF-SHA256.

        Args:
            shared_secret: Raw X25519 shared secret (32 bytes).
            salt: Optional salt for HKDF (random if None).

        Returns:
            32-byte derived AES key.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            info=HKDF_INFO,
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def encrypt(
        plaintext: bytes, recipient_public_key: X25519PublicKey, aad: bytes | None = None,
    ) -> bytes:
        """Encrypt using ephemeral ECDH + AES-256-GCM.

        Generates an ephemeral key pair, performs X25519, derives AES key via HKDF,
        then encrypts with AES-256-GCM.

        Args:
            plaintext: Data to encrypt.
            recipient_public_key: Recipient's X25519 public key.
            aad: Optional additional authenticated data.

        Returns:
            Encrypted blob: ephemeral_pub (32B) || nonce (12B) || ciphertext || tag (16B).
        """
        # Generate ephemeral key pair
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()

        # Perform key exchange
        shared_secret = ephemeral_private.exchange(recipient_public_key)

        # Derive AES key
        aes_key = ECDHEncryptor._derive_key(shared_secret)

        # Encrypt with AES-256-GCM
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Export ephemeral public key
        ephemeral_pub_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return ephemeral_pub_bytes + nonce + ciphertext

    @staticmethod
    def decrypt(
        blob: bytes,
        recipient_private_key: X25519PrivateKey,
        aad: bytes | None = None,
    ) -> bytes:
        """Decrypt an ECDH + AES-256-GCM encrypted blob.

        Args:
            blob: Encrypted data (ephemeral_pub || nonce || ciphertext || tag).
            recipient_private_key: Recipient's X25519 private key.
            aad: Optional additional authenticated data.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthTagError: If authentication fails.
            CryptoError: If blob is malformed.
        """
        min_size = X25519_PUBLIC_KEY_SIZE + NONCE_SIZE + 16  # key + nonce + tag
        if len(blob) < min_size:
            raise CryptoError(
                f"ECDH blob too short: {len(blob)} bytes (minimum {min_size})",
                operation="ecdh_decrypt",
            )

        # Parse blob
        ephemeral_pub_bytes = blob[:X25519_PUBLIC_KEY_SIZE]
        nonce = blob[X25519_PUBLIC_KEY_SIZE : X25519_PUBLIC_KEY_SIZE + NONCE_SIZE]
        ciphertext = blob[X25519_PUBLIC_KEY_SIZE + NONCE_SIZE :]

        # Reconstruct ephemeral public key
        ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)

        # Perform key exchange
        shared_secret = recipient_private_key.exchange(ephemeral_public)

        # Derive AES key
        aes_key = ECDHEncryptor._derive_key(shared_secret)

        # Decrypt
        aesgcm = AESGCM(aes_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise AuthTagError(
                "ECDH+AES-GCM decryption failed — wrong key or tampered data"
            ) from e
