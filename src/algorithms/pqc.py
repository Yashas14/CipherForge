"""Post-Quantum Cryptography: Hybrid X25519 + Kyber-768 encryption.

Security notes:
- Combines classical X25519 with post-quantum Kyber-768 (NIST PQC standard 2024)
- XOR of both shared secrets fed to HKDF → AES-256-GCM key
- "Belt and suspenders" approach: secure even if either algorithm is broken
- Falls back to X25519-only if liboqs is unavailable
- Dilithium signatures for quantum-resistant digital signatures

Note: Requires liboqs-python (optional dependency).
Install with: pip install encryption-suite-v2[pqc]
"""

from __future__ import annotations

import os
import struct
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.exceptions import AuthTagError, CryptoError

# Try to import liboqs
try:
    import oqs  # type: ignore[import-untyped]

    HAS_LIBOQS = True
except ImportError:
    HAS_LIBOQS = False

# Constants
NONCE_SIZE = 12
AES_KEY_SIZE = 32
HKDF_INFO_HYBRID = b"hybrid-x25519-kyber768-aes256gcm-v1"
HKDF_INFO_CLASSICAL = b"x25519-aes256gcm-fallback-v1"
KYBER_ALGORITHM = "Kyber768"
DILITHIUM_ALGORITHM = "Dilithium3"


class HybridPQC:
    """Hybrid X25519 + Kyber-768 post-quantum encryption.

    Combines classical X25519 ECDH with post-quantum Kyber-768 KEM.
    XOR the shared secrets → feed to HKDF → AES-256-GCM key.
    Secure even if either algorithm is broken.

    Wire format (hybrid mode):
        [version (1B)][classical_pub (32B)][pq_ciphertext_len (2B)][pq_ciphertext]
        [nonce (12B)][aes_ciphertext + tag]

    Wire format (fallback mode — no liboqs):
        [version (1B)][classical_pub (32B)][nonce (12B)][aes_ciphertext + tag]
    """

    VERSION_HYBRID = 0x01
    VERSION_CLASSICAL_ONLY = 0x02

    @staticmethod
    def is_available() -> bool:
        """Check if post-quantum algorithms are available."""
        return HAS_LIBOQS

    @staticmethod
    def generate_keypair() -> dict[str, Any]:
        """Generate hybrid key pair (X25519 + Kyber-768).

        Returns:
            Dictionary with keys:
                - classical_private: X25519PrivateKey
                - classical_public: X25519PublicKey
                - pq_private: Kyber-768 secret key bytes (if available)
                - pq_public: Kyber-768 public key bytes (if available)
                - has_pqc: bool indicating if PQC keys are present
        """
        # Classical key pair
        classical_private = X25519PrivateKey.generate()
        classical_public = classical_private.public_key()

        result: dict[str, Any] = {
            "classical_private": classical_private,
            "classical_public": classical_public,
            "has_pqc": False,
            "pq_private": None,
            "pq_public": None,
        }

        # Post-quantum key pair (if available)
        if HAS_LIBOQS:
            kem = oqs.KeyEncapsulation(KYBER_ALGORITHM)
            pq_public = kem.generate_keypair()
            pq_private = kem.export_secret_key()
            result["pq_public"] = pq_public
            result["pq_private"] = pq_private
            result["has_pqc"] = True

        return result

    @staticmethod
    def encrypt(
        plaintext: bytes,
        recipient_classical_pub: X25519PublicKey,
        recipient_pq_pub: bytes | None = None,
        aad: bytes | None = None,
    ) -> bytes:
        """Encrypt using hybrid X25519 + Kyber-768 (or X25519-only fallback).

        Args:
            plaintext: Data to encrypt.
            recipient_classical_pub: Recipient's X25519 public key.
            recipient_pq_pub: Recipient's Kyber-768 public key (optional).
            aad: Optional additional authenticated data.

        Returns:
            Encrypted blob with version byte indicating mode.
        """
        # Generate ephemeral classical key
        ephemeral_classical = X25519PrivateKey.generate()
        ephemeral_classical_pub = ephemeral_classical.public_key()
        classical_pub_bytes = ephemeral_classical_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Classical key exchange
        classical_shared = ephemeral_classical.exchange(recipient_classical_pub)

        if HAS_LIBOQS and recipient_pq_pub is not None:
            # Hybrid mode: X25519 + Kyber-768
            kem = oqs.KeyEncapsulation(KYBER_ALGORITHM)
            pq_ciphertext, pq_shared = kem.encap_secret(recipient_pq_pub)

            # XOR shared secrets, then HKDF
            combined_secret = bytes(
                a ^ b for a, b in zip(classical_shared, pq_shared[:32], strict=False)
            )
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=None,
                info=HKDF_INFO_HYBRID,
            ).derive(combined_secret + classical_shared + pq_shared)

            # Encrypt
            nonce = os.urandom(NONCE_SIZE)
            aesgcm = AESGCM(derived_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

            # Package
            pq_ct_len = struct.pack("!H", len(pq_ciphertext))
            return (
                bytes([HybridPQC.VERSION_HYBRID])
                + classical_pub_bytes
                + pq_ct_len
                + pq_ciphertext
                + nonce
                + ciphertext
            )
        else:
            # Classical-only fallback
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=None,
                info=HKDF_INFO_CLASSICAL,
            ).derive(classical_shared)

            nonce = os.urandom(NONCE_SIZE)
            aesgcm = AESGCM(derived_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

            return (
                bytes([HybridPQC.VERSION_CLASSICAL_ONLY]) + classical_pub_bytes + nonce + ciphertext
            )

    @staticmethod
    def decrypt(
        blob: bytes,
        recipient_classical_priv: X25519PrivateKey,
        recipient_pq_priv: bytes | None = None,
        aad: bytes | None = None,
    ) -> bytes:
        """Decrypt hybrid or classical-only encrypted blob.

        Args:
            blob: Encrypted data.
            recipient_classical_priv: Recipient's X25519 private key.
            recipient_pq_priv: Recipient's Kyber-768 secret key (for hybrid mode).
            aad: Optional additional authenticated data.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthTagError: If decryption fails.
            CryptoError: If blob is malformed or PQC not available for hybrid blob.
        """
        if len(blob) < 2:
            raise CryptoError("PQC blob too short", operation="pqc_decrypt")

        version = blob[0]
        offset = 1

        # Extract classical ephemeral public key
        classical_pub_bytes = blob[offset : offset + 32]
        offset += 32
        ephemeral_classical_pub = X25519PublicKey.from_public_bytes(classical_pub_bytes)

        # Classical key exchange
        classical_shared = recipient_classical_priv.exchange(ephemeral_classical_pub)

        if version == HybridPQC.VERSION_HYBRID:
            if not HAS_LIBOQS:
                raise CryptoError(
                    "Cannot decrypt hybrid PQC blob — liboqs not installed",
                    operation="pqc_decrypt",
                )
            if recipient_pq_priv is None:
                raise CryptoError(
                    "PQ private key required for hybrid decryption",
                    operation="pqc_decrypt",
                )

            # Extract PQ ciphertext
            (pq_ct_len,) = struct.unpack("!H", blob[offset : offset + 2])
            offset += 2
            pq_ciphertext = blob[offset : offset + pq_ct_len]
            offset += pq_ct_len

            # PQ decapsulation
            kem = oqs.KeyEncapsulation(KYBER_ALGORITHM, secret_key=recipient_pq_priv)
            pq_shared = kem.decap_secret(pq_ciphertext)

            # Combine secrets
            combined_secret = bytes(
                a ^ b for a, b in zip(classical_shared, pq_shared[:32], strict=False)
            )
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=None,
                info=HKDF_INFO_HYBRID,
            ).derive(combined_secret + classical_shared + pq_shared)

        elif version == HybridPQC.VERSION_CLASSICAL_ONLY:
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=None,
                info=HKDF_INFO_CLASSICAL,
            ).derive(classical_shared)
        else:
            raise CryptoError(f"Unknown PQC version: {version}", operation="pqc_decrypt")

        # Extract nonce and ciphertext
        nonce = blob[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE
        ciphertext = blob[offset:]

        # Decrypt
        aesgcm = AESGCM(derived_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise AuthTagError("PQC hybrid decryption failed — wrong key or tampered") from e


class DilithiumSigner:
    """CRYSTALS-Dilithium digital signatures (post-quantum).

    Dilithium3 provides NIST security level 3 (~128-bit post-quantum security).
    Requires liboqs-python.
    """

    @staticmethod
    def is_available() -> bool:
        """Check if Dilithium signatures are available."""
        return HAS_LIBOQS

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate a Dilithium3 signing key pair.

        Returns:
            Tuple of (secret_key, public_key).

        Raises:
            CryptoError: If liboqs is not available.
        """
        if not HAS_LIBOQS:
            raise CryptoError("liboqs required for Dilithium", operation="dilithium_keygen")

        signer = oqs.Signature(DILITHIUM_ALGORITHM)
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
        return secret_key, public_key

    @staticmethod
    def sign(message: bytes, secret_key: bytes) -> bytes:
        """Sign a message with Dilithium3.

        Args:
            message: Data to sign.
            secret_key: Dilithium3 secret key.

        Returns:
            Signature bytes.
        """
        if not HAS_LIBOQS:
            raise CryptoError("liboqs required for Dilithium", operation="dilithium_sign")

        signer = oqs.Signature(DILITHIUM_ALGORITHM, secret_key=secret_key)
        return signer.sign(message)

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a Dilithium3 signature.

        Args:
            message: Original message.
            signature: Signature to verify.
            public_key: Signer's Dilithium3 public key.

        Returns:
            True if valid.

        Raises:
            AuthTagError: If verification fails.
        """
        if not HAS_LIBOQS:
            raise CryptoError("liboqs required for Dilithium", operation="dilithium_verify")

        verifier = oqs.Signature(DILITHIUM_ALGORITHM)
        is_valid = verifier.verify(message, signature, public_key)
        if not is_valid:
            raise AuthTagError("Dilithium signature verification failed")
        return True
