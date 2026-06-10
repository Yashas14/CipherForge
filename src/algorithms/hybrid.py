"""Hybrid RSA-4096-OAEP + AES-256-GCM encryption.

Security notes:
- RSA encrypts a random AES data encryption key (DEK)
- AES-256-GCM encrypts the actual data with the DEK
- Combines RSA's key distribution with AES's efficiency
- Suitable for encrypting data of any size
- The DEK is unique per encryption — forward secrecy at data level
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.exceptions import AuthTagError, CryptoError

# Constants
AES_KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits
RSA_CIPHERTEXT_SIZE = 512  # RSA-4096 produces 512-byte ciphertext
HEADER_FORMAT = "!H"  # uint16 for RSA ciphertext length
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class HybridEncryptor:
    """Hybrid RSA-4096-OAEP + AES-256-GCM encryption.

    Workflow:
    1. Generate random 256-bit Data Encryption Key (DEK)
    2. Encrypt DEK with RSA-OAEP (recipient's public key)
    3. Encrypt plaintext with AES-256-GCM using DEK
    4. Package: [rsa_ct_len (2B)][rsa_ciphertext][nonce (12B)][aes_ciphertext + tag]

    This approach allows encrypting data of any size while maintaining
    the security properties of RSA for key exchange.
    """

    @staticmethod
    def encrypt(
        plaintext: bytes,
        recipient_public_key: rsa.RSAPublicKey,
        aad: bytes | None = None,
    ) -> bytes:
        """Encrypt data using hybrid RSA+AES.

        Args:
            plaintext: Data to encrypt (any size).
            recipient_public_key: Recipient's RSA-4096 public key.
            aad: Optional additional authenticated data for AES-GCM.

        Returns:
            Hybrid encrypted blob.
        """
        # Generate random DEK
        dek = os.urandom(AES_KEY_SIZE)

        # Encrypt DEK with RSA-OAEP
        try:
            encrypted_dek = recipient_public_key.encrypt(
                dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            raise CryptoError(f"RSA key encryption failed: {e}", operation="hybrid_encrypt") from e

        # Encrypt plaintext with AES-256-GCM
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Package: [rsa_ct_len][encrypted_dek][nonce][aes_ciphertext]
        header = struct.pack(HEADER_FORMAT, len(encrypted_dek))
        return header + encrypted_dek + nonce + ciphertext

    @staticmethod
    def decrypt(
        blob: bytes,
        recipient_private_key: rsa.RSAPrivateKey,
        aad: bytes | None = None,
    ) -> bytes:
        """Decrypt a hybrid RSA+AES encrypted blob.

        Args:
            blob: Hybrid encrypted data.
            recipient_private_key: Recipient's RSA-4096 private key.
            aad: Optional additional authenticated data.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthTagError: If AES-GCM authentication fails.
            CryptoError: If RSA decryption fails or blob is malformed.
        """
        if len(blob) < HEADER_SIZE + RSA_CIPHERTEXT_SIZE + NONCE_SIZE + 16:
            raise CryptoError("Hybrid blob too short", operation="hybrid_decrypt")

        # Parse header
        offset = 0
        (rsa_ct_len,) = struct.unpack(HEADER_FORMAT, blob[offset : offset + HEADER_SIZE])
        offset += HEADER_SIZE

        # Extract encrypted DEK
        encrypted_dek = blob[offset : offset + rsa_ct_len]
        offset += rsa_ct_len

        # Extract nonce and AES ciphertext
        nonce = blob[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE
        aes_ciphertext = blob[offset:]

        # Decrypt DEK with RSA-OAEP
        try:
            dek = recipient_private_key.decrypt(
                encrypted_dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            raise CryptoError(
                "Failed to decrypt data encryption key — wrong RSA key",
                operation="hybrid_decrypt",
            ) from e

        # Decrypt data with AES-256-GCM
        aesgcm = AESGCM(dek)
        try:
            return aesgcm.decrypt(nonce, aes_ciphertext, aad)
        except Exception as e:
            raise AuthTagError("Hybrid decryption failed — AES-GCM auth tag invalid") from e
