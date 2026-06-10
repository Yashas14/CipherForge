"""RSA-4096-OAEP asymmetric encryption implementation.

Security notes:
- Uses RSA-4096 with OAEP padding (SHA-256 for both hash and MGF1)
- NEVER use PKCS#1 v1.5 padding — vulnerable to Bleichenbacher's attack
- Maximum plaintext size for RSA-4096-OAEP-SHA256: 446 bytes
- For larger data, use hybrid encryption (RSA + AES)
- Public exponent: 65537 (F4) — standard and secure
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.exceptions import AuthTagError, CryptoError

# Constants
KEY_SIZE_BITS = 4096
PUBLIC_EXPONENT = 65537
MAX_PLAINTEXT_SIZE = 446  # bytes for RSA-4096-OAEP-SHA256


class RSAEncryptor:
    """RSA-4096-OAEP asymmetric encryption.

    Uses OAEP padding with SHA-256 hash and SHA-256 MGF1.
    Suitable for encrypting small data (≤446 bytes) or symmetric keys.
    For larger data, use HybridEncryptor.
    """

    @staticmethod
    def generate_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate an RSA-4096 key pair.

        Returns:
            Tuple of (private_key, public_key).
        """
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE_BITS,
        )
        return private_key, private_key.public_key()

    @staticmethod
    def export_private_key(
        private_key: rsa.RSAPrivateKey,
        password: bytes | None = None,
    ) -> bytes:
        """Export private key to PEM format.

        Args:
            private_key: RSA private key to export.
            password: Optional password to encrypt the PEM file.

        Returns:
            PEM-encoded private key bytes.
        """
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    @staticmethod
    def export_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """Export public key to PEM format.

        Args:
            public_key: RSA public key to export.

        Returns:
            PEM-encoded public key bytes.
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def import_private_key(pem_data: bytes, password: bytes | None = None) -> rsa.RSAPrivateKey:
        """Import private key from PEM format.

        Args:
            pem_data: PEM-encoded private key.
            password: Password if the PEM is encrypted.

        Returns:
            RSA private key object.

        Raises:
            CryptoError: If the PEM data is invalid.
        """
        try:
            key = serialization.load_pem_private_key(pem_data, password=password)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise CryptoError("Loaded key is not an RSA private key", operation="rsa_import")
            return key
        except Exception as e:
            if isinstance(e, CryptoError):
                raise
            raise CryptoError(f"Failed to load RSA private key: {e}", operation="rsa_import") from e

    @staticmethod
    def import_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
        """Import public key from PEM format.

        Args:
            pem_data: PEM-encoded public key.

        Returns:
            RSA public key object.

        Raises:
            CryptoError: If the PEM data is invalid.
        """
        try:
            key = serialization.load_pem_public_key(pem_data)
            if not isinstance(key, rsa.RSAPublicKey):
                raise CryptoError("Loaded key is not an RSA public key", operation="rsa_import")
            return key
        except Exception as e:
            if isinstance(e, CryptoError):
                raise
            raise CryptoError(f"Failed to load RSA public key: {e}", operation="rsa_import") from e

    @staticmethod
    def encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """Encrypt plaintext using RSA-OAEP.

        Args:
            plaintext: Data to encrypt (max 446 bytes for RSA-4096-OAEP-SHA256).
            public_key: Recipient's RSA public key.

        Returns:
            Encrypted ciphertext (512 bytes for RSA-4096).

        Raises:
            CryptoError: If plaintext exceeds maximum size.
        """
        if len(plaintext) > MAX_PLAINTEXT_SIZE:
            raise CryptoError(
                f"Plaintext too large for RSA-OAEP: {len(plaintext)} bytes "
                f"(max {MAX_PLAINTEXT_SIZE}). Use hybrid encryption for larger data.",
                operation="rsa_encrypt",
            )

        try:
            return public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            raise CryptoError(f"RSA encryption failed: {e}", operation="rsa_encrypt") from e

    @staticmethod
    def decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Decrypt ciphertext using RSA-OAEP.

        Args:
            ciphertext: RSA-OAEP encrypted data.
            private_key: Recipient's RSA private key.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthTagError: If decryption fails (wrong key or corrupted ciphertext).
        """
        try:
            return private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            raise AuthTagError(
                "RSA-OAEP decryption failed — wrong key or corrupted ciphertext"
            ) from e

    @staticmethod
    def sign(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Sign a message using RSA-PSS with SHA-256.

        Args:
            message: Data to sign.
            private_key: Signer's RSA private key.

        Returns:
            Digital signature bytes.
        """
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        """Verify an RSA-PSS signature.

        Args:
            message: Original signed data.
            signature: Signature to verify.
            public_key: Signer's RSA public key.

        Returns:
            True if signature is valid.

        Raises:
            AuthTagError: If signature verification fails.
        """
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception as e:
            raise AuthTagError("RSA-PSS signature verification failed") from e
