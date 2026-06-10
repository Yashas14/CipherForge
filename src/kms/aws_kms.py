"""AWS KMS envelope encryption integration.

Security notes:
- Uses KMS GenerateDataKey to get a DEK — key never leaves KMS boundary
- Plaintext DEK is used locally for AES-256-GCM, then discarded
- Encrypted DEK is stored alongside ciphertext
- Full audit trail available in AWS CloudTrail
- Encryption context provides AAD at the KMS layer
- Requires: pip install encryption-suite-v2[aws]
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.exceptions import AuthTagError, CryptoError, KMSError

# Constants
NONCE_SIZE = 12
AES_KEY_SIZE = 32


class AWSKMSEncryptor:
    """AWS KMS envelope encryption.

    Workflow:
    1. Call KMS GenerateDataKey → (plaintext_dek, encrypted_dek)
    2. Encrypt data locally with plaintext_dek (AES-256-GCM)
    3. Store encrypted_dek alongside ciphertext (never store plaintext_dek)
    4. On decrypt: call KMS Decrypt(encrypted_dek) → plaintext_dek → decrypt data

    Benefits: key never leaves KMS boundary; full audit trail in CloudTrail.
    """

    def __init__(self, key_id: str, region: str = "us-east-1") -> None:
        """Initialize AWS KMS encryptor.

        Args:
            key_id: AWS KMS Key ID, Key ARN, Alias, or Alias ARN.
            region: AWS region where the KMS key resides.

        Raises:
            KMSError: If boto3 is not available.
        """
        try:
            import boto3
            from botocore.exceptions import ClientError  # noqa: F401
        except ImportError as e:
            raise KMSError(
                "boto3 required for AWS KMS. Install with: pip install encryption-suite-v2[aws]",
                provider="aws",
            ) from e

        self._key_id = key_id
        self._region = region
        self._client = boto3.client("kms", region_name=region)

    async def encrypt(self, plaintext: bytes, context: dict[str, str] | None = None) -> bytes:
        """Encrypt data using KMS envelope encryption.

        Args:
            plaintext: Data to encrypt.
            context: Optional encryption context (key-value pairs for AAD).

        Returns:
            Encrypted blob: [encrypted_dek_len (2B)][encrypted_dek][nonce (12B)][ciphertext+tag]

        Raises:
            KMSError: If KMS API call fails.
        """
        from botocore.exceptions import ClientError

        try:
            # Generate data key via KMS
            params: dict = {
                "KeyId": self._key_id,
                "KeySpec": "AES_256",
            }
            if context:
                params["EncryptionContext"] = context

            response = self._client.generate_data_key(**params)
            plaintext_dek = response["Plaintext"]
            encrypted_dek = response["CiphertextBlob"]

        except ClientError as e:
            raise KMSError(
                f"KMS GenerateDataKey failed: {e.response['Error']['Message']}",
                provider="aws",
            ) from e

        try:
            # Encrypt data locally with the plaintext DEK
            nonce = os.urandom(NONCE_SIZE)
            aesgcm = AESGCM(plaintext_dek)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Package: [dek_len][encrypted_dek][nonce][ciphertext+tag]
            dek_len = struct.pack("!H", len(encrypted_dek))
            return dek_len + encrypted_dek + nonce + ciphertext

        finally:
            # Zero out plaintext DEK from memory
            plaintext_dek = b"\x00" * len(plaintext_dek)

    async def decrypt(self, blob: bytes, context: dict[str, str] | None = None) -> bytes:
        """Decrypt data using KMS envelope decryption.

        Args:
            blob: Encrypted data from encrypt().
            context: Encryption context (must match what was used during encryption).

        Returns:
            Decrypted plaintext.

        Raises:
            KMSError: If KMS Decrypt API call fails.
            AuthTagError: If local AES-GCM decryption fails.
        """
        from botocore.exceptions import ClientError

        if len(blob) < 2:
            raise CryptoError("KMS blob too short", operation="kms_decrypt")

        # Parse blob
        (dek_len,) = struct.unpack("!H", blob[:2])
        offset = 2
        encrypted_dek = blob[offset : offset + dek_len]
        offset += dek_len
        nonce = blob[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE
        ciphertext = blob[offset:]

        # Decrypt DEK via KMS
        try:
            params: dict = {
                "CiphertextBlob": encrypted_dek,
            }
            if context:
                params["EncryptionContext"] = context

            response = self._client.decrypt(**params)
            plaintext_dek = response["Plaintext"]

        except ClientError as e:
            raise KMSError(
                f"KMS Decrypt failed: {e.response['Error']['Message']}",
                provider="aws",
            ) from e

        try:
            # Decrypt data locally
            aesgcm = AESGCM(plaintext_dek)
            try:
                return aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                raise AuthTagError("KMS envelope decryption: AES-GCM auth tag failed") from e
        finally:
            plaintext_dek = b"\x00" * len(plaintext_dek)

    async def re_encrypt(self, blob: bytes, new_key_id: str) -> bytes:
        """Re-encrypt data under a different KMS key.

        Decrypts the DEK with the original key, then re-encrypts with new key.
        The data ciphertext is NOT re-encrypted — only the DEK wrapper changes.

        Args:
            blob: Original encrypted blob.
            new_key_id: New KMS key ID to re-encrypt under.

        Returns:
            New blob with DEK encrypted under new key.
        """
        from botocore.exceptions import ClientError

        (dek_len,) = struct.unpack("!H", blob[:2])
        offset = 2
        encrypted_dek = blob[offset : offset + dek_len]
        offset += dek_len
        rest = blob[offset:]  # nonce + ciphertext (unchanged)

        try:
            response = self._client.re_encrypt(
                CiphertextBlob=encrypted_dek,
                DestinationKeyId=new_key_id,
            )
            new_encrypted_dek = response["CiphertextBlob"]
        except ClientError as e:
            raise KMSError(
                f"KMS ReEncrypt failed: {e.response['Error']['Message']}",
                provider="aws",
            ) from e

        new_dek_len = struct.pack("!H", len(new_encrypted_dek))
        return new_dek_len + new_encrypted_dek + rest
