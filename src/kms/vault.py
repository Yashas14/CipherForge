"""HashiCorp Vault Transit secrets engine integration.

Security notes:
- Vault acts as an HSM — encryption/decryption happens server-side
- Plaintext is sent to Vault, only ciphertext is returned (and vice versa)
- Supports automatic key rotation with configurable min_decryption_version
- Convergent encryption: same plaintext + same context → same ciphertext
- Requires: pip install encryption-suite-v2[vault]
"""

from __future__ import annotations

import base64

from src.exceptions import KMSError


class VaultTransitEncryptor:
    """HashiCorp Vault Transit secrets engine encryption.

    Uses Vault's Transit engine as a crypto-as-a-service backend.
    All encryption/decryption happens within Vault — keys never leave.

    Supports:
    - Automatic key rotation with configurable min_decryption_version
    - Batch encryption (encrypt many items in one API call)
    - Convergent encryption (deterministic for searching)
    - Key rewrapping (update ciphertext to latest key version)
    """

    def __init__(
        self,
        vault_url: str,
        token: str,
        mount: str = "transit",
        namespace: str | None = None,
    ) -> None:
        """Initialize Vault Transit encryptor.

        Args:
            vault_url: Vault server URL (e.g., "https://vault.example.com:8200").
            token: Vault authentication token.
            mount: Transit secrets engine mount point.
            namespace: Optional Vault namespace (Enterprise feature).

        Raises:
            KMSError: If hvac is not available.
        """
        try:
            import hvac
        except ImportError as e:
            raise KMSError(
                "hvac required for Vault Transit. "
                "Install with: pip install encryption-suite-v2[vault]",
                provider="vault",
            ) from e

        self._mount = mount
        self._client = hvac.Client(url=vault_url, token=token, namespace=namespace)

        if not self._client.is_authenticated():
            raise KMSError("Vault authentication failed", provider="vault")

    async def create_key(
        self,
        key_name: str,
        key_type: str = "aes256-gcm96",
        exportable: bool = False,
        allow_plaintext_backup: bool = False,
    ) -> None:
        """Create a new encryption key in Vault Transit.

        Args:
            key_name: Name for the new key.
            key_type: Key type (aes256-gcm96, chacha20-poly1305, rsa-4096, ed25519, etc.).
            exportable: Whether the key can be exported (not recommended for production).
            allow_plaintext_backup: Whether plaintext backup is allowed.
        """
        try:
            self._client.secrets.transit.create_key(
                name=key_name,
                key_type=key_type,
                exportable=exportable,
                allow_plaintext_backup=allow_plaintext_backup,
                mount_point=self._mount,
            )
        except Exception as e:
            raise KMSError(f"Failed to create Vault key '{key_name}': {e}", provider="vault") from e

    async def encrypt(self, plaintext: bytes, key_name: str, context: bytes | None = None) -> str:
        """Encrypt data using Vault Transit.

        Args:
            plaintext: Data to encrypt.
            key_name: Name of the Transit key to use.
            context: Optional context for convergent encryption (must be base64-encoded).

        Returns:
            Vault ciphertext string (format: "vault:v1:base64data").
        """
        try:
            b64_plaintext = base64.b64encode(plaintext).decode()
            params: dict = {
                "name": key_name,
                "plaintext": b64_plaintext,
                "mount_point": self._mount,
            }
            if context:
                params["context"] = base64.b64encode(context).decode()

            response = self._client.secrets.transit.encrypt_data(**params)
            return response["data"]["ciphertext"]
        except Exception as e:
            raise KMSError(f"Vault encrypt failed: {e}", provider="vault") from e

    async def decrypt(self, ciphertext: str, key_name: str, context: bytes | None = None) -> bytes:
        """Decrypt data using Vault Transit.

        Args:
            ciphertext: Vault ciphertext string (e.g., "vault:v1:base64data").
            key_name: Name of the Transit key.
            context: Optional context (must match encryption context).

        Returns:
            Decrypted plaintext bytes.
        """
        try:
            params: dict = {
                "name": key_name,
                "ciphertext": ciphertext,
                "mount_point": self._mount,
            }
            if context:
                params["context"] = base64.b64encode(context).decode()

            response = self._client.secrets.transit.decrypt_data(**params)
            b64_plaintext = response["data"]["plaintext"]
            return base64.b64decode(b64_plaintext)
        except Exception as e:
            raise KMSError(f"Vault decrypt failed: {e}", provider="vault") from e

    async def encrypt_batch(self, items: list[bytes], key_name: str) -> list[str]:
        """Encrypt multiple items in a single API call.

        Args:
            items: List of plaintext items to encrypt.
            key_name: Name of the Transit key.

        Returns:
            List of Vault ciphertext strings.
        """
        try:
            batch_input = [
                {"plaintext": base64.b64encode(item).decode()} for item in items
            ]
            response = self._client.secrets.transit.encrypt_data(
                name=key_name,
                batch_input=batch_input,
                mount_point=self._mount,
            )
            return [item["ciphertext"] for item in response["data"]["batch_results"]]
        except Exception as e:
            raise KMSError(f"Vault batch encrypt failed: {e}", provider="vault") from e

    async def decrypt_batch(self, ciphertexts: list[str], key_name: str) -> list[bytes]:
        """Decrypt multiple items in a single API call.

        Args:
            ciphertexts: List of Vault ciphertext strings.
            key_name: Name of the Transit key.

        Returns:
            List of decrypted plaintext bytes.
        """
        try:
            batch_input = [{"ciphertext": ct} for ct in ciphertexts]
            response = self._client.secrets.transit.decrypt_data(
                name=key_name,
                batch_input=batch_input,
                mount_point=self._mount,
            )
            return [
                base64.b64decode(item["plaintext"])
                for item in response["data"]["batch_results"]
            ]
        except Exception as e:
            raise KMSError(f"Vault batch decrypt failed: {e}", provider="vault") from e

    async def rotate_key(self, key_name: str) -> None:
        """Rotate a Transit key to a new version.

        Old versions remain available for decryption until min_decryption_version
        is updated.

        Args:
            key_name: Name of the key to rotate.
        """
        try:
            self._client.secrets.transit.rotate_key(
                name=key_name,
                mount_point=self._mount,
            )
        except Exception as e:
            raise KMSError(f"Vault key rotation failed: {e}", provider="vault") from e

    async def rewrap(self, ciphertext: str, key_name: str) -> str:
        """Re-wrap ciphertext with the latest key version.

        Does NOT decrypt — re-encrypts the internal DEK with the latest key version.
        Use this after key rotation to update old ciphertexts.

        Args:
            ciphertext: Existing Vault ciphertext.
            key_name: Name of the Transit key.

        Returns:
            New ciphertext encrypted with latest key version.
        """
        try:
            response = self._client.secrets.transit.rewrap_data(
                name=key_name,
                ciphertext=ciphertext,
                mount_point=self._mount,
            )
            return response["data"]["ciphertext"]
        except Exception as e:
            raise KMSError(f"Vault rewrap failed: {e}", provider="vault") from e

    async def set_min_decryption_version(self, key_name: str, version: int) -> None:
        """Set minimum decryption version — retire old key versions.

        After setting this, ciphertexts encrypted with older versions
        will no longer be decryptable. Use rewrap() first to migrate them.

        Args:
            key_name: Name of the Transit key.
            version: Minimum version that can decrypt.
        """
        try:
            self._client.secrets.transit.update_key_configuration(
                name=key_name,
                min_decryption_version=version,
                mount_point=self._mount,
            )
        except Exception as e:
            raise KMSError(
                f"Vault set min_decryption_version failed: {e}", provider="vault"
            ) from e

