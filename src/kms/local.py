"""Local key management — file-based key storage for development.

Security notes:
- Stores keys encrypted with a master password (Argon2id + AES-256-GCM)
- NOT intended for production — use AWS KMS or Vault for production
- Keys are stored in a JSON file with metadata (algorithm, creation date, etc.)
- Supports key rotation and expiry tracking
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import argon2.low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.exceptions import CryptoError, KeyError_

# Constants
KEYSTORE_VERSION = 1
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
NONCE_SIZE = 12


class LocalKeyStore:
    """File-based encrypted key store for development/testing.

    Keys are stored encrypted with a master password using Argon2id + AES-256-GCM.
    Each key has metadata: id, algorithm, created_at, expires_at, status.

    WARNING: For development only. Use AWS KMS or Vault for production.
    """

    def __init__(self, store_path: Path, master_password: bytes) -> None:
        """Initialize local key store.

        Args:
            store_path: Path to the key store file.
            master_password: Master password to encrypt/decrypt keys.
        """
        self._store_path = store_path
        self._master_password = master_password
        self._store: dict[str, Any] = {"version": KEYSTORE_VERSION, "keys": {}}

        if store_path.exists():
            self._load()

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from master password."""
        return argon2.low_level.hash_secret_raw(
            secret=self._master_password,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=32,
            type=argon2.Type.ID,
        )

    def _encrypt_key_material(self, key_material: bytes) -> dict[str, str]:
        """Encrypt key material for storage."""
        salt = os.urandom(16)
        derived = self._derive_key(salt)
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(derived)
        ciphertext = aesgcm.encrypt(nonce, key_material, None)
        return {
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }

    def _decrypt_key_material(self, encrypted: dict[str, str]) -> bytes:
        """Decrypt stored key material."""
        salt = bytes.fromhex(encrypted["salt"])
        nonce = bytes.fromhex(encrypted["nonce"])
        ciphertext = bytes.fromhex(encrypted["ciphertext"])
        derived = self._derive_key(salt)
        aesgcm = AESGCM(derived)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise KeyError_("Failed to decrypt key — wrong master password") from e

    def _load(self) -> None:
        """Load key store from disk."""
        try:
            data = self._store_path.read_text(encoding="utf-8")
            self._store = json.loads(data)
        except (json.JSONDecodeError, OSError) as e:
            raise CryptoError(f"Failed to load key store: {e}", operation="keystore_load") from e

    def _save(self) -> None:
        """Save key store to disk."""
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        self._store_path.write_text(
            json.dumps(self._store, indent=2, default=str),
            encoding="utf-8",
        )

    def generate_key(
        self,
        algorithm: str = "aes-256-gcm",
        key_size: int = 32,
        expires_in_days: int | None = None,
    ) -> str:
        """Generate and store a new key.

        Args:
            algorithm: Algorithm this key is for.
            key_size: Key size in bytes.
            expires_in_days: Optional expiry in days.

        Returns:
            Key ID (UUID).
        """
        key_id = str(uuid.uuid4())
        key_material = os.urandom(key_size)
        now = datetime.now(UTC)

        entry = {
            "id": key_id,
            "algorithm": algorithm,
            "key_size": key_size,
            "created_at": now.isoformat(),
            "expires_at": None,
            "status": "active",
            "encrypted_material": self._encrypt_key_material(key_material),
        }

        if expires_in_days:
            from datetime import timedelta

            entry["expires_at"] = (now + timedelta(days=expires_in_days)).isoformat()

        self._store["keys"][key_id] = entry
        self._save()
        return key_id

    def get_key(self, key_id: str) -> bytes:
        """Retrieve key material by ID.

        Args:
            key_id: Key identifier.

        Returns:
            Decrypted key material.

        Raises:
            KeyError_: If key not found or expired.
        """
        if key_id not in self._store["keys"]:
            raise KeyError_(f"Key not found: {key_id}", key_id=key_id)

        entry = self._store["keys"][key_id]

        if entry["status"] != "active":
            raise KeyError_(f"Key {key_id} is {entry['status']}", key_id=key_id)

        # Check expiry
        if entry["expires_at"]:
            expires = datetime.fromisoformat(entry["expires_at"])
            if datetime.now(UTC) > expires:
                entry["status"] = "expired"
                self._save()
                raise KeyError_(f"Key {key_id} has expired", key_id=key_id)

        return self._decrypt_key_material(entry["encrypted_material"])

    def list_keys(self) -> list[dict[str, Any]]:
        """List all keys with metadata (no key material).

        Returns:
            List of key metadata dictionaries.
        """
        return [
            {k: v for k, v in entry.items() if k != "encrypted_material"}
            for entry in self._store["keys"].values()
        ]

    def rotate_key(self, key_id: str) -> str:
        """Rotate a key — generate new key, mark old as rotated.

        Args:
            key_id: Key to rotate.

        Returns:
            New key ID.
        """
        if key_id not in self._store["keys"]:
            raise KeyError_(f"Key not found: {key_id}", key_id=key_id)

        old_entry = self._store["keys"][key_id]
        old_entry["status"] = "rotated"
        old_entry["rotated_at"] = datetime.now(UTC).isoformat()

        # Generate new key with same parameters
        new_key_id = self.generate_key(
            algorithm=old_entry["algorithm"],
            key_size=old_entry["key_size"],
        )

        self._store["keys"][new_key_id]["rotated_from"] = key_id
        self._save()
        return new_key_id

    def delete_key(self, key_id: str) -> None:
        """Soft-delete a key (marks as deleted, does not remove).

        Args:
            key_id: Key to delete.
        """
        if key_id not in self._store["keys"]:
            raise KeyError_(f"Key not found: {key_id}", key_id=key_id)

        self._store["keys"][key_id]["status"] = "deleted"
        self._store["keys"][key_id]["deleted_at"] = datetime.now(UTC).isoformat()
        self._save()
