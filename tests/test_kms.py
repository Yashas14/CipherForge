"""Test suite for KMS integrations (mock-based)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.exceptions import KeyError_
from src.kms.local import LocalKeyStore


class TestLocalKeyStore:
    """Test suite for local key store."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> LocalKeyStore:
        """Create a temporary key store."""
        store_path = tmp_path / "keystore.json"
        return LocalKeyStore(store_path, master_password=b"test_password_123")

    def test_generate_and_retrieve(self, store: LocalKeyStore) -> None:
        """Generate a key and retrieve it."""
        key_id = store.generate_key(algorithm="aes-256-gcm", key_size=32)
        key = store.get_key(key_id)
        assert len(key) == 32

    def test_list_keys(self, store: LocalKeyStore) -> None:
        """List should show generated keys."""
        store.generate_key()
        store.generate_key()
        keys = store.list_keys()
        assert len(keys) == 2

    def test_rotate_key(self, store: LocalKeyStore) -> None:
        """Rotation creates new key and marks old as rotated."""
        old_id = store.generate_key()
        new_id = store.rotate_key(old_id)
        assert old_id != new_id

        # Old key should still be retrievable (for decryption of existing data)
        # but marked as rotated
        keys = store.list_keys()
        old_entry = next(k for k in keys if k["id"] == old_id)
        assert old_entry["status"] == "rotated"

    def test_delete_key(self, store: LocalKeyStore) -> None:
        """Deleted key should not be retrievable."""
        key_id = store.generate_key()
        store.delete_key(key_id)
        with pytest.raises(KeyError_):
            store.get_key(key_id)

    def test_nonexistent_key(self, store: LocalKeyStore) -> None:
        """Accessing non-existent key should raise."""
        with pytest.raises(KeyError_):
            store.get_key("nonexistent-uuid")

    def test_wrong_master_password(self, tmp_path: Path) -> None:
        """Wrong master password should fail to decrypt keys."""
        store_path = tmp_path / "keystore.json"
        store = LocalKeyStore(store_path, master_password=b"correct_password")
        key_id = store.generate_key()

        # Reopen with wrong password
        store2 = LocalKeyStore(store_path, master_password=b"wrong_password")
        with pytest.raises(KeyError_):
            store2.get_key(key_id)

    def test_persistence(self, tmp_path: Path) -> None:
        """Key store should persist across instances."""
        store_path = tmp_path / "keystore.json"
        password = b"persist_test"

        store1 = LocalKeyStore(store_path, master_password=password)
        key_id = store1.generate_key()

        # Reopen
        store2 = LocalKeyStore(store_path, master_password=password)
        key = store2.get_key(key_id)
        assert len(key) == 32
