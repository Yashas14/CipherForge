"""Property-based fuzzing tests using Hypothesis."""

from __future__ import annotations

import os

from hypothesis import given, settings
from hypothesis import strategies as st

from src.algorithms.aes import AESEncryptor
from src.algorithms.argon2_enc import Argon2Encryptor
from src.algorithms.chacha import ChaChaEncryptor
from src.algorithms.ecdh import ECDHEncryptor
from src.key_hierarchy import KeyHierarchy


class TestAESFuzz:
    """Property-based fuzzing for AES-256-GCM."""

    @given(data=st.binary(min_size=0, max_size=10_000))
    @settings(max_examples=100)
    def test_roundtrip_any_data(self, data: bytes) -> None:
        """Any binary data should encrypt/decrypt correctly."""
        key = AESEncryptor.generate_key()
        ciphertext = AESEncryptor.encrypt(data, key)
        decrypted = AESEncryptor.decrypt(ciphertext, key)
        assert decrypted == data

    @given(data=st.binary(min_size=0, max_size=5_000), aad=st.binary(min_size=0, max_size=1_000))
    @settings(max_examples=50)
    def test_roundtrip_with_aad(self, data: bytes, aad: bytes) -> None:
        """Any data + AAD combination should work."""
        key = AESEncryptor.generate_key()
        ciphertext = AESEncryptor.encrypt(data, key, aad)
        decrypted = AESEncryptor.decrypt(ciphertext, key, aad)
        assert decrypted == data


class TestChaChaFuzz:
    """Property-based fuzzing for ChaCha20-Poly1305."""

    @given(data=st.binary(min_size=0, max_size=10_000))
    @settings(max_examples=100)
    def test_roundtrip_any_data(self, data: bytes) -> None:
        """Any binary data should encrypt/decrypt correctly."""
        key = ChaChaEncryptor.generate_key()
        ciphertext = ChaChaEncryptor.encrypt(data, key)
        decrypted = ChaChaEncryptor.decrypt(ciphertext, key)
        assert decrypted == data


class TestECDHFuzz:
    """Property-based fuzzing for X25519-ECDH."""

    @given(data=st.binary(min_size=0, max_size=10_000))
    @settings(max_examples=50)
    def test_roundtrip_any_data(self, data: bytes) -> None:
        """Any binary data should encrypt/decrypt via ECDH."""
        private, public = ECDHEncryptor.generate_keypair()
        ciphertext = ECDHEncryptor.encrypt(data, public)
        decrypted = ECDHEncryptor.decrypt(ciphertext, private)
        assert decrypted == data


class TestArgon2Fuzz:
    """Property-based fuzzing for Argon2id + AES."""

    @given(
        data=st.binary(min_size=0, max_size=5_000),
        password=st.binary(min_size=1, max_size=100),
    )
    @settings(max_examples=20, deadline=30000)  # Argon2 is slow
    def test_roundtrip_any_data(self, data: bytes, password: bytes) -> None:
        """Any data + password should work."""
        enc = Argon2Encryptor(time_cost=1, memory_cost=8192, parallelism=1)  # Fast for testing
        ciphertext = enc.encrypt(data, password)
        decrypted = enc.decrypt(ciphertext, password)
        assert decrypted == data


class TestKeyHierarchyFuzz:
    """Property-based tests for key derivation."""

    @given(purpose=st.text(
        min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N")),
    ))
    @settings(max_examples=100)
    def test_derive_deterministic(self, purpose: str) -> None:
        """Same master key + purpose should always derive the same subkey."""
        master = os.urandom(32)
        kh1 = KeyHierarchy(master)
        kh2 = KeyHierarchy(master)
        assert kh1.derive(purpose) == kh2.derive(purpose)

    @given(
        purpose1=st.text(
            min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L",)),
        ),
        purpose2=st.text(
            min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L",)),
        ),
    )
    @settings(max_examples=100)
    def test_different_purposes_different_keys(self, purpose1: str, purpose2: str) -> None:
        """Different purposes should produce different keys (unless same string)."""
        if purpose1 == purpose2:
            return
        master = os.urandom(32)
        kh = KeyHierarchy(master)
        assert kh.derive(purpose1) != kh.derive(purpose2)
