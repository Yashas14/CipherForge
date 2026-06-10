"""Comprehensive test suite for cryptographic algorithms."""

from __future__ import annotations

import os

import pytest

from src.algorithms.aes import AESEncryptor
from src.algorithms.argon2_enc import Argon2Encryptor
from src.algorithms.chacha import ChaChaEncryptor
from src.algorithms.ecdh import ECDHEncryptor
from src.algorithms.fernet import FernetEncryptor
from src.algorithms.hybrid import HybridEncryptor
from src.algorithms.rsa import RSAEncryptor
from src.exceptions import AuthTagError, CryptoError


class TestAESGCM:
    """Test suite for AES-256-GCM."""

    def test_roundtrip(self) -> None:
        """Encrypt then decrypt should return original plaintext."""
        key = AESEncryptor.generate_key()
        plaintext = b"Hello, World! This is a test message."
        ciphertext = AESEncryptor.encrypt(plaintext, key)
        decrypted = AESEncryptor.decrypt(ciphertext, key)
        assert decrypted == plaintext

    def test_roundtrip_empty(self) -> None:
        """Empty plaintext should encrypt/decrypt correctly."""
        key = AESEncryptor.generate_key()
        ciphertext = AESEncryptor.encrypt(b"", key)
        decrypted = AESEncryptor.decrypt(ciphertext, key)
        assert decrypted == b""

    def test_roundtrip_large(self) -> None:
        """Large plaintext (1MB) should work correctly."""
        key = AESEncryptor.generate_key()
        plaintext = os.urandom(1024 * 1024)  # 1 MB
        ciphertext = AESEncryptor.encrypt(plaintext, key)
        decrypted = AESEncryptor.decrypt(ciphertext, key)
        assert decrypted == plaintext

    def test_aad_roundtrip(self) -> None:
        """AAD should be authenticated but not encrypted."""
        key = AESEncryptor.generate_key()
        plaintext = b"secret data"
        aad = b"authenticated context"
        ciphertext = AESEncryptor.encrypt(plaintext, key, aad)
        decrypted = AESEncryptor.decrypt(ciphertext, key, aad)
        assert decrypted == plaintext

    def test_aad_tamper_detection(self) -> None:
        """Modified AAD must raise AuthTagError."""
        key = AESEncryptor.generate_key()
        plaintext = b"secret data"
        aad = b"original aad"
        ciphertext = AESEncryptor.encrypt(plaintext, key, aad)
        with pytest.raises(AuthTagError):
            AESEncryptor.decrypt(ciphertext, key, b"tampered aad")

    def test_ciphertext_tamper(self) -> None:
        """Flipped bit in ciphertext must raise AuthTagError."""
        key = AESEncryptor.generate_key()
        plaintext = b"secret data"
        ciphertext = bytearray(AESEncryptor.encrypt(plaintext, key))
        # Flip a bit in the ciphertext body (after nonce)
        ciphertext[15] ^= 0x01
        with pytest.raises(AuthTagError):
            AESEncryptor.decrypt(bytes(ciphertext), key)

    def test_wrong_key(self) -> None:
        """Wrong key must raise AuthTagError."""
        key1 = AESEncryptor.generate_key()
        key2 = AESEncryptor.generate_key()
        ciphertext = AESEncryptor.encrypt(b"data", key1)
        with pytest.raises(AuthTagError):
            AESEncryptor.decrypt(ciphertext, key2)

    def test_nonce_uniqueness(self) -> None:
        """1000 encryptions should produce 1000 unique nonces."""
        key = AESEncryptor.generate_key()
        nonces = set()
        for _ in range(1000):
            ct = AESEncryptor.encrypt(b"data", key)
            nonce = ct[:12]
            nonces.add(nonce)
        assert len(nonces) == 1000

    def test_invalid_key_size(self) -> None:
        """Invalid key size must raise CryptoError."""
        with pytest.raises(CryptoError):
            AESEncryptor.encrypt(b"data", b"short_key")

    def test_short_ciphertext(self) -> None:
        """Too-short ciphertext must raise CryptoError."""
        key = AESEncryptor.generate_key()
        with pytest.raises(CryptoError):
            AESEncryptor.decrypt(b"too_short", key)


class TestChaCha20:
    """Test suite for ChaCha20-Poly1305."""

    def test_roundtrip(self) -> None:
        key = ChaChaEncryptor.generate_key()
        plaintext = b"Test message for ChaCha20"
        ciphertext = ChaChaEncryptor.encrypt(plaintext, key)
        decrypted = ChaChaEncryptor.decrypt(ciphertext, key)
        assert decrypted == plaintext

    def test_aad_roundtrip(self) -> None:
        key = ChaChaEncryptor.generate_key()
        plaintext = b"data"
        aad = b"context"
        ct = ChaChaEncryptor.encrypt(plaintext, key, aad)
        assert ChaChaEncryptor.decrypt(ct, key, aad) == plaintext

    def test_tamper_detection(self) -> None:
        key = ChaChaEncryptor.generate_key()
        ct = bytearray(ChaChaEncryptor.encrypt(b"data", key))
        ct[-1] ^= 0xFF
        with pytest.raises(AuthTagError):
            ChaChaEncryptor.decrypt(bytes(ct), key)

    def test_wrong_key(self) -> None:
        key1 = ChaChaEncryptor.generate_key()
        key2 = ChaChaEncryptor.generate_key()
        ct = ChaChaEncryptor.encrypt(b"data", key1)
        with pytest.raises(AuthTagError):
            ChaChaEncryptor.decrypt(ct, key2)


class TestRSA:
    """Test suite for RSA-4096-OAEP."""

    def test_roundtrip(self) -> None:
        private, public = RSAEncryptor.generate_keypair()
        plaintext = b"RSA encrypted message"
        ciphertext = RSAEncryptor.encrypt(plaintext, public)
        decrypted = RSAEncryptor.decrypt(ciphertext, private)
        assert decrypted == plaintext

    def test_max_size(self) -> None:
        """446 bytes should work for RSA-4096-OAEP-SHA256."""
        private, public = RSAEncryptor.generate_keypair()
        plaintext = os.urandom(446)
        ciphertext = RSAEncryptor.encrypt(plaintext, public)
        decrypted = RSAEncryptor.decrypt(ciphertext, private)
        assert decrypted == plaintext

    def test_exceed_max_size(self) -> None:
        """Exceeding max plaintext size should raise CryptoError."""
        _, public = RSAEncryptor.generate_keypair()
        with pytest.raises(CryptoError):
            RSAEncryptor.encrypt(os.urandom(500), public)

    def test_wrong_key_decrypt(self) -> None:
        _private1, public1 = RSAEncryptor.generate_keypair()
        private2, _public2 = RSAEncryptor.generate_keypair()
        ct = RSAEncryptor.encrypt(b"data", public1)
        with pytest.raises(AuthTagError):
            RSAEncryptor.decrypt(ct, private2)

    def test_sign_verify(self) -> None:
        private, public = RSAEncryptor.generate_keypair()
        message = b"Sign this message"
        signature = RSAEncryptor.sign(message, private)
        assert RSAEncryptor.verify(message, signature, public) is True

    def test_sign_verify_tamper(self) -> None:
        private, public = RSAEncryptor.generate_keypair()
        message = b"Sign this message"
        signature = RSAEncryptor.sign(message, private)
        with pytest.raises(AuthTagError):
            RSAEncryptor.verify(b"different message", signature, public)

    def test_key_export_import(self) -> None:
        private, public = RSAEncryptor.generate_keypair()
        priv_pem = RSAEncryptor.export_private_key(private)
        pub_pem = RSAEncryptor.export_public_key(public)

        imported_priv = RSAEncryptor.import_private_key(priv_pem)
        imported_pub = RSAEncryptor.import_public_key(pub_pem)

        # Verify they work together
        ct = RSAEncryptor.encrypt(b"test", imported_pub)
        assert RSAEncryptor.decrypt(ct, imported_priv) == b"test"


class TestHybrid:
    """Test suite for Hybrid RSA+AES encryption."""

    def test_roundtrip(self) -> None:
        private, public = RSAEncryptor.generate_keypair()
        plaintext = b"Hybrid encryption test with a larger message " * 100
        ciphertext = HybridEncryptor.encrypt(plaintext, public)
        decrypted = HybridEncryptor.decrypt(ciphertext, private)
        assert decrypted == plaintext

    def test_large_data(self) -> None:
        """Should handle multi-MB data."""
        private, public = RSAEncryptor.generate_keypair()
        plaintext = os.urandom(5 * 1024 * 1024)  # 5 MB
        ciphertext = HybridEncryptor.encrypt(plaintext, public)
        decrypted = HybridEncryptor.decrypt(ciphertext, private)
        assert decrypted == plaintext

    def test_aad(self) -> None:
        private, public = RSAEncryptor.generate_keypair()
        plaintext = b"data with AAD"
        aad = b"context"
        ct = HybridEncryptor.encrypt(plaintext, public, aad)
        assert HybridEncryptor.decrypt(ct, private, aad) == plaintext

    def test_wrong_key(self) -> None:
        _priv1, pub1 = RSAEncryptor.generate_keypair()
        priv2, _pub2 = RSAEncryptor.generate_keypair()
        ct = HybridEncryptor.encrypt(b"data", pub1)
        with pytest.raises(CryptoError):
            HybridEncryptor.decrypt(ct, priv2)


class TestECDH:
    """Test suite for X25519-ECDH + AES."""

    def test_roundtrip(self) -> None:
        private, public = ECDHEncryptor.generate_keypair()
        plaintext = b"ECDH encrypted message"
        ciphertext = ECDHEncryptor.encrypt(plaintext, public)
        decrypted = ECDHEncryptor.decrypt(ciphertext, private)
        assert decrypted == plaintext

    def test_aad(self) -> None:
        private, public = ECDHEncryptor.generate_keypair()
        plaintext = b"data with aad"
        aad = b"associated data"
        ct = ECDHEncryptor.encrypt(plaintext, public, aad)
        assert ECDHEncryptor.decrypt(ct, private, aad) == plaintext

    def test_wrong_key(self) -> None:
        _priv1, pub1 = ECDHEncryptor.generate_keypair()
        priv2, _pub2 = ECDHEncryptor.generate_keypair()
        ct = ECDHEncryptor.encrypt(b"data", pub1)
        with pytest.raises(AuthTagError):
            ECDHEncryptor.decrypt(ct, priv2)

    def test_forward_secrecy(self) -> None:
        """Each encryption uses a different ephemeral key."""
        _, public = ECDHEncryptor.generate_keypair()
        ct1 = ECDHEncryptor.encrypt(b"same data", public)
        ct2 = ECDHEncryptor.encrypt(b"same data", public)
        # Ephemeral keys differ → ciphertexts differ
        assert ct1 != ct2


class TestFernet:
    """Test suite for Fernet with key rotation."""

    def test_roundtrip(self) -> None:
        enc = FernetEncryptor()
        plaintext = b"Fernet test"
        token = enc.encrypt(plaintext)
        assert enc.decrypt(token) == plaintext

    def test_key_rotation(self) -> None:
        enc = FernetEncryptor()
        token = enc.encrypt(b"original")

        # Add new key
        new_key = FernetEncryptor.generate_key()
        enc.add_key(new_key)

        # Old token still decrypts
        assert enc.decrypt(token) == b"original"

        # Rotate re-encrypts with new key
        rotated = enc.rotate(token)
        assert enc.decrypt(rotated) == b"original"

    def test_ttl_expired(self) -> None:
        import time as _time

        enc = FernetEncryptor()
        token = enc.encrypt(b"data")
        _time.sleep(2)
        # TTL of 1 second: token created >1s ago should fail
        with pytest.raises(AuthTagError):
            enc.decrypt(token, ttl=1)

    def test_tampered_token(self) -> None:
        enc = FernetEncryptor()
        token = bytearray(enc.encrypt(b"data"))
        token[10] ^= 0xFF
        with pytest.raises(AuthTagError):
            enc.decrypt(bytes(token))


class TestArgon2:
    """Test suite for Argon2id + AES."""

    def test_roundtrip(self) -> None:
        enc = Argon2Encryptor()
        plaintext = b"Password-encrypted data"
        password = b"strong_password_123!"
        ct = enc.encrypt(plaintext, password)
        assert enc.decrypt(ct, password) == plaintext

    def test_wrong_password(self) -> None:
        enc = Argon2Encryptor()
        ct = enc.encrypt(b"data", b"correct_password")
        with pytest.raises(AuthTagError):
            enc.decrypt(ct, b"wrong_password")

    def test_aad(self) -> None:
        enc = Argon2Encryptor()
        plaintext = b"data"
        password = b"pass"
        aad = b"context"
        ct = enc.encrypt(plaintext, password, aad)
        assert enc.decrypt(ct, password, aad) == plaintext

    def test_empty_password_rejected(self) -> None:
        enc = Argon2Encryptor()
        with pytest.raises(CryptoError):
            enc.encrypt(b"data", b"")

    def test_different_salt_per_encryption(self) -> None:
        """Each encryption uses a different salt → different ciphertext."""
        enc = Argon2Encryptor()
        ct1 = enc.encrypt(b"same", b"same_pass")
        ct2 = enc.encrypt(b"same", b"same_pass")
        assert ct1 != ct2
