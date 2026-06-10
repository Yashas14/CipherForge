"""Test suite for FIPS compliance, key hierarchy, and security utilities."""

from __future__ import annotations

import os

import pytest

from src.exceptions import AlgorithmDisabledError, CryptoError
from src.fips import FIPSMode
from src.key_hierarchy import KeyHierarchy


class TestFIPSMode:
    """Test FIPS 140-3 compliance enforcement."""

    def setup_method(self) -> None:
        """Reset FIPS mode before each test."""
        FIPSMode.disable()

    def teardown_method(self) -> None:
        """Reset FIPS mode after each test."""
        FIPSMode.disable()

    def test_fips_disabled_by_default(self) -> None:
        """FIPS should be disabled unless explicitly enabled."""
        assert FIPSMode.is_enabled() is False

    def test_enable_disable(self) -> None:
        """Enable/disable should toggle FIPS mode."""
        FIPSMode.enable()
        assert FIPSMode.is_enabled() is True
        FIPSMode.disable()
        assert FIPSMode.is_enabled() is False

    def test_allowed_algorithm_passes(self) -> None:
        """FIPS-approved algorithm should not raise when FIPS is enabled."""
        FIPSMode.enable()
        # These should not raise
        FIPSMode.check_algorithm("aes-256-gcm")
        FIPSMode.check_algorithm("chacha20-poly1305")
        FIPSMode.check_algorithm("rsa-4096-oaep")
        FIPSMode.check_algorithm("x25519-ecdh")

    def test_disallowed_algorithm_raises(self) -> None:
        """Explicitly disallowed algorithm should raise."""
        FIPSMode.enable()
        with pytest.raises(AlgorithmDisabledError) as exc_info:
            FIPSMode.check_algorithm("md5")
        assert "explicitly disallowed" in str(exc_info.value)

    def test_unknown_algorithm_raises(self) -> None:
        """Algorithm not in allowed list should raise."""
        FIPSMode.enable()
        with pytest.raises(AlgorithmDisabledError) as exc_info:
            FIPSMode.check_algorithm("some-unknown-algo")
        assert "not in FIPS" in str(exc_info.value)

    def test_no_check_when_disabled(self) -> None:
        """When FIPS is disabled, any algorithm should pass."""
        FIPSMode.disable()
        # Should NOT raise even for disallowed algorithms
        FIPSMode.check_algorithm("md5")
        FIPSMode.check_algorithm("des")
        FIPSMode.check_algorithm("anything")

    def test_check_key_size_rsa_below_minimum(self) -> None:
        """RSA key below 2048 bits should be rejected in FIPS mode."""
        FIPSMode.enable()
        with pytest.raises(AlgorithmDisabledError):
            FIPSMode.check_key_size("rsa", 1024)

    def test_check_key_size_rsa_acceptable(self) -> None:
        """RSA key at/above minimum should pass."""
        FIPSMode.enable()
        FIPSMode.check_key_size("rsa", 2048)
        FIPSMode.check_key_size("rsa", 4096)

    def test_check_key_size_aes_below_minimum(self) -> None:
        """AES key below 128 bits should fail in FIPS mode."""
        FIPSMode.enable()
        with pytest.raises(AlgorithmDisabledError):
            FIPSMode.check_key_size("aes", 64)

    def test_check_key_size_no_check_disabled(self) -> None:
        """Key size check should pass when FIPS is disabled."""
        FIPSMode.disable()
        FIPSMode.check_key_size("rsa", 512)  # Should not raise

    def test_compliance_report(self) -> None:
        """Compliance report should include required fields."""
        report = FIPSMode.get_compliance_report()
        assert "fips_mode" in report
        assert "allowed_algorithms" in report
        assert "disallowed_algorithms" in report
        assert "minimum_key_sizes" in report
        assert report["standard"] == "FIPS 140-3"
        assert "aes-256-gcm" in report["allowed_algorithms"]
        assert "md5" in report["disallowed_algorithms"]

    def test_case_insensitive_check(self) -> None:
        """Algorithm check should be case-insensitive."""
        FIPSMode.enable()
        FIPSMode.check_algorithm("AES-256-GCM")
        FIPSMode.check_algorithm("Aes-256-Gcm")

    def test_disallowed_des_variants(self) -> None:
        """All DES variants should be disallowed."""
        FIPSMode.enable()
        for algo in ("des", "3des", "triple-des"):
            with pytest.raises(AlgorithmDisabledError):
                FIPSMode.check_algorithm(algo)

    def test_disallowed_weak_hash(self) -> None:
        """SHA-1 should be disallowed."""
        FIPSMode.enable()
        with pytest.raises(AlgorithmDisabledError):
            FIPSMode.check_algorithm("sha1")
        with pytest.raises(AlgorithmDisabledError):
            FIPSMode.check_algorithm("sha-1")


class TestKeyHierarchy:
    """Test HKDF-based key derivation hierarchy."""

    def test_create_with_random_master(self) -> None:
        """Creating without master key should generate one."""
        kh = KeyHierarchy()
        key = kh.derive("encryption/aes", 32)
        assert len(key) == 32

    def test_create_with_explicit_master(self) -> None:
        """Creating with explicit 32-byte master should work."""
        master = os.urandom(32)
        kh = KeyHierarchy(master)
        key = kh.derive("test/purpose", 32)
        assert len(key) == 32

    def test_invalid_master_key_size(self) -> None:
        """Non-32-byte master key should raise CryptoError."""
        with pytest.raises(CryptoError):
            KeyHierarchy(b"too_short")
        with pytest.raises(CryptoError):
            KeyHierarchy(os.urandom(64))

    def test_deterministic_derivation(self) -> None:
        """Same master + purpose should produce same derived key."""
        master = os.urandom(32)
        kh1 = KeyHierarchy(master)
        kh2 = KeyHierarchy(master)
        assert kh1.derive("enc/aes", 32) == kh2.derive("enc/aes", 32)

    def test_different_purposes_produce_different_keys(self) -> None:
        """Different purposes should yield different keys."""
        kh = KeyHierarchy()
        key_aes = kh.derive("encryption/aes", 32)
        key_chacha = kh.derive("encryption/chacha", 32)
        key_mac = kh.derive("signing/hmac", 32)
        assert key_aes != key_chacha
        assert key_aes != key_mac
        assert key_chacha != key_mac

    def test_different_masters_produce_different_keys(self) -> None:
        """Different master keys should yield different derived keys."""
        kh1 = KeyHierarchy(os.urandom(32))
        kh2 = KeyHierarchy(os.urandom(32))
        assert kh1.derive("same/purpose", 32) != kh2.derive("same/purpose", 32)

    def test_variable_key_sizes(self) -> None:
        """Should support deriving keys of various sizes."""
        kh = KeyHierarchy()
        assert len(kh.derive("test16", 16)) == 16
        assert len(kh.derive("test32", 32)) == 32
        assert len(kh.derive("test64", 64)) == 64

    def test_empty_purpose_raises(self) -> None:
        """Empty purpose string should raise."""
        kh = KeyHierarchy()
        with pytest.raises(CryptoError):
            kh.derive("", 32)

    def test_convenience_methods(self) -> None:
        """Convenience methods should return correct-sized keys."""
        kh = KeyHierarchy()
        assert len(kh.derive_aes_key()) == 32
        assert len(kh.derive_chacha_key()) == 32


class TestExceptionHierarchy:
    """Test custom exception classes."""

    def test_crypto_error_fields(self) -> None:
        err = CryptoError("test error", operation="encrypt")
        assert str(err) == "test error"
        assert err.operation == "encrypt"

    def test_auth_tag_error(self) -> None:
        from src.exceptions import AuthTagError
        err = AuthTagError()
        assert "tag" in str(err).lower()
        assert err.operation == "verify_tag"

    def test_algorithm_disabled_error(self) -> None:
        err = AlgorithmDisabledError("md5", reason="not FIPS approved")
        assert "md5" in str(err)
        assert err.algorithm == "md5"
        assert err.operation == "algorithm_check"

    def test_kms_error(self) -> None:
        from src.exceptions import KMSError
        err = KMSError("connection failed", provider="aws")
        assert err.provider == "aws"
        assert err.operation == "kms"

    def test_streaming_error(self) -> None:
        from src.exceptions import StreamingError
        err = StreamingError("chunk corrupted", chunk_index=5)
        assert err.chunk_index == 5
        assert err.operation == "streaming"
