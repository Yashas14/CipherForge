"""Extended API test suite — covers signing, verification, key generation,
FIPS compliance, error handling, and edge cases."""

from __future__ import annotations

import base64

import pytest
from httpx import ASGITransport, AsyncClient

from src.algorithms.ecdh import ECDHEncryptor
from src.algorithms.rsa import RSAEncryptor
from src.api.app import app


@pytest.fixture
async def client():
    """Create async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ─── Signing & Verification ─────────────────────────────────────────────────


class TestSignEndpoint:
    """Test /v1/keys/sign endpoint."""

    @pytest.mark.asyncio
    async def test_sign_rsa_pss(self, client: AsyncClient) -> None:
        """RSA-PSS signing should return a valid base64 signature."""
        private, _public = RSAEncryptor.generate_keypair()
        priv_pem = RSAEncryptor.export_private_key(private).decode()
        message = base64.b64encode(b"Sign this message").decode()

        response = await client.post(
            "/v1/keys/sign",
            json={
                "message": message,
                "algorithm": "rsa-pss",
                "private_key": priv_pem,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "signature" in data
        assert data["algorithm"] == "rsa-pss"
        # Verify it's valid base64
        sig_bytes = base64.b64decode(data["signature"])
        assert len(sig_bytes) == 512  # RSA-4096 signature is 512 bytes

    @pytest.mark.asyncio
    async def test_sign_missing_private_key(self, client: AsyncClient) -> None:
        """Signing without private_key should return 400."""
        message = base64.b64encode(b"test").decode()
        response = await client.post(
            "/v1/keys/sign",
            json={"message": message, "algorithm": "rsa-pss"},
        )
        assert response.status_code == 400
        assert "private_key" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_sign_invalid_base64(self, client: AsyncClient) -> None:
        """Invalid base64 message should return 400."""
        private, _ = RSAEncryptor.generate_keypair()
        priv_pem = RSAEncryptor.export_private_key(private).decode()
        response = await client.post(
            "/v1/keys/sign",
            json={
                "message": "not-valid-base64!!!",
                "algorithm": "rsa-pss",
                "private_key": priv_pem,
            },
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_sign_unsupported_algorithm(self, client: AsyncClient) -> None:
        """Unsupported algorithm should return 400."""
        private, _ = RSAEncryptor.generate_keypair()
        priv_pem = RSAEncryptor.export_private_key(private).decode()
        message = base64.b64encode(b"test").decode()
        response = await client.post(
            "/v1/keys/sign",
            json={
                "message": message,
                "algorithm": "unsupported-algo",
                "private_key": priv_pem,
            },
        )
        assert response.status_code == 422  # Pydantic validation error


class TestVerifyEndpoint:
    """Test /v1/keys/verify endpoint."""

    @pytest.mark.asyncio
    async def test_verify_valid_signature(self, client: AsyncClient) -> None:
        """Valid signature should verify successfully."""
        private, public = RSAEncryptor.generate_keypair()
        priv_pem = RSAEncryptor.export_private_key(private).decode()
        pub_pem = RSAEncryptor.export_public_key(public).decode()
        message = base64.b64encode(b"Verify this").decode()

        # Sign
        sign_resp = await client.post(
            "/v1/keys/sign",
            json={
                "message": message,
                "algorithm": "rsa-pss",
                "private_key": priv_pem,
            },
        )
        assert sign_resp.status_code == 200
        signature = sign_resp.json()["signature"]

        # Verify
        verify_resp = await client.post(
            "/v1/keys/verify",
            json={
                "message": message,
                "signature": signature,
                "algorithm": "rsa-pss",
                "public_key": pub_pem,
            },
        )
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is True

    @pytest.mark.asyncio
    async def test_verify_invalid_signature(self, client: AsyncClient) -> None:
        """Tampered signature should fail verification."""
        _private, public = RSAEncryptor.generate_keypair()
        pub_pem = RSAEncryptor.export_public_key(public).decode()
        message = base64.b64encode(b"Original message").decode()
        fake_sig = base64.b64encode(b"\x00" * 512).decode()

        response = await client.post(
            "/v1/keys/verify",
            json={
                "message": message,
                "signature": fake_sig,
                "algorithm": "rsa-pss",
                "public_key": pub_pem,
            },
        )
        assert response.status_code == 200
        assert response.json()["valid"] is False

    @pytest.mark.asyncio
    async def test_verify_wrong_message(self, client: AsyncClient) -> None:
        """Signature for a different message should fail."""
        private, public = RSAEncryptor.generate_keypair()
        priv_pem = RSAEncryptor.export_private_key(private).decode()
        pub_pem = RSAEncryptor.export_public_key(public).decode()

        original = base64.b64encode(b"Original").decode()
        sign_resp = await client.post(
            "/v1/keys/sign",
            json={"message": original, "algorithm": "rsa-pss", "private_key": priv_pem},
        )
        signature = sign_resp.json()["signature"]

        # Verify with different message
        tampered = base64.b64encode(b"Tampered").decode()
        verify_resp = await client.post(
            "/v1/keys/verify",
            json={
                "message": tampered,
                "signature": signature,
                "algorithm": "rsa-pss",
                "public_key": pub_pem,
            },
        )
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is False

    @pytest.mark.asyncio
    async def test_verify_missing_public_key(self, client: AsyncClient) -> None:
        """Verification without public_key should return 400."""
        response = await client.post(
            "/v1/keys/verify",
            json={
                "message": base64.b64encode(b"msg").decode(),
                "signature": base64.b64encode(b"sig").decode(),
                "algorithm": "rsa-pss",
            },
        )
        assert response.status_code == 400


# ─── Encrypt/Decrypt Extended ────────────────────────────────────────────────


class TestEncryptDecryptRoundtrip:
    """Full roundtrip tests for all algorithms via API."""

    @pytest.mark.asyncio
    async def test_chacha20_roundtrip(self, client: AsyncClient) -> None:
        """ChaCha20 encrypt → decrypt roundtrip."""
        plaintext_bytes = b"ChaCha20-Poly1305 full roundtrip test!"
        plaintext_b64 = base64.b64encode(plaintext_bytes).decode()

        enc_resp = await client.post(
            "/v1/encrypt/text",
            json={"plaintext": plaintext_b64, "algorithm": "chacha20"},
        )
        assert enc_resp.status_code == 200
        enc_data = enc_resp.json()

        dec_resp = await client.post(
            "/v1/decrypt/text",
            json={
                "ciphertext": enc_data["ciphertext"],
                "algorithm": "chacha20",
                "key_id": enc_data["metadata"]["key"],
            },
        )
        assert dec_resp.status_code == 200
        decrypted = base64.b64decode(dec_resp.json()["plaintext"])
        assert decrypted == plaintext_bytes

    @pytest.mark.asyncio
    async def test_rsa_oaep_roundtrip(self, client: AsyncClient) -> None:
        """RSA-OAEP encrypt → decrypt roundtrip."""
        private, public = RSAEncryptor.generate_keypair()
        pub_pem = RSAEncryptor.export_public_key(public).decode()
        priv_pem = RSAEncryptor.export_private_key(private).decode()

        plaintext_bytes = b"RSA-OAEP API roundtrip"
        plaintext_b64 = base64.b64encode(plaintext_bytes).decode()

        enc_resp = await client.post(
            "/v1/encrypt/text",
            json={
                "plaintext": plaintext_b64,
                "algorithm": "rsa-oaep",
                "recipient_public_key": pub_pem,
            },
        )
        assert enc_resp.status_code == 200

        dec_resp = await client.post(
            "/v1/decrypt/text",
            json={
                "ciphertext": enc_resp.json()["ciphertext"],
                "algorithm": "rsa-oaep",
                "private_key": priv_pem,
            },
        )
        assert dec_resp.status_code == 200
        decrypted = base64.b64decode(dec_resp.json()["plaintext"])
        assert decrypted == plaintext_bytes

    @pytest.mark.asyncio
    async def test_hybrid_roundtrip(self, client: AsyncClient) -> None:
        """Hybrid RSA+AES encrypt → decrypt roundtrip."""
        private, public = RSAEncryptor.generate_keypair()
        pub_pem = RSAEncryptor.export_public_key(public).decode()
        priv_pem = RSAEncryptor.export_private_key(private).decode()

        plaintext_bytes = b"Hybrid encryption roundtrip " * 50  # Larger data
        plaintext_b64 = base64.b64encode(plaintext_bytes).decode()

        enc_resp = await client.post(
            "/v1/encrypt/text",
            json={
                "plaintext": plaintext_b64,
                "algorithm": "hybrid",
                "recipient_public_key": pub_pem,
            },
        )
        assert enc_resp.status_code == 200

        dec_resp = await client.post(
            "/v1/decrypt/text",
            json={
                "ciphertext": enc_resp.json()["ciphertext"],
                "algorithm": "hybrid",
                "private_key": priv_pem,
            },
        )
        assert dec_resp.status_code == 200
        decrypted = base64.b64decode(dec_resp.json()["plaintext"])
        assert decrypted == plaintext_bytes

    @pytest.mark.asyncio
    async def test_ecdh_roundtrip(self, client: AsyncClient) -> None:
        """ECDH X25519 encrypt → decrypt roundtrip."""
        private, public = ECDHEncryptor.generate_keypair()
        pub_b64 = base64.b64encode(ECDHEncryptor.export_public_key(public)).decode()
        priv_b64 = base64.b64encode(ECDHEncryptor.export_private_key(private)).decode()

        plaintext_bytes = b"ECDH X25519 test message"
        plaintext_b64 = base64.b64encode(plaintext_bytes).decode()

        enc_resp = await client.post(
            "/v1/encrypt/text",
            json={
                "plaintext": plaintext_b64,
                "algorithm": "ecdh",
                "recipient_public_key": pub_b64,
            },
        )
        assert enc_resp.status_code == 200

        dec_resp = await client.post(
            "/v1/decrypt/text",
            json={
                "ciphertext": enc_resp.json()["ciphertext"],
                "algorithm": "ecdh",
                "private_key": priv_b64,
            },
        )
        assert dec_resp.status_code == 200
        decrypted = base64.b64decode(dec_resp.json()["plaintext"])
        assert decrypted == plaintext_bytes


# ─── Key Generation Extended ─────────────────────────────────────────────────


class TestKeyGeneration:
    """Extended key generation tests."""

    @pytest.mark.asyncio
    async def test_generate_chacha20_key(self, client: AsyncClient) -> None:
        response = await client.post("/v1/keys/generate", json={"algorithm": "chacha20"})
        assert response.status_code == 200
        data = response.json()
        assert data["algorithm"] == "chacha20"
        # Key should be 32 bytes (base64-encoded = 44 chars)
        key_bytes = base64.b64decode(data["key_id"])
        assert len(key_bytes) == 32

    @pytest.mark.asyncio
    async def test_generate_x25519_key(self, client: AsyncClient) -> None:
        response = await client.post("/v1/keys/generate", json={"algorithm": "x25519"})
        assert response.status_code == 200
        data = response.json()
        assert data["algorithm"] == "x25519"
        assert data["public_key"] is not None
        # Public key should be base64-encoded 32 bytes
        pub_bytes = base64.b64decode(data["public_key"])
        assert len(pub_bytes) == 32

    @pytest.mark.asyncio
    async def test_generate_fernet_key(self, client: AsyncClient) -> None:
        response = await client.post("/v1/keys/generate", json={"algorithm": "fernet"})
        assert response.status_code == 200
        data = response.json()
        assert data["algorithm"] == "fernet"
        # Fernet key is URL-safe base64 of 32 bytes
        assert len(data["key_id"]) == 44

    @pytest.mark.asyncio
    async def test_generate_invalid_algorithm(self, client: AsyncClient) -> None:
        response = await client.post("/v1/keys/generate", json={"algorithm": "invalid"})
        assert response.status_code == 422  # Pydantic validation


# ─── FIPS Compliance Endpoint ────────────────────────────────────────────────


class TestFIPSEndpoint:
    """Test FIPS compliance endpoint."""

    @pytest.mark.asyncio
    async def test_fips_status(self, client: AsyncClient) -> None:
        response = await client.get("/v1/compliance/fips")
        assert response.status_code == 200
        data = response.json()
        assert "fips_mode" in data
        assert "allowed_algorithms" in data
        assert "disallowed_algorithms" in data
        assert "minimum_key_sizes" in data
        assert data["standard"] == "FIPS 140-3"

    @pytest.mark.asyncio
    async def test_fips_has_correct_algorithms(self, client: AsyncClient) -> None:
        response = await client.get("/v1/compliance/fips")
        data = response.json()
        # AES-256-GCM should be allowed
        assert "aes-256-gcm" in data["allowed_algorithms"]
        # MD5 should be disallowed
        assert "md5" in data["disallowed_algorithms"]


# ─── Audit Log Endpoint ──────────────────────────────────────────────────────


class TestAuditEndpoint:
    """Test audit log endpoint."""

    @pytest.mark.asyncio
    async def test_audit_log(self, client: AsyncClient) -> None:
        response = await client.get("/v1/audit/log")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data

    @pytest.mark.asyncio
    async def test_audit_log_with_params(self, client: AsyncClient) -> None:
        response = await client.get("/v1/audit/log?last=10&operation=encrypt")
        assert response.status_code == 200
        data = response.json()
        assert data["last_requested"] == 10
        assert data["operation_filter"] == "encrypt"


# ─── Error Handling ──────────────────────────────────────────────────────────


class TestErrorHandling:
    """Test error responses and edge cases."""

    @pytest.mark.asyncio
    async def test_decrypt_missing_key(self, client: AsyncClient) -> None:
        """Decrypting AES without key should return 400."""
        ciphertext = base64.b64encode(b"\x00" * 100).decode()
        response = await client.post(
            "/v1/decrypt/text",
            json={"ciphertext": ciphertext, "algorithm": "aes-gcm"},
        )
        assert response.status_code == 400
        assert "key" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_decrypt_invalid_ciphertext(self, client: AsyncClient) -> None:
        """Invalid base64 ciphertext should return 400."""
        response = await client.post(
            "/v1/decrypt/text",
            json={"ciphertext": "!!!invalid!!!", "algorithm": "aes-gcm", "key_id": "abc"},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_encrypt_rsa_missing_key(self, client: AsyncClient) -> None:
        """RSA encrypt without public key should return 400."""
        plaintext = base64.b64encode(b"test").decode()
        response = await client.post(
            "/v1/encrypt/text",
            json={"plaintext": plaintext, "algorithm": "rsa-oaep"},
        )
        assert response.status_code == 400
        assert "public_key" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_encrypt_hybrid_missing_key(self, client: AsyncClient) -> None:
        """Hybrid encrypt without public key should return 400."""
        plaintext = base64.b64encode(b"test").decode()
        response = await client.post(
            "/v1/encrypt/text",
            json={"plaintext": plaintext, "algorithm": "hybrid"},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_encrypt_ecdh_missing_key(self, client: AsyncClient) -> None:
        """ECDH encrypt without public key should return 400."""
        plaintext = base64.b64encode(b"test").decode()
        response = await client.post(
            "/v1/encrypt/text",
            json={"plaintext": plaintext, "algorithm": "ecdh"},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_unknown_algorithm_encrypt(self, client: AsyncClient) -> None:
        """Unknown algorithm should return 422."""
        plaintext = base64.b64encode(b"test").decode()
        response = await client.post(
            "/v1/encrypt/text",
            json={"plaintext": plaintext, "algorithm": "blowfish"},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_health_response_shape(self, client: AsyncClient) -> None:
        """Health endpoint should have all required fields."""
        response = await client.get("/v1/health")
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "fips_mode" in data
        assert "algorithms_available" in data
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], (int, float))
        assert data["algorithms_available"] == 8
