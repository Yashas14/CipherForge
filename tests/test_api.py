"""Test suite for REST API endpoints."""

from __future__ import annotations

import base64

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.app import app


@pytest.fixture
async def client():
    """Create async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestHealthEndpoint:
    """Test health check."""

    @pytest.mark.asyncio
    async def test_health(self, client: AsyncClient) -> None:
        response = await client.get("/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "2.0.0"


class TestAlgorithmsEndpoint:
    """Test algorithms listing."""

    @pytest.mark.asyncio
    async def test_list_algorithms(self, client: AsyncClient) -> None:
        response = await client.get("/v1/algorithms")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 8
        names = [a["name"] for a in data]
        assert "AES-256-GCM" in names
        assert "ChaCha20-Poly1305" in names


class TestEncryptEndpoint:
    """Test encryption endpoints."""

    @pytest.mark.asyncio
    async def test_encrypt_aes_gcm(self, client: AsyncClient) -> None:
        plaintext = base64.b64encode(b"Hello, World!").decode()
        response = await client.post(
            "/v1/encrypt/text",
            json={"plaintext": plaintext, "algorithm": "aes-gcm"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "ciphertext" in data
        assert data["algorithm"] == "aes-gcm"
        # Verify it's valid base64
        base64.b64decode(data["ciphertext"])

    @pytest.mark.asyncio
    async def test_encrypt_chacha20(self, client: AsyncClient) -> None:
        plaintext = base64.b64encode(b"ChaCha test").decode()
        response = await client.post(
            "/v1/encrypt/text",
            json={"plaintext": plaintext, "algorithm": "chacha20"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["algorithm"] == "chacha20"

    @pytest.mark.asyncio
    async def test_encrypt_invalid_base64(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/encrypt/text",
            json={"plaintext": "not valid base64!!!", "algorithm": "aes-gcm"},
        )
        assert response.status_code == 400


class TestDecryptEndpoint:
    """Test decryption endpoints."""

    @pytest.mark.asyncio
    async def test_decrypt_aes_gcm(self, client: AsyncClient) -> None:
        # First encrypt
        plaintext_bytes = b"roundtrip test"
        plaintext_b64 = base64.b64encode(plaintext_bytes).decode()
        enc_response = await client.post(
            "/v1/encrypt/text",
            json={"plaintext": plaintext_b64, "algorithm": "aes-gcm"},
        )
        assert enc_response.status_code == 200
        enc_data = enc_response.json()

        # Then decrypt
        dec_response = await client.post(
            "/v1/decrypt/text",
            json={
                "ciphertext": enc_data["ciphertext"],
                "algorithm": "aes-gcm",
                "key_id": enc_data["metadata"]["key"],
            },
        )
        assert dec_response.status_code == 200
        dec_data = dec_response.json()
        decrypted = base64.b64decode(dec_data["plaintext"])
        assert decrypted == plaintext_bytes


class TestKeyEndpoints:
    """Test key management endpoints."""

    @pytest.mark.asyncio
    async def test_generate_aes_key(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/keys/generate",
            json={"algorithm": "aes-256"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["algorithm"] == "aes-256"
        assert "key_id" in data

    @pytest.mark.asyncio
    async def test_generate_rsa_key(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/keys/generate",
            json={"algorithm": "rsa-4096"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["algorithm"] == "rsa-4096"
        assert data["public_key"] is not None
        assert "BEGIN PUBLIC KEY" in data["public_key"]
