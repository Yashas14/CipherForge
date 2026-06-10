"""Test suite for streaming encryption/decryption."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest

from src.exceptions import StreamingError
from src.streaming import decrypt_stream, encrypt_stream


async def _bytes_to_stream(data: bytes, chunk_size: int = 1024) -> AsyncIterator[bytes]:
    """Helper: convert bytes to async iterator."""
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]


async def _collect_stream(stream: AsyncIterator[bytes]) -> bytes:
    """Helper: collect async iterator into bytes."""
    result = b""
    async for chunk in stream:
        result += chunk
    return result


class TestStreaming:
    """Test suite for streaming encryption."""

    @pytest.mark.asyncio
    async def test_roundtrip_aes_gcm(self) -> None:
        """Encrypt then decrypt stream should return original data."""
        key = os.urandom(32)
        plaintext = os.urandom(256 * 1024)  # 256 KB

        # Encrypt
        encrypted = await _collect_stream(
            encrypt_stream(_bytes_to_stream(plaintext, 8192), key, "aes-gcm", chunk_size=16384)
        )

        # Decrypt
        decrypted = await _collect_stream(
            decrypt_stream(_bytes_to_stream(encrypted, 4096), key)
        )

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_roundtrip_chacha20(self) -> None:
        """Test streaming with ChaCha20-Poly1305."""
        key = os.urandom(32)
        plaintext = os.urandom(128 * 1024)

        encrypted = await _collect_stream(
            encrypt_stream(_bytes_to_stream(plaintext), key, "chacha20")
        )

        decrypted = await _collect_stream(
            decrypt_stream(_bytes_to_stream(encrypted), key)
        )

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_empty_data(self) -> None:
        """Empty input should produce header + sentinel only."""
        key = os.urandom(32)
        plaintext = b""

        encrypted = await _collect_stream(
            encrypt_stream(_bytes_to_stream(plaintext), key, "aes-gcm")
        )

        decrypted = await _collect_stream(
            decrypt_stream(_bytes_to_stream(encrypted), key)
        )

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_single_byte(self) -> None:
        """Single byte should work."""
        key = os.urandom(32)
        plaintext = b"X"

        encrypted = await _collect_stream(
            encrypt_stream(_bytes_to_stream(plaintext), key, "aes-gcm")
        )

        decrypted = await _collect_stream(
            decrypt_stream(_bytes_to_stream(encrypted), key)
        )

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_tamper_detection(self) -> None:
        """Tampered chunk should raise StreamingError."""
        key = os.urandom(32)
        plaintext = os.urandom(100 * 1024)

        encrypted = bytearray(
            await _collect_stream(
                encrypt_stream(_bytes_to_stream(plaintext), key, "aes-gcm")
            )
        )

        # Tamper with data after the header (byte 50)
        encrypted[50] ^= 0xFF

        with pytest.raises(StreamingError):
            await _collect_stream(
                decrypt_stream(_bytes_to_stream(bytes(encrypted)), key)
            )

    @pytest.mark.asyncio
    async def test_wrong_key(self) -> None:
        """Wrong key should raise StreamingError."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        plaintext = os.urandom(10 * 1024)

        encrypted = await _collect_stream(
            encrypt_stream(_bytes_to_stream(plaintext), key1, "aes-gcm")
        )

        with pytest.raises(StreamingError):
            await _collect_stream(
                decrypt_stream(_bytes_to_stream(encrypted), key2)
            )

    @pytest.mark.asyncio
    async def test_large_file(self) -> None:
        """Test with 5MB data to verify chunk handling."""
        key = os.urandom(32)
        plaintext = os.urandom(5 * 1024 * 1024)  # 5 MB

        encrypted = await _collect_stream(
            encrypt_stream(_bytes_to_stream(plaintext, 32768), key, "aes-gcm", chunk_size=65536)
        )

        decrypted = await _collect_stream(
            decrypt_stream(_bytes_to_stream(encrypted, 16384), key)
        )

        assert decrypted == plaintext
