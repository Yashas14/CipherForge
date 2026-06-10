"""Streaming encryption for large files without RAM exhaustion.

Security notes:
- Each chunk gets its own nonce derived from (master_nonce XOR chunk_index)
- Chunk index is included in AAD to prevent reordering attacks
- Header includes master nonce, total chunks (if known), algorithm ID, and version
- Integrity verified at each chunk boundary — early abort on tampering
- Uses authenticated encryption (AES-256-GCM or ChaCha20-Poly1305)
"""

from __future__ import annotations

import os
import struct
from collections.abc import AsyncIterator
from typing import Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from src.exceptions import CryptoError, StreamingError

# Constants
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB
NONCE_SIZE = 12  # 96 bits for both AES-GCM and ChaCha20
VERSION = b"CSTRM01"  # 7 bytes — Crypto Stream v01

# Header format: master_nonce(12) + total_chunks(8) + algo_id(1) + version(7) = 28 bytes
HEADER_SIZE = 28
ALGO_AES_GCM = 0x01
ALGO_CHACHA20 = 0x02

ALGO_MAP = {
    "aes-gcm": ALGO_AES_GCM,
    "chacha20": ALGO_CHACHA20,
}


def _derive_chunk_nonce(master_nonce: bytes, chunk_index: int) -> bytes:
    """Derive a unique nonce for each chunk by XORing with chunk index.

    This ensures nonce uniqueness without requiring random nonce per chunk.
    Master nonce is 12 bytes; chunk_index is encoded as 8 bytes (big-endian)
    and XORed with the last 8 bytes of the master nonce.

    Args:
        master_nonce: 12-byte random master nonce.
        chunk_index: Zero-based chunk index.

    Returns:
        12-byte chunk-specific nonce.
    """
    index_bytes = struct.pack("!Q", chunk_index)  # 8 bytes big-endian
    # XOR last 8 bytes of nonce with chunk index
    nonce_arr = bytearray(master_nonce)
    for i in range(8):
        nonce_arr[4 + i] ^= index_bytes[i]
    return bytes(nonce_arr)


def _get_cipher(algorithm: Literal["aes-gcm", "chacha20"], key: bytes):
    """Get the AEAD cipher instance."""
    if algorithm == "aes-gcm":
        return AESGCM(key)
    elif algorithm == "chacha20":
        return ChaCha20Poly1305(key)
    else:
        raise CryptoError(f"Unknown streaming algorithm: {algorithm}", operation="streaming")


async def encrypt_stream(
    source: AsyncIterator[bytes],
    key: bytes,
    algorithm: Literal["aes-gcm", "chacha20"] = "aes-gcm",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> AsyncIterator[bytes]:
    """Encrypt a stream chunk by chunk with authenticated encryption.

    Each chunk gets its own nonce derived from (master_nonce XOR chunk_index).
    Chunk index is included in AAD to prevent reordering attacks.

    First yield: 28-byte header (master_nonce[12] + total_chunks[8] + algo_id[1] + version[7])
    Subsequent yields: encrypted chunks (nonce is derived, not stored per-chunk)

    Args:
        source: Async iterator yielding plaintext chunks.
        key: 256-bit encryption key.
        algorithm: AEAD algorithm to use.
        chunk_size: Size of plaintext chunks to process.

    Yields:
        Encrypted data: header first, then encrypted chunks.

    Raises:
        StreamingError: On encryption errors.
    """
    if len(key) != 32:
        raise CryptoError(f"Invalid key size: {len(key)}", operation="stream_encrypt")

    master_nonce = os.urandom(NONCE_SIZE)
    algo_id = ALGO_MAP.get(algorithm, ALGO_AES_GCM)
    cipher = _get_cipher(algorithm, key)

    # Emit header — total_chunks is 0 (unknown for streaming)
    header = master_nonce + struct.pack("!Q", 0) + bytes([algo_id]) + VERSION
    yield header

    chunk_index = 0
    buffer = b""

    async for data in source:
        buffer += data
        while len(buffer) >= chunk_size:
            chunk = buffer[:chunk_size]
            buffer = buffer[chunk_size:]

            # Derive nonce for this chunk
            chunk_nonce = _derive_chunk_nonce(master_nonce, chunk_index)

            # AAD includes chunk index to prevent reordering
            aad = struct.pack("!Q", chunk_index)

            encrypted_chunk = cipher.encrypt(chunk_nonce, chunk, aad)
            # Prefix each encrypted chunk with its length (4 bytes)
            yield struct.pack("!I", len(encrypted_chunk)) + encrypted_chunk
            chunk_index += 1

    # Final chunk (may be smaller than chunk_size)
    if buffer:
        chunk_nonce = _derive_chunk_nonce(master_nonce, chunk_index)
        aad = struct.pack("!Q", chunk_index)
        encrypted_chunk = cipher.encrypt(chunk_nonce, buffer, aad)
        yield struct.pack("!I", len(encrypted_chunk)) + encrypted_chunk
        chunk_index += 1

    # Emit sentinel: zero-length chunk to signal end
    yield struct.pack("!I", 0)


async def decrypt_stream(
    source: AsyncIterator[bytes],
    key: bytes,
) -> AsyncIterator[bytes]:
    """Decrypt a streaming-encrypted data source.

    Reads the header to determine algorithm, then decrypts chunk by chunk
    with integrity verification at each boundary.

    Args:
        source: Async iterator yielding encrypted data.
        key: 256-bit decryption key.

    Yields:
        Decrypted plaintext chunks.

    Raises:
        StreamingError: If a chunk fails integrity verification.
        CryptoError: If header is invalid.
    """
    if len(key) != 32:
        raise CryptoError(f"Invalid key size: {len(key)}", operation="stream_decrypt")

    # Accumulate data from source
    raw_buffer = b""
    source_iter = source.__aiter__()

    # Read header
    while len(raw_buffer) < HEADER_SIZE:
        try:
            chunk = await source_iter.__anext__()
            raw_buffer += chunk
        except StopAsyncIteration as exc:
            raise StreamingError(
                "Stream ended before header was complete",
                chunk_index=0,
            ) from exc

    # Parse header
    header = raw_buffer[:HEADER_SIZE]
    raw_buffer = raw_buffer[HEADER_SIZE:]

    master_nonce = header[:12]
    # total_chunks = struct.unpack("!Q", header[12:20])[0]  # May be 0 (unknown)
    algo_id = header[20]
    version = header[21:28]

    if version != VERSION:
        raise StreamingError(f"Unknown stream version: {version!r}", chunk_index=0)

    # Determine algorithm
    if algo_id == ALGO_AES_GCM:
        algorithm: Literal["aes-gcm", "chacha20"] = "aes-gcm"
    elif algo_id == ALGO_CHACHA20:
        algorithm = "chacha20"
    else:
        raise StreamingError(f"Unknown algorithm ID: {algo_id}", chunk_index=0)

    cipher = _get_cipher(algorithm, key)
    chunk_index = 0

    while True:
        # Read chunk length (4 bytes)
        while len(raw_buffer) < 4:
            try:
                data = await source_iter.__anext__()
                raw_buffer += data
            except StopAsyncIteration:
                if raw_buffer:
                    raise StreamingError(  # noqa: B904
                        "Stream ended mid-chunk",
                        chunk_index=chunk_index,
                    )
                return

        (chunk_len,) = struct.unpack("!I", raw_buffer[:4])
        raw_buffer = raw_buffer[4:]

        # Zero-length chunk = end sentinel
        if chunk_len == 0:
            return

        # Read encrypted chunk
        while len(raw_buffer) < chunk_len:
            try:
                data = await source_iter.__anext__()
                raw_buffer += data
            except StopAsyncIteration as exc:
                raise StreamingError(
                    f"Stream ended before chunk {chunk_index} complete",
                    chunk_index=chunk_index,
                ) from exc

        encrypted_chunk = raw_buffer[:chunk_len]
        raw_buffer = raw_buffer[chunk_len:]

        # Derive nonce and decrypt
        chunk_nonce = _derive_chunk_nonce(master_nonce, chunk_index)
        aad = struct.pack("!Q", chunk_index)

        try:
            plaintext_chunk = cipher.decrypt(chunk_nonce, encrypted_chunk, aad)
        except Exception as e:
            raise StreamingError(
                f"Chunk {chunk_index} integrity verification failed",
                chunk_index=chunk_index,
            ) from e

        yield plaintext_chunk
        chunk_index += 1
