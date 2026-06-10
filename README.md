<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black"/>
  <img src="https://img.shields.io/badge/Vite-6-646CFF?style=for-the-badge&logo=vite&logoColor=white"/>
  <img src="https://img.shields.io/badge/TailwindCSS-4-38BDF8?style=for-the-badge&logo=tailwindcss&logoColor=white"/>
  <img src="https://img.shields.io/badge/FIPS_140--3-Enforced-gold?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Post--Quantum-Kyber--768-8B5CF6?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge"/>
</p>

<h1 align="center">🔐 CipherForge</h1>

<p align="center">
  <strong>Enterprise-grade full-stack cryptography platform — FastAPI · React 19 · 8 Algorithms · FIPS 140-3 · Post-Quantum Ready</strong>
</p>

<p align="center">
  CipherForge is a production-oriented cryptography toolkit demonstrating secure algorithm design,
  REST API construction, interactive dashboards, streaming encryption, and cloud key management —
  all wired together across backend, frontend, and CLI.
</p>

---

## Table of Contents

- [Why CipherForge](#why-cipherforge)
- [Feature Matrix](#feature-matrix)
- [Architecture](#architecture)
- [Cryptographic Algorithms](#cryptographic-algorithms)
- [API Reference](#api-reference)
- [React Dashboard](#react-dashboard)
- [CLI Reference](#cli-reference)
- [Security Design](#security-design)
- [Key Management](#key-management)
- [Streaming Encryption](#streaming-encryption)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Testing](#testing)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Performance](#performance)
- [Contributing](#contributing)
- [Snapshots](#snapshots)

---

## Why CipherForge

Most cryptography demos show a single RSA encrypt/decrypt example. CipherForge is different:

| Dimension | Typical Demo | CipherForge |
|:----------|:------------:|:-----------:|
| Algorithms | 1 | **8 implementations** |
| Architecture | Script | **Full-stack (API + CLI + Dashboard)** |
| Padding | Textbook RSA | **OAEP-SHA256, PSS — OWASP-compliant** |
| Key management | Hardcoded | **HKDF hierarchy + local store + KMS adapters** |
| Testing | None | **80+ test functions across 8 modules** |
| Security controls | None | **FIPS enforcement, audit logging, AAD, tamper detection** |
| Streaming | No | **64 KB chunked pipeline with per-chunk integrity** |
| Post-Quantum | No | **X25519 + Kyber-768 hybrid (NIST PQC 2024)** |
| Deployment | N/A | **Docker + Compose, production build path** |

---

## Feature Matrix

### Cryptographic Operations

| Feature | API | CLI | Library |
|:--------|:---:|:---:|:-------:|
| AES-256-GCM encrypt/decrypt | ✅ | ✅ | ✅ |
| ChaCha20-Poly1305 encrypt/decrypt | ✅ | ✅ | ✅ |
| RSA-4096-OAEP encrypt/decrypt | ✅ | — | ✅ |
| X25519-ECDH envelope encrypt | ✅ | ✅ | ✅ |
| Hybrid RSA+AES envelope | ✅ | — | ✅ |
| Fernet token encryption | — | — | ✅ |
| Argon2id + AES password encryption | — | ✅ | ✅ |
| X25519 + Kyber-768 PQC (optional) | — | — | ✅ |
| RSA-PSS digital signatures | ✅ | — | ✅ |
| Key generation (all types) | ✅ | ✅ | ✅ |

### Platform Features

| Feature | Notes |
|:--------|:------|
| FIPS 140-3 policy mode | Toggle via `CRYPTO_FIPS_MODE=1` or CLI `fips --enable` |
| Structured audit logging | JSON via structlog — no key or plaintext material |
| HKDF key hierarchy | SHA-256 domain-separated subkey derivation |
| Streaming pipeline | 64 KB chunks · AES-GCM or ChaCha20 · reorder-protected |
| Local key store | Argon2id + AES-GCM master-password-encrypted JSON file |
| AWS KMS adapter | Envelope key operations (`src/kms/aws_kms.py`) |
| HashiCorp Vault adapter | Transit secret engine (`src/kms/vault.py`) |
| Typed exceptions | `CryptoError`, `AuthTagError`, `StreamingError`, `KMSError` |
| Pydantic v2 schemas | Full request/response validation + OpenAPI docs |
| CORS middleware | FastAPI CORSMiddleware, configurable origins |

---

## Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│          React 19 Dashboard  (http://localhost:3000)             │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Encrypt  │ │  File    │ │ Sign &   │ │   Key    │           │
│  │ /Decrypt │ │  Vault   │ │  Verify  │ │ Workshop │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌─────────────────────────────────────┐           │
│  │Benchmark │ │         Algorithm Guide             │           │
│  └──────────┘ └─────────────────────────────────────┘           │
│                                                                  │
│  useHealth (10s poll) → /v1/health     Vite proxy /v1 → :8000   │
└──────────────────────────┬───────────────────────────────────────┘
                           │ HTTP/JSON
┌──────────────────────────▼───────────────────────────────────────┐
│         FastAPI Application  (http://localhost:8000)             │
│                                                                  │
│  CORS Middleware  ·  Pydantic v2 validation  ·  Typed exceptions │
│                                                                  │
│  /v1/health          /v1/algorithms                              │
│  /v1/encrypt/text    /v1/decrypt/text                            │
│  /v1/encrypt/file    /v1/decrypt/file                            │
│  /v1/keys/generate   /v1/keys/sign    /v1/keys/verify            │
│  /v1/audit/log       /v1/compliance/fips                         │
└──────┬──────────────┬──────────────┬────────────┬────────────────┘
       │              │              │            │
┌──────▼──────┐ ┌─────▼──────┐ ┌────▼─────┐ ┌───▼────────────┐
│  Algorithms │ │    Key     │ │  FIPS    │ │   Streaming    │
│             │ │ Hierarchy  │ │  140-3   │ │   Pipeline     │
│  aes.py     │ │ (HKDF-256) │ │  Policy  │ │ (64KB chunks)  │
│  chacha.py  │ ├────────────┤ └──────────┘ └────────────────┘
│  rsa.py     │ │   KMS      │
│  ecdh.py    │ │            │
│  hybrid.py  │ │ local.py   │
│  fernet.py  │ │ aws_kms.py │
│  argon2.py  │ │ vault.py   │
│  pqc.py     │ └────────────┘
└─────────────┘
```

---

## Cryptographic Algorithms

### 1 — AES-256-GCM (`src/algorithms/aes.py`)

Symmetric authenticated encryption using the industry-standard AES-GCM construction.

- **Wire format:** `nonce (12 B) || ciphertext || tag (16 B)`
- **Nonce:** 96-bit cryptographically random per operation (`os.urandom(12)`)
- **Auth tag:** 128-bit — forgery probability ≈ 2⁻¹²⁸
- **AAD support:** Optional additional authenticated data authenticated but not encrypted
- **Hardware acceleration:** AES-NI on x86/ARM — typically 400+ MB/s
- **NIST reference:** SP 800-38D

```python
from src.algorithms.aes import AESEncryptor

key = AESEncryptor.generate_key()           # 32 random bytes
ct  = AESEncryptor.encrypt(b"secret", key)  # nonce || ciphertext || tag
pt  = AESEncryptor.decrypt(ct, key)         # back to b"secret"
```

---

### 2 — ChaCha20-Poly1305 (`src/algorithms/chacha.py`)

Symmetric AEAD using Bernstein's stream cipher — constant-time, no hardware dependency.

- **Wire format:** `nonce (12 B) || ciphertext || tag (16 B)`
- **Constant-time implementation** — immune to cache-timing attacks
- **No AES hardware needed** — consistent performance on all platforms
- **RFC 8439** compliant

---

### 3 — RSA-4096-OAEP (`src/algorithms/rsa.py`)

Asymmetric public-key encryption and digital signatures.

- **Encryption:** OAEP padding with SHA-256 hash and SHA-256 MGF1
- **Signatures:** PSS padding with SHA-256
- **Max plaintext:** 446 bytes for RSA-4096-OAEP-SHA256 — use Hybrid for larger data
- **Public exponent:** 65537 (F4)
- **PEM export/import:** PKCS#8 private key, SPKI public key
- **NIST reference:** SP 800-56B

```python
from src.algorithms.rsa import RSAEncryptor

priv, pub = RSAEncryptor.generate_keypair()
ct  = RSAEncryptor.encrypt(b"small secret", pub)
pt  = RSAEncryptor.decrypt(ct, priv)

sig   = RSAEncryptor.sign(b"message", priv)
valid = RSAEncryptor.verify(b"message", sig, pub)
```

---

### 4 — X25519-ECDH + AES-256-GCM (`src/algorithms/ecdh.py`)

Ephemeral key agreement with immediate symmetric encryption — forward secrecy included.

- Generates a fresh X25519 ephemeral key per encryption
- X25519 shared secret → HKDF-SHA256 → 256-bit AES-GCM key
- Long-term key compromise does not decrypt past messages
- **NIST reference:** SP 800-56A

---

### 5 — Hybrid RSA+AES (`src/algorithms/hybrid.py`)

Combines RSA key distribution with AES bulk encryption — no plaintext size limit.

- Random 256-bit AES session key per message
- RSA-4096-OAEP wraps the session key (512 B RSA ciphertext)
- AES-256-GCM encrypts the payload
- AAD propagated to the AES-GCM layer

---

### 6 — Fernet (`src/algorithms/fernet.py`)

Simple symmetric token encryption with built-in expiry and key rotation.

- AES-128-CBC + HMAC-SHA256 token construction
- Multi-key rotation: try each key in sequence until one succeeds
- Optional TTL expiry embedded in the token
- Good choice for web session tokens and short-lived secrets

---

### 7 — Argon2id + AES-256-GCM (`src/algorithms/argon2_enc.py`)

Password-based encryption resistant to GPU/ASIC brute-force.

- **KDF:** Argon2id — time=3, memory=64 MB, parallelism=4
- Per-encryption random salt embedded in ciphertext
- Derived 256-bit key fed to AES-256-GCM
- **RFC 9106** compliant

```bash
python cli.py encrypt ./secret.txt --password
# prompts for password, uses Argon2id derivation
```

---

### 8 — Hybrid X25519 + Kyber-768 (`src/algorithms/pqc.py`)

Post-quantum hybrid combining classical and lattice-based cryptography.

- Classical X25519 shared secret XORed with Kyber-768 shared secret → HKDF → AES-256-GCM key
- Secure even if one algorithm is broken — "belt and suspenders"
- **Wire format (hybrid):** `version (1B) || ephemeral_pub (32B) || pq_ct_len (2B) || pq_ct || nonce (12B) || ciphertext`
- Gracefully falls back to X25519-only if liboqs is not installed
- **NIST PQC 2024:** FIPS 203 (ML-KEM / Kyber-768)
- Install: `pip install ".[pqc]"`

---

## API Reference

Base URL: `http://localhost:8000/v1`  
Swagger UI: `http://localhost:8000/docs`  
ReDoc: `http://localhost:8000/redoc`

---

### GET `/v1/health`

Service liveness and metadata.

```json
{
  "status": "healthy",
  "version": "2.0.0",
  "fips_mode": false,
  "algorithms_available": 8,
  "uptime_seconds": 42.5
}
```

---

### GET `/v1/algorithms`

Returns the algorithm catalog with `name`, `family`, `key_size_bits`, `security_level`, `fips_approved`, `nist_recommendation`, and `use_case` fields.

---

### POST `/v1/encrypt/text`

**Request:**

```json
{
  "plaintext": "<base64 plaintext>",
  "algorithm": "aes-gcm",
  "aad": "<base64 AAD — optional>",
  "recipient_public_key": "<PEM or base64 — required for rsa-oaep / hybrid / ecdh>"
}
```

Supported `algorithm` values: `aes-gcm` · `chacha20` · `rsa-oaep` · `hybrid` · `ecdh`

**Response:**

```json
{
  "ciphertext": "<base64 ciphertext>",
  "algorithm": "aes-gcm",
  "key_id": null,
  "metadata": {
    "key": "<base64 decryption key — symmetric modes only, save this>",
    "nonce_size": 12,
    "tag_size": 16
  }
}
```

---

### POST `/v1/decrypt/text`

**Request:**

```json
{
  "ciphertext": "<base64 ciphertext>",
  "algorithm": "aes-gcm",
  "key_id": "<base64 symmetric key — for aes-gcm / chacha20>",
  "private_key": "<PEM private key — for rsa-oaep / hybrid / ecdh>",
  "aad": "<base64 AAD — must match encryption>"
}
```

---

### POST `/v1/encrypt/file` · POST `/v1/decrypt/file`

`multipart/form-data` — `file` field + `algorithm` query param (+ `key` for decrypt).  
Returns base64 result in the same response schema.

---

### POST `/v1/keys/generate`

```json
{ "algorithm": "rsa-4096" }
```

Values: `aes-256` · `chacha20` · `rsa-4096` · `x25519` · `fernet`

Returns `key_id` (symmetric key or identifier) and `public_key` (PEM/base64 for asymmetric types).

---

### POST `/v1/keys/sign` · POST `/v1/keys/verify`

**Sign:**
```json
{ "message": "<base64>", "algorithm": "rsa-pss", "private_key": "<PEM>" }
```

**Verify:**
```json
{ "message": "<base64>", "signature": "<base64>", "algorithm": "rsa-pss", "public_key": "<PEM>" }
```

---

### GET `/v1/audit/log` · GET `/v1/compliance/fips`

`/audit/log` returns shipping guidance — logs emit to structured JSON stdout.  
`/compliance/fips` returns allowed/disallowed algorithm lists, minimum key sizes, and current mode.

---

## React Dashboard

Built with React 19 + Vite 6 + TailwindCSS 4 + Framer Motion 12.

### Tab 1 — Encrypt / Decrypt

- Algorithm selector for all 5 API algorithms
- Optional AAD field
- Toggle encrypt / decrypt mode
- Output: ciphertext, decryption key (symmetric), operation time
- Copy-to-clipboard on ciphertext

### Tab 2 — File Vault

- Drag-and-drop or click-to-browse file upload
- Encrypt or decrypt file via API
- Download processed output as a file
- Supports AES-GCM and ChaCha20

### Tab 3 — Sign & Verify

- Browser-side RSA-4096 keypair generation via WebCrypto API
- Sign message with RSA-PSS (server-processed)
- Verify produces SIGNATURE VALID / SIGNATURE INVALID result

### Tab 4 — Key Workshop

- Server-side generation: AES, ChaCha20, RSA, X25519, Fernet
- Browser-side full RSA-4096 keypair helper for signing flows
- Session key store showing all generated entries
- Clear-all button

### Tab 5 — Benchmark

- Live benchmark against real API: AES-GCM vs ChaCha20
- Configurable payload: 100 B · 1 KB · 10 KB · 100 KB
- Configurable iterations
- Bar chart: encrypt and decrypt latency + throughput

### Tab 6 — Algorithm Guide

- Reference cards for all 8 algorithms with key size, FIPS status, quantum safety, use case
- Security best practices checklist
- Common cryptography mistakes list

### Sidebar Live Status

Polls `/v1/health` every 10 seconds showing: API online/offline · FIPS mode · operation counter · RSA/X25519 readiness.

---

## CLI Reference

Built with Typer for a rich terminal experience.

### Encrypt a file

```bash
python cli.py encrypt ./document.pdf --algo aes-gcm
python cli.py encrypt ./document.pdf --algo chacha20 --out ./doc.enc
python cli.py encrypt ./secret.txt --password          # Argon2id flow
```

### Decrypt a file

```bash
python cli.py decrypt ./doc.enc --algo aes-gcm --key <base64_key>
python cli.py decrypt ./secret.txt.enc --password
```

### Generate keys

```bash
python cli.py keygen --algo rsa     --out ./keys   # RSA-4096 PEM pair
python cli.py keygen --algo x25519  --out ./keys   # X25519 key pair
python cli.py keygen --algo aes                     # AES-256 key file
python cli.py keygen --algo chacha                  # ChaCha20 key file
python cli.py keygen --algo fernet                  # Fernet key
```

### Other commands

```bash
python cli.py algorithms             # Print algorithm table
python cli.py fips --enable          # Enable FIPS mode
python cli.py fips --status          # Show FIPS status
python cli.py serve --port 8000      # Start FastAPI server
python cli.py audit-log --last 100   # Show audit log guidance
```

---

## Security Design

### Nonce Strategy

Every symmetric encryption call generates a fresh cryptographically random nonce via `os.urandom(12)`. The nonce is prepended to the ciphertext blob so decryption is self-contained.

### Authentication Tag Enforcement

All encryption paths use AEAD modes (AES-GCM or ChaCha20-Poly1305). Decryption always verifies the 128-bit authentication tag — any bit flip raises `AuthTagError` immediately.

### FIPS 140-3 Policy

```bash
CRYPTO_FIPS_MODE=1 uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```

When active: any request that uses a disallowed algorithm (DES, 3DES, RC4, ECB, MD5, SHA-1, PKCS#1 v1.5, RSA < 2048-bit) returns HTTP 403 `AlgorithmDisabledError`.

### Audit Log Schema

```json
{
  "event": "crypto_operation",
  "operation": "encrypt",
  "algorithm": "aes-gcm",
  "key_id": "ephemeral",
  "data_size_bytes": 1024,
  "user_id": "system",
  "success": true,
  "duration_ms": 1.23,
  "timestamp": "2026-06-10T12:00:00+00:00"
}
```

Key material and plaintext are **never** written to logs.

### Exception Hierarchy

```text
CryptoError (base)
├── AuthTagError           # AEAD tag verification failure
├── KeyError_              # Key generation/import/derivation failure
├── NonceReuseError        # Nonce collision detected
├── AlgorithmDisabledError # FIPS policy violation (HTTP 403)
├── KMSError               # AWS KMS / Vault error (HTTP 502)
├── StreamingError         # Chunk decryption / format error
└── KeyRotationError       # Rotation failure
```

---

## Key Management

### HKDF Key Hierarchy

`KeyHierarchy` derives domain-separated subkeys from a 256-bit master key using HKDF-Expand (RFC 5869 SHA-256):

```text
master_key (256-bit)
├── derive("encryption/aes")    → 256-bit AES key
├── derive("encryption/chacha") → 256-bit ChaCha20 key
├── derive("signing/hmac")      → 256-bit HMAC key
└── derive("wrapping/kek")      → 256-bit key-wrapping key
```

Subkeys are cryptographically independent — compromise of one domain does not expose others. Master keys can be wrapped with AES-GCM for persistent storage.

### Local Key Store

For development use. Keys encrypted under Argon2id + AES-256-GCM with a master password.

- Argon2id parameters: time\_cost=3, memory=64 MB, parallelism=4
- Operations: `generate_key`, `get_key`, `list_keys`, `rotate_key`, `delete_key`
- Rotation marks old entry as `rotated` (still decryptable) and creates a new entry

For production use: the AWS KMS adapter (`src/kms/aws_kms.py`) and Vault adapter (`src/kms/vault.py`) follow the same interface.

---

## Streaming Encryption

`src/streaming.py` provides async generator-based chunked AEAD for arbitrarily large files without loading them into memory.

### Stream Header (28 bytes)

```text
master_nonce(12B) | total_chunks(8B) | algo_id(1B) | version "CSTRM01"(7B)
```

### Per-Chunk Nonce Derivation

```text
chunk_nonce = master_nonce XOR pack("!Q", chunk_index)
```

No stored nonce per chunk — uniqueness guaranteed by the XOR construction.

### Reorder Protection

Chunk index is passed as AAD to the cipher. A reordered or duplicated chunk fails authentication immediately.

### Usage

```python
import os
from src.streaming import encrypt_stream, decrypt_stream

key = os.urandom(32)

async def source():
    with open("large.bin", "rb") as f:
        while data := f.read(65536):
            yield data

async for chunk in encrypt_stream(source(), key, algorithm="aes-gcm"):
    output.write(chunk)
```

---

## Quick Start

### Prerequisites

| Requirement | Minimum Version |
|:-----------|:---------------:|
| Python | 3.11 |
| Node.js | 18 |

### 1 — Install backend dependencies

```bash
git clone https://github.com/Yashas14/CipherForge.git
cd CipherForge
pip install -e ".[dev]"
```

Optional extras:

```bash
pip install -e ".[pqc]"   # Kyber-768 post-quantum (requires liboqs)
pip install -e ".[aws]"   # AWS KMS adapter
pip install -e ".[vault]" # HashiCorp Vault adapter
```

### 2 — Install frontend dependencies

```bash
cd frontend
npm install
cd ..
```

### 3 — Start the API server (Terminal 1)

```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload
```

Swagger UI: **http://localhost:8000/docs**

### 4 — Start the React dashboard (Terminal 2)

```bash
cd frontend
npm run dev
```

Dashboard: **http://localhost:3000**

### 5 — Production frontend build

```bash
cd frontend && npm run build && cd ..
uvicorn src.api.app:app --host 0.0.0.0 --port 8000
```

FastAPI serves `frontend/dist` at `/` when the build directory exists.

---

## Docker Deployment

### Single container

```bash
docker build -t cipherforge .
docker run -p 8000:8000 -e CRYPTO_FIPS_MODE=0 cipherforge
```

### Docker Compose (API + health check)

```bash
docker compose up --build
```

The `api` service runs as a non-root user, exposes port 8000, and health-checks `/v1/health` every 30 seconds.

---

## Testing

### Run all tests

```bash
pytest tests/ -v
```

### Run with coverage

```bash
pytest tests/ --cov=src --cov-report=html
```

### Run specific modules

```bash
pytest tests/test_algorithms.py -v    # Unit + tamper detection
pytest tests/test_api.py -v           # REST integration
pytest tests/test_api_extended.py -v  # Sign/verify + edge cases
pytest tests/test_security.py -v      # FIPS + key hierarchy
pytest tests/test_fuzz.py -v          # Hypothesis property tests
pytest tests/test_kms.py -v           # Local key store
pytest tests/test_streaming.py -v     # Async streaming pipeline
```

### Lint

```bash
ruff check src/ tests/
mypy src/
```

### Test module summary

| Module | Coverage Area |
|:-------|:-------------|
| `test_algorithms.py` | AES / ChaCha / RSA / ECDH / Hybrid / Fernet / Argon2 round-trips, tamper, wrong key, nonce uniqueness |
| `test_api.py` | All REST endpoints end-to-end |
| `test_api_extended.py` | Sign/verify flows, file endpoints, error handling |
| `test_security.py` | FIPS enforcement, HKDF derivation, key rotation |
| `test_fuzz.py` | Property-based fuzzing on all algorithms |
| `test_kms.py` | LocalKeyStore: CRUD, rotation, wrong-password, persistence |
| `test_streaming.py` | Async round-trips (AES/ChaCha), tamper, large files, empty/single byte |

---

## Tech Stack

| Layer | Technology | Version |
|:------|:-----------|:-------:|
| Language | Python | 3.11+ |
| API framework | FastAPI | 0.111+ |
| Schema validation | Pydantic v2 | 2.7+ |
| Crypto primitives | `cryptography` (OpenSSL) | 42.0+ |
| Memory-hard KDF | argon2-cffi | 23.1+ |
| Audit logging | structlog | 24.1+ |
| CLI | Typer + Rich | 0.12+ |
| ASGI server | Uvicorn | 0.29+ |
| Frontend | React | 19.x |
| Build tool | Vite | 6.x |
| Styling | TailwindCSS | 4.x |
| Animation | Framer Motion | 12.x |
| Icons | lucide-react | 0.511+ |
| Testing | pytest + pytest-asyncio | 8.2+ |
| Fuzzing | Hypothesis | 6.100+ |
| HTTP test client | httpx | 0.27+ |
| Linting | Ruff | 0.4+ |
| Type checking | mypy | 1.10+ |
| Containers | Docker + Compose | — |
| Optional PQC | liboqs-python | 0.9+ |

---

## Project Structure

```text
CipherForge/
│
├── src/
│   ├── algorithms/
│   │   ├── aes.py            # AES-256-GCM (NIST SP 800-38D)
│   │   ├── chacha.py         # ChaCha20-Poly1305 (RFC 8439)
│   │   ├── rsa.py            # RSA-4096-OAEP + PSS (NIST SP 800-56B)
│   │   ├── ecdh.py           # X25519-ECDH + AES (NIST SP 800-56A)
│   │   ├── hybrid.py         # RSA envelope + AES-256-GCM
│   │   ├── fernet.py         # Fernet token encryption + rotation
│   │   ├── argon2_enc.py     # Argon2id + AES-256-GCM (RFC 9106)
│   │   └── pqc.py            # X25519 + Kyber-768 hybrid (NIST PQC)
│   │
│   ├── api/
│   │   ├── app.py            # FastAPI app, CORS, exception handlers
│   │   ├── schemas.py        # Pydantic v2 models
│   │   └── routes/
│   │       ├── encrypt.py    # POST /encrypt/text, /encrypt/file
│   │       ├── decrypt.py    # POST /decrypt/text, /decrypt/file
│   │       ├── keys.py       # POST /keys/generate, /keys/sign, /keys/verify
│   │       └── audit.py      # GET /audit/log, /compliance/fips
│   │
│   ├── kms/
│   │   ├── local.py          # Dev key store (Argon2id + AES-GCM JSON)
│   │   ├── aws_kms.py        # AWS KMS envelope adapter
│   │   └── vault.py          # HashiCorp Vault Transit adapter
│   │
│   ├── audit.py              # Structured JSON audit logger
│   ├── exceptions.py         # Typed exception hierarchy
│   ├── fips.py               # FIPS 140-3 policy enforcement
│   ├── key_hierarchy.py      # HKDF-SHA256 domain-separated key tree
│   ├── secure_buffer.py      # Memory-locked sensitive buffer
│   └── streaming.py          # Async 64 KB chunked AEAD pipeline
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx           # Root: 6-tab layout + hero
│   │   ├── components/
│   │   │   ├── Sidebar.jsx       # Fixed sidebar with live health status
│   │   │   ├── EncryptTab.jsx    # Text encrypt/decrypt UI
│   │   │   ├── FileTab.jsx       # File vault drag-and-drop
│   │   │   ├── SignTab.jsx       # RSA-PSS sign/verify
│   │   │   ├── KeysTab.jsx       # Key generation workshop
│   │   │   ├── BenchmarkTab.jsx  # Algorithm throughput benchmark
│   │   │   └── GuideTab.jsx      # Algorithm reference guide
│   │   ├── hooks/
│   │   │   └── useHealth.js      # /v1/health polling hook
│   │   └── lib/
│   │       └── api.js            # fetch helpers + base64 utilities
│   ├── vite.config.js        # Vite + TailwindCSS plugin + /v1 proxy
│   └── package.json          # Dependencies
│
├── tests/                    # 8 test modules
├── cli.py                    # Typer CLI
├── conftest.py               # Pytest path setup
├── pyproject.toml            # Build + dependency config
├── Dockerfile                # Multi-stage build
└── docker-compose.yml        # API service + health check
```

---

## Performance

Measured with the dashboard Benchmark tab (includes HTTP round-trip latency):

| Algorithm | Encrypt 1 KB | Decrypt 1 KB | Notes |
|:----------|:------------:|:------------:|:------|
| AES-256-GCM | ~2 ms | ~1 ms | AES-NI hardware accelerated |
| ChaCha20-Poly1305 | ~2 ms | ~1 ms | Software — no hardware needed |
| RSA-4096-OAEP | ~50–80 ms | ~15 ms | 446 B payload max |
| Hybrid RSA+AES | ~55–85 ms | ~18 ms | Unlimited payload size |
| X25519-ECDH | ~3 ms | ~3 ms | Ephemeral key per operation |
| Argon2id + AES | ~200 ms | ~200 ms | Memory-hard by design |

---
## 📸 Snapshots


<img width="1883" height="859" alt="image" src="https://github.com/user-attachments/assets/2feefec0-1dad-4f90-b2f5-0e8f9a40838c" />


--
<img width="1897" height="860" alt="image" src="https://github.com/user-attachments/assets/c617628f-82e6-4dd8-bb83-bfef5aa0165e" />


--
<img width="1891" height="854" alt="image" src="https://github.com/user-attachments/assets/e16e264c-d637-4ee3-bff6-9be2714e957e" />

--
<img width="1898" height="862" alt="image" src="https://github.com/user-attachments/assets/c6eeff20-99bc-46b0-bb69-794420eca939" />


--
<img width="1895" height="857" alt="image" src="https://github.com/user-attachments/assets/0e5ac98b-9995-4020-8795-537c2288ce12" />


--
<img width="1878" height="867" alt="image" src="https://github.com/user-attachments/assets/af5180b8-ea57-4dab-aae5-ca1500513e35" />


---
## Contributing

1. Fork the repository on GitHub
2. Create a feature branch: `git checkout -b feature/improvement`
3. Write tests for your changes
4. Run `pytest tests/ -v` and `ruff check src/ tests/`
5. Submit a pull request with a clear description

---
## 👤 Author

**Yashas D**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Yashas%20D-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/yashasd2004/)
[![GitHub](https://img.shields.io/badge/GitHub-Yashas14-181717?logo=github&logoColor=white)](https://github.com/Yashas14)

