<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/FastAPI-v1%20API-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React 19"/>
  <img src="https://img.shields.io/badge/Vite-6-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite 6"/>
  <img src="https://img.shields.io/badge/FIPS-140--3%20Mode-gold?style=for-the-badge" alt="FIPS mode"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License"/>
</p>

<h1 align="center">CipherForge</h1>

<p align="center">
  <strong>Security-first cryptography toolkit with API, CLI, and React dashboard</strong>
</p>

Production-style cryptography playground built with Python, FastAPI, and React.

This repository combines:

- A FastAPI REST service for encryption, decryption, signing, verification, key generation, audit/status, and compliance checks.
- A React dashboard with 6 interactive tabs.
- A Typer CLI for local encryption workflows.
- Reusable crypto modules (including optional post-quantum hybrid support).
- Security-focused helpers for FIPS policy checks, structured audit logging, key hierarchy derivation, and streaming encryption.

## What Is Implemented Right Now

### API encryption and decryption algorithms

The text/file REST endpoints currently support 5 algorithms directly:

- aes-gcm
- chacha20
- rsa-oaep
- hybrid (RSA + AES-GCM envelope)
- ecdh (X25519 + AES-GCM)

### Additional algorithms in the codebase

These are implemented in the library/CLI layer, but not all are exposed from the main encrypt/decrypt REST endpoints:

- Fernet
- Argon2id + AES
- Hybrid X25519 + Kyber-768 (optional, requires liboqs)

### Security and platform capabilities

- FIPS mode gate via CRYPTO_FIPS_MODE and runtime policy checks.
- Structured JSON audit logging with operation metadata (no plaintext/key material logging).
- HKDF-based key hierarchy with domain-separated derivation.
- Streaming encryption/decryption pipeline with per-chunk integrity checks.
- Local key store and optional AWS KMS / Vault integration modules.

## Architecture Snapshot

```text
Frontend (React 19 + Vite 6 + Tailwind 4 + Framer Motion)
   |
   | /v1 proxy from :3000 to :8000
   v
FastAPI app (src/api/app.py)
   |- /v1/encrypt/*
   |- /v1/decrypt/*
   |- /v1/keys/*
   |- /v1/audit/log
   |- /v1/compliance/fips
   |- /v1/health
   |- /v1/algorithms
   v
Crypto modules + FIPS policy + audit + key hierarchy + streaming + KMS adapters
```

## REST API Reference

Base URL: http://localhost:8000/v1

| Endpoint | Method | Purpose |
|---|---|---|
| /v1/health | GET | Liveness plus uptime, FIPS state, and algorithm count |
| /v1/algorithms | GET | Metadata for available algorithm catalog |
| /v1/encrypt/text | POST | Encrypt base64 plaintext |
| /v1/decrypt/text | POST | Decrypt base64 ciphertext |
| /v1/encrypt/file | POST | Encrypt uploaded file bytes |
| /v1/decrypt/file | POST | Decrypt uploaded encrypted file bytes |
| /v1/keys/generate | POST | Generate key material metadata (algorithm-specific) |
| /v1/keys/sign | POST | RSA-PSS signing |
| /v1/keys/verify | POST | RSA-PSS signature verification |
| /v1/audit/log | GET | Audit endpoint (placeholder response + guidance) |
| /v1/compliance/fips | GET | FIPS policy report |

OpenAPI docs are available at:

- http://localhost:8000/docs
- http://localhost:8000/redoc

## Frontend Dashboard

The React app includes these tabs:

1. Encrypt / Decrypt: text workflows for 5 API algorithms and optional AAD.
2. File Vault: drag-and-drop file encryption/decryption (currently API text route based).
3. Sign & Verify: RSA-4096-PSS signing and verification flow.
4. Key Workshop: server-generated keys plus browser-side RSA keypair generation helpers.
5. Benchmark: AES-GCM vs ChaCha20 benchmark against live API calls.
6. Algorithm Guide: reference cards with best-practice notes.

## CLI Commands

The CLI entry point is cli.py and provides commands such as:

- encrypt
- decrypt
- keygen
- algorithms
- audit-log
- fips
- serve

Example:

```bash
python cli.py algorithms
python cli.py keygen --algo rsa --out ./keys
python cli.py encrypt ./notes.txt --algo aes-gcm
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+

### Install dependencies

```bash
pip install -e ".[dev]"
cd frontend
npm install
cd ..
```

### Run backend + frontend

Terminal 1:

```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```

Terminal 2:

```bash
cd frontend
npm run dev
```

Open http://localhost:3000.

### Production-style frontend build

```bash
cd frontend
npm run build
cd ..
uvicorn src.api.app:app --host 0.0.0.0 --port 8000
```

If frontend/dist exists, FastAPI serves it at /.

## Testing and Quality

The repository contains 8 dedicated test modules across algorithms, API, fuzz/property tests, security policy, KMS, and streaming behavior.

A quick static count currently shows 80 explicit test_* functions in tests/.

Run locally:

```bash
pytest tests -v
ruff check src tests
```

## Security Notes

- AEAD modes are used for authenticated encryption in core flows.
- FIPS checks can reject disallowed algorithms when compliance mode is enabled.
- Audit logs are structured and intentionally avoid sensitive payload material.
- Streaming format includes chunk boundary integrity checks.
- Post-quantum mode gracefully falls back when liboqs is not installed.

## Repository Layout

```text
.
|- src/
|  |- algorithms/
|  |- api/
|  |- kms/
|  |- audit.py
|  |- fips.py
|  |- key_hierarchy.py
|  |- secure_buffer.py
|  |- streaming.py
|- frontend/
|  |- src/
|  |- package.json
|  |- vite.config.js
|- tests/
|- cli.py
|- pyproject.toml
|- Dockerfile
|- docker-compose.yml
```

## Known Notes

- The optional PQC implementation requires liboqs-python and is not a default API route path.
- The audit endpoint currently returns a placeholder message while logs are emitted to structured output.
- Some docker-compose references may need alignment if you plan to run a Streamlit UI target.

## License

MIT.

