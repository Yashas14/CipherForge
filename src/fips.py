"""FIPS 140-3 compliance mode.

Security notes:
- When FIPS mode is active, only FIPS-approved algorithms are allowed
- Disallows: MD5, SHA-1, DES, 3DES, RC4, ECB mode, RSA < 2048-bit
- Requires: AES, SHA-2/3, RSA ≥ 2048, ECDH P-256+, HMAC
- Logs any attempt to use non-FIPS algorithm
- Controlled via CRYPTO_FIPS_MODE environment variable or explicit activation
"""

from __future__ import annotations

import os
from typing import ClassVar

import structlog

from src.exceptions import AlgorithmDisabledError

log = structlog.get_logger("fips_compliance")


class FIPSMode:
    """FIPS 140-3 compliance enforcement.

    When active:
    - Disallow: MD5, SHA-1, DES, 3DES, RC4, ECB mode, < 2048-bit RSA
    - Require: FIPS-approved algorithms only
    - Log any attempt to use non-FIPS algorithm

    Activate via:
    - Environment variable: CRYPTO_FIPS_MODE=1
    - Explicit call: FIPSMode.enable()
    """

    # FIPS-approved algorithms
    ALLOWED_ALGORITHMS: frozenset[str] = frozenset({
        "aes-128-gcm",
        "aes-256-gcm",
        "aes-128-cbc",
        "aes-256-cbc",
        "chacha20-poly1305",
        "rsa-2048-oaep",
        "rsa-3072-oaep",
        "rsa-4096-oaep",
        "rsa-2048-pss",
        "rsa-3072-pss",
        "rsa-4096-pss",
        "x25519-ecdh",
        "ecdh-p256",
        "ecdh-p384",
        "ecdh-p521",
        "ed25519",
        "sha-256",
        "sha-384",
        "sha-512",
        "sha3-256",
        "sha3-384",
        "sha3-512",
        "hmac-sha256",
        "hmac-sha384",
        "hmac-sha512",
        "hkdf-sha256",
        "hkdf-sha384",
        "argon2id",
        "hybrid-rsa-aes",
        "hybrid-ecdh-aes",
    })

    # Explicitly disallowed algorithms
    DISALLOWED_ALGORITHMS: frozenset[str] = frozenset({
        "md5",
        "sha1",
        "sha-1",
        "des",
        "3des",
        "triple-des",
        "rc4",
        "ecb",
        "aes-ecb",
        "rsa-1024",
        "rsa-512",
        "pkcs1v15",
        "rsa-pkcs1",
        "blowfish",
        "idea",
        "cast5",
    })

    # Minimum key sizes in bits
    MIN_KEY_SIZES: ClassVar[dict[str, int]] = {
        "rsa": 2048,
        "aes": 128,
        "ecdh": 256,
        "hmac": 256,
    }

    _enabled: bool = False

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if FIPS mode is currently active."""
        if cls._enabled:
            return True
        return os.environ.get("CRYPTO_FIPS_MODE", "0") in ("1", "true", "yes")

    @classmethod
    def enable(cls) -> None:
        """Explicitly enable FIPS mode."""
        cls._enabled = True
        log.info("fips_mode_enabled")

    @classmethod
    def disable(cls) -> None:
        """Explicitly disable FIPS mode."""
        cls._enabled = False
        log.info("fips_mode_disabled")

    @classmethod
    def check_algorithm(cls, algorithm: str) -> None:
        """Check if an algorithm is FIPS-approved.

        Args:
            algorithm: Algorithm identifier to check.

        Raises:
            AlgorithmDisabledError: If algorithm is not FIPS-approved and FIPS mode is active.
        """
        if not cls.is_enabled():
            return

        algo_lower = algorithm.lower().strip()

        # Check explicit disallowed list
        if algo_lower in cls.DISALLOWED_ALGORITHMS:
            log.warning(
                "fips_violation_attempt",
                algorithm=algorithm,
                reason="explicitly_disallowed",
            )
            raise AlgorithmDisabledError(
                algorithm, reason="not FIPS 140-3 approved (explicitly disallowed)"
            )

        # Check if in allowed list
        if algo_lower not in cls.ALLOWED_ALGORITHMS:
            log.warning(
                "fips_violation_attempt",
                algorithm=algorithm,
                reason="not_in_allowed_list",
            )
            raise AlgorithmDisabledError(
                algorithm, reason="not in FIPS 140-3 approved algorithm list"
            )

    @classmethod
    def check_key_size(cls, algorithm_family: str, key_size_bits: int) -> None:
        """Check if a key size meets FIPS minimum requirements.

        Args:
            algorithm_family: Algorithm family (rsa, aes, ecdh, hmac).
            key_size_bits: Key size in bits.

        Raises:
            AlgorithmDisabledError: If key size is below FIPS minimum.
        """
        if not cls.is_enabled():
            return

        family_lower = algorithm_family.lower()
        min_size = cls.MIN_KEY_SIZES.get(family_lower)

        if min_size and key_size_bits < min_size:
            log.warning(
                "fips_key_size_violation",
                algorithm_family=algorithm_family,
                key_size_bits=key_size_bits,
                min_required=min_size,
            )
            raise AlgorithmDisabledError(
                f"{algorithm_family}-{key_size_bits}",
                reason=f"key size {key_size_bits} bits below FIPS minimum of {min_size} bits",
            )

    @classmethod
    def get_compliance_report(cls) -> dict:
        """Generate a FIPS compliance status report.

        Returns:
            Dictionary with compliance status and details.
        """
        return {
            "fips_mode": cls.is_enabled(),
            "allowed_algorithms": sorted(cls.ALLOWED_ALGORITHMS),
            "disallowed_algorithms": sorted(cls.DISALLOWED_ALGORITHMS),
            "minimum_key_sizes": cls.MIN_KEY_SIZES,
            "standard": "FIPS 140-3",
            "reference": "NIST SP 800-175B Rev. 1",
        }

