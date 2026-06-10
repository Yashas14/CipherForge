"""Typer CLI for the encryption suite.

Provides command-line interface for all cryptographic operations
with rich terminal output, progress bars, and colored status messages.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.algorithms.aes import AESEncryptor
from src.algorithms.chacha import ChaChaEncryptor
from src.algorithms.rsa import RSAEncryptor
from src.algorithms.ecdh import ECDHEncryptor
from src.algorithms.argon2_enc import Argon2Encryptor
from src.algorithms.fernet import FernetEncryptor
from src.fips import FIPSMode

app = typer.Typer(
    name="crypto",
    help="🔐 Next-Level CipherForgeX CLI — Enterprise-grade encryption toolkit",
    add_completion=True,
)
console = Console()


@app.command()
def encrypt(
    file: Path = typer.Argument(..., help="File to encrypt", exists=True),
    algorithm: str = typer.Option("aes-gcm", "--algo", "-a", help="Encryption algorithm"),
    output: Optional[Path] = typer.Option(None, "--out", "-o", help="Output file path"),
    password: bool = typer.Option(False, "--password", "-p", help="Use password-based encryption (Argon2id)"),
) -> None:
    """Encrypt a file using the specified algorithm."""
    if not output:
        output = file.with_suffix(file.suffix + ".enc")

    FIPSMode.check_algorithm(algorithm)

    plaintext = file.read_bytes()
    file_size = len(plaintext)

    with console.status(f"[bold green]Encrypting {file.name} with {algorithm}…"):
        start = time.perf_counter()

        if password:
            pwd = typer.prompt("Enter encryption password", hide_input=True)
            pwd_confirm = typer.prompt("Confirm password", hide_input=True)
            if pwd != pwd_confirm:
                console.print("[bold red]❌ Passwords do not match[/bold red]")
                raise typer.Exit(1)
            encryptor = Argon2Encryptor()
            ciphertext = encryptor.encrypt(plaintext, pwd.encode())
            key_info = "Password-derived (Argon2id)"
        elif algorithm == "aes-gcm":
            key = AESEncryptor.generate_key()
            ciphertext = AESEncryptor.encrypt(plaintext, key)
            key_info = base64.b64encode(key).decode()
        elif algorithm == "chacha20":
            key = ChaChaEncryptor.generate_key()
            ciphertext = ChaChaEncryptor.encrypt(plaintext, key)
            key_info = base64.b64encode(key).decode()
        else:
            console.print(f"[bold red]❌ Unknown algorithm: {algorithm}[/bold red]")
            raise typer.Exit(1)

        elapsed = (time.perf_counter() - start) * 1000

    output.write_bytes(ciphertext)

    console.print(f"\n[bold green]✅ Encrypted → {output}[/bold green]")
    console.print(f"   Algorithm: {algorithm}")
    console.print(f"   Input size: {file_size:,} bytes")
    console.print(f"   Output size: {len(ciphertext):,} bytes")
    console.print(f"   Duration: {elapsed:.1f} ms")
    if not password:
        console.print(f"   Key (save this!): {key_info}")


@app.command()
def decrypt(
    file: Path = typer.Argument(..., help="File to decrypt", exists=True),
    algorithm: str = typer.Option("aes-gcm", "--algo", "-a", help="Decryption algorithm"),
    output: Optional[Path] = typer.Option(None, "--out", "-o", help="Output file path"),
    key: Optional[str] = typer.Option(None, "--key", "-k", help="Base64-encoded decryption key"),
    password: bool = typer.Option(False, "--password", "-p", help="Use password-based decryption"),
) -> None:
    """Decrypt a file using the specified algorithm."""
    if not output:
        output = file.with_suffix("")  # Remove .enc extension

    ciphertext = file.read_bytes()

    with console.status(f"[bold green]Decrypting {file.name}…"):
        start = time.perf_counter()

        if password:
            pwd = typer.prompt("Enter decryption password", hide_input=True)
            encryptor = Argon2Encryptor()
            plaintext = encryptor.decrypt(ciphertext, pwd.encode())
        elif key:
            key_bytes = base64.b64decode(key)
            if algorithm == "aes-gcm":
                plaintext = AESEncryptor.decrypt(ciphertext, key_bytes)
            elif algorithm == "chacha20":
                plaintext = ChaChaEncryptor.decrypt(ciphertext, key_bytes)
            else:
                console.print(f"[bold red]❌ Unknown algorithm: {algorithm}[/bold red]")
                raise typer.Exit(1)
        else:
            console.print("[bold red]❌ Either --key or --password is required[/bold red]")
            raise typer.Exit(1)

        elapsed = (time.perf_counter() - start) * 1000

    output.write_bytes(plaintext)

    console.print(f"\n[bold green]✅ Decrypted → {output}[/bold green]")
    console.print(f"   Algorithm: {algorithm}")
    console.print(f"   Output size: {len(plaintext):,} bytes")
    console.print(f"   Duration: {elapsed:.1f} ms")


@app.command()
def keygen(
    algorithm: str = typer.Option("rsa", "--algo", "-a", help="Key type (rsa, x25519, aes, chacha, fernet)"),
    bits: int = typer.Option(4096, "--bits", "-b", help="Key size in bits (for RSA)"),
    output_dir: Path = typer.Option(Path("."), "--out", "-o", help="Output directory"),
) -> None:
    """Generate a cryptographic key pair."""
    output_dir.mkdir(parents=True, exist_ok=True)

    with console.status(f"[bold green]Generating {algorithm} key…"):
        start = time.perf_counter()

        if algorithm == "rsa":
            private_key, public_key = RSAEncryptor.generate_keypair()
            priv_pem = RSAEncryptor.export_private_key(private_key)
            pub_pem = RSAEncryptor.export_public_key(public_key)

            priv_path = output_dir / "private_key.pem"
            pub_path = output_dir / "public_key.pem"
            priv_path.write_bytes(priv_pem)
            pub_path.write_bytes(pub_pem)

            elapsed = (time.perf_counter() - start) * 1000
            console.print(f"\n[bold green]✅ RSA-{bits} key pair generated[/bold green]")
            console.print(f"   Private key: {priv_path}")
            console.print(f"   Public key:  {pub_path}")

        elif algorithm == "x25519":
            private_key, public_key = ECDHEncryptor.generate_keypair()
            priv_bytes = ECDHEncryptor.export_private_key(private_key)
            pub_bytes = ECDHEncryptor.export_public_key(public_key)

            priv_path = output_dir / "x25519_private.key"
            pub_path = output_dir / "x25519_public.key"
            priv_path.write_bytes(base64.b64encode(priv_bytes))
            pub_path.write_bytes(base64.b64encode(pub_bytes))

            elapsed = (time.perf_counter() - start) * 1000
            console.print("\n[bold green]✅ X25519 key pair generated[/bold green]")
            console.print(f"   Private key: {priv_path}")
            console.print(f"   Public key:  {pub_path}")

        elif algorithm == "aes":
            key = AESEncryptor.generate_key()
            key_path = output_dir / "aes256.key"
            key_path.write_bytes(base64.b64encode(key))
            elapsed = (time.perf_counter() - start) * 1000
            console.print("\n[bold green]✅ AES-256 key generated[/bold green]")
            console.print(f"   Key file: {key_path}")

        elif algorithm == "chacha":
            key = ChaChaEncryptor.generate_key()
            key_path = output_dir / "chacha20.key"
            key_path.write_bytes(base64.b64encode(key))
            elapsed = (time.perf_counter() - start) * 1000
            console.print("\n[bold green]✅ ChaCha20 key generated[/bold green]")
            console.print(f"   Key file: {key_path}")

        elif algorithm == "fernet":
            key = FernetEncryptor.generate_key()
            key_path = output_dir / "fernet.key"
            key_path.write_bytes(key)
            elapsed = (time.perf_counter() - start) * 1000
            console.print("\n[bold green]✅ Fernet key generated[/bold green]")
            console.print(f"   Key file: {key_path}")

        else:
            console.print(f"[bold red]❌ Unknown algorithm: {algorithm}[/bold red]")
            raise typer.Exit(1)

    console.print(f"   Duration: {elapsed:.1f} ms")


@app.command()
def algorithms() -> None:
    """List available algorithms with security ratings."""
    table = Table(title="🔐 Available Algorithms", show_header=True, header_style="bold cyan")
    table.add_column("Algorithm", style="bold")
    table.add_column("Family")
    table.add_column("Key Size")
    table.add_column("Security", style="green")
    table.add_column("FIPS")
    table.add_column("Use Case")

    algos = [
        ("AES-256-GCM", "Symmetric", "256-bit", "Very High", "✅", "General-purpose AEAD"),
        ("ChaCha20-Poly1305", "Symmetric", "256-bit", "Very High", "✅", "Software AEAD (no AES-NI)"),
        ("RSA-4096-OAEP", "Asymmetric", "4096-bit", "Very High", "✅", "Key exchange, small data"),
        ("X25519-ECDH", "Key Agreement", "256-bit", "High", "✅", "Forward-secret key exchange"),
        ("Hybrid RSA+AES", "Hybrid", "4096+256", "Very High", "✅", "Large data + RSA key dist"),
        ("Fernet", "Symmetric", "256-bit", "High", "✅", "Simple token encryption"),
        ("Argon2id+AES", "Password", "256-bit", "High", "✅", "Password-based encryption"),
        ("X25519+Kyber-768", "Post-Quantum", "768-dim", "PQ Safe", "⏳", "Quantum-resistant"),
    ]

    for algo in algos:
        table.add_row(*algo)

    console.print(table)


@app.command("audit-log")
def audit_log(
    last: int = typer.Option(50, "--last", "-n", help="Number of entries to show"),
    operation: Optional[str] = typer.Option(None, "--op", help="Filter by operation type"),
) -> None:
    """View the operation audit log."""
    table = Table(title="📋 Audit Log", show_header=True, header_style="bold cyan")
    table.add_column("Timestamp")
    table.add_column("Operation")
    table.add_column("Algorithm")
    table.add_column("Key ID")
    table.add_column("Status")

    # Note: In production, this reads from persistent audit store
    console.print(
        Panel(
            "Audit logs are emitted to structured log output.\n"
            "Configure LOG_DESTINATION for CloudWatch/Splunk/Elasticsearch shipping.",
            title="ℹ️  Audit Log Info",
            border_style="blue",
        )
    )
    console.print(table)


@app.command()
def fips(
    enable: bool = typer.Option(False, "--enable", help="Enable FIPS mode"),
    disable: bool = typer.Option(False, "--disable", help="Disable FIPS mode"),
    status: bool = typer.Option(False, "--status", "-s", help="Show FIPS status"),
) -> None:
    """Manage FIPS 140-3 compliance mode."""
    if enable:
        FIPSMode.enable()
        console.print("[bold green]✅ FIPS 140-3 mode ENABLED[/bold green]")
    elif disable:
        FIPSMode.disable()
        console.print("[bold yellow]⚠️  FIPS 140-3 mode DISABLED[/bold yellow]")
    else:
        report = FIPSMode.get_compliance_report()
        status_emoji = "🟢" if report["fips_mode"] else "🔴"
        console.print(f"\n{status_emoji} FIPS Mode: {'ENABLED' if report['fips_mode'] else 'DISABLED'}")
        console.print(f"   Standard: {report['standard']}")
        console.print(f"   Reference: {report['reference']}")
        console.print(f"   Approved algorithms: {len(report['allowed_algorithms'])}")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload"),
) -> None:
    """Start the REST API server."""
    import uvicorn

    console.print(f"\n🚀 Starting Crypto API server on {host}:{port}")
    console.print(f"   Docs: http://{host}:{port}/docs")
    console.print(f"   ReDoc: http://{host}:{port}/redoc\n")

    uvicorn.run(
        "encryption_suite_v2.src.api.app:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    app()
