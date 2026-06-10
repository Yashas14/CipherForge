"""Secure memory buffer — prevents key leakage via swap/core dumps.

Security notes:
- Allocates memory with mlock() on supported platforms — prevents swapping to disk
- Zeroes memory on deletion using ctypes to prevent compiler optimization removal
- Falls back to standard bytes on platforms without mlock support
- Compatible with Python's secrets module for key generation
- WARNING: Python's GC may copy data — this is best-effort, not a guarantee
"""

from __future__ import annotations

import ctypes
import platform

_IS_WINDOWS = platform.system() == "Windows"
_IS_LINUX = platform.system() == "Linux"
_IS_MACOS = platform.system() == "Darwin"


def _mlock(address: int, size: int) -> bool:
    """Lock memory pages to prevent swapping.

    Args:
        address: Memory address to lock.
        size: Number of bytes to lock.

    Returns:
        True if successful.
    """
    try:
        if _IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            return bool(kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(size)))
        elif _IS_LINUX or _IS_MACOS:
            libc = ctypes.CDLL("libc.so.6" if _IS_LINUX else "libSystem.B.dylib")
            result = libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return result == 0
    except (OSError, AttributeError):
        pass
    return False


def _munlock(address: int, size: int) -> bool:
    """Unlock memory pages.

    Args:
        address: Memory address to unlock.
        size: Number of bytes to unlock.

    Returns:
        True if successful.
    """
    try:
        if _IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            return bool(kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(size)))
        elif _IS_LINUX or _IS_MACOS:
            libc = ctypes.CDLL("libc.so.6" if _IS_LINUX else "libSystem.B.dylib")
            result = libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return result == 0
    except (OSError, AttributeError):
        pass
    return False


class SecureBuffer:
    """Secure memory buffer for sensitive data (keys, passwords).

    Allocates memory with mlock() — prevents swapping to disk.
    Zeroes memory on __del__ using ctypes to prevent compiler optimization removal.

    Usage:
        buf = SecureBuffer(32)
        buf.write(key_bytes)
        key = buf.read()
        del buf  # zeros memory
    """

    def __init__(self, size: int) -> None:
        """Allocate a secure buffer.

        Args:
            size: Number of bytes to allocate.
        """
        self._size = size
        self._buffer = (ctypes.c_char * size)()
        self._locked = False
        self._written = False

        # Try to lock memory
        address = ctypes.addressof(self._buffer)
        self._locked = _mlock(address, size)

    @property
    def size(self) -> int:
        """Return buffer size in bytes."""
        return self._size

    @property
    def is_locked(self) -> bool:
        """Return whether memory is locked (mlock'd)."""
        return self._locked

    def write(self, data: bytes) -> None:
        """Write data into the secure buffer.

        Args:
            data: Data to write. Must not exceed buffer size.

        Raises:
            ValueError: If data exceeds buffer size.
        """
        if len(data) > self._size:
            raise ValueError(f"Data ({len(data)} bytes) exceeds buffer size ({self._size} bytes)")

        # Zero existing content first
        ctypes.memset(ctypes.addressof(self._buffer), 0, self._size)

        # Copy data in
        ctypes.memmove(ctypes.addressof(self._buffer), data, len(data))
        self._written = True

    def read(self) -> bytes:
        """Read data from the secure buffer.

        Returns:
            Bytes content of the buffer.

        Raises:
            ValueError: If nothing has been written.
        """
        if not self._written:
            raise ValueError("Buffer has not been written to")
        return bytes(self._buffer[: self._size])

    def zero(self) -> None:
        """Explicitly zero the buffer contents.

        Uses ctypes.memset to prevent compiler from optimizing away the zeroing.
        """
        ctypes.memset(ctypes.addressof(self._buffer), 0, self._size)
        self._written = False

    def __del__(self) -> None:
        """Zero memory and unlock on garbage collection."""
        try:
            # Guaranteed zero using ctypes — not subject to compiler optimization
            ctypes.memset(ctypes.addressof(self._buffer), 0, self._size)

            # Unlock memory
            if self._locked:
                address = ctypes.addressof(self._buffer)
                _munlock(address, self._size)
        except (TypeError, AttributeError):
            pass  # During interpreter shutdown

    def __enter__(self) -> SecureBuffer:
        """Context manager entry."""
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit — zeros buffer."""
        self.zero()

    def __repr__(self) -> str:
        """Safe repr — never shows content."""
        return f"SecureBuffer(size={self._size}, locked={self._locked})"

    def __str__(self) -> str:
        """Never reveal content in string conversion."""
        return f"[SecureBuffer: {self._size} bytes]"

