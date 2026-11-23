"""Supply a classic VNC password to RealVNC Viewer through a private Windows pipe."""

import asyncio
import sys
import uuid
from contextlib import closing, contextmanager

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

try:
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32pipe
    import win32security
    import winerror
except ImportError:
    win32pipe = None


def encode_vnc_password(password: str) -> bytes:
    """Build the eight-byte value expected by Viewer's PasswordFile option."""
    if not password or "\0" in password:
        raise ValueError("Enter a nonempty VNC password without NUL.")
    # Viewer reads PasswordFile in the Windows ANSI code page, then uses the first eight UTF-8 bytes for VNC.
    encoding = "mbcs" if sys.platform == "win32" else "ascii"
    unsupported = "This password cannot be represented in RealVNC's eight-byte Windows password file."
    try:
        prefix = ""
        for char in password[:8]:
            prefix += char
            if len(prefix.encode("utf-8")) >= 8:
                break
        raw = prefix.encode(encoding)
        if len(raw) > 8 or raw.decode(encoding) != prefix:
            raise ValueError(unsupported)
    except UnicodeError:
        raise ValueError(unsupported) from None
    # The VNC password-file format uses single DES with this fixed key.
    key = bytes.fromhex("e84ad660c4721ae0")
    encoder = Cipher(TripleDES(key * 3), modes.ECB()).encryptor()
    return encoder.update(raw.ljust(8, b"\0")) + encoder.finalize()


@contextmanager
def password_pipe():
    """Expose one non-inheritable, local-only pipe to the current Windows user."""
    if sys.platform != "win32":
        raise OSError("Automatic VNC password entry requires Windows.")
    if win32pipe is None:
        raise OSError("Install the project requirements to enable the private Windows password pipe.")
    path = rf"\\.\pipe\ecb-vnc-{uuid.uuid4().hex}"
    try:
        pipe = _create_user_pipe(path)
    except pywintypes.error as exc:
        raise OSError(exc.winerror, exc.strerror) from exc
    with closing(pipe):
        yield path, pipe


def _create_user_pipe(path):
    with closing(win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)) as token:
        user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        sid = win32security.ConvertSidToStringSid(user_sid)
    access = pywintypes.SECURITY_ATTRIBUTES()
    access.bInheritHandle = False
    access.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;;GA;;;{sid})", win32security.SDDL_REVISION_1
    )
    first_pipe_instance = 0x00080000  # FILE_FLAG_FIRST_PIPE_INSTANCE is absent from pywin32.
    return win32pipe.CreateNamedPipe(
        path, win32pipe.PIPE_ACCESS_OUTBOUND | first_pipe_instance,
        win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_NOWAIT | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
        1, 64, 0, 0, access,
    )


async def deliver_password(pipe, encoded_password: bytes, viewer_pid: int, timeout: float = 90):
    """Wait once for Viewer to open the pipe, then queue its password file."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            win32pipe.ConnectNamedPipe(pipe, None)
            break
        except pywintypes.error as exc:
            if exc.winerror == winerror.ERROR_PIPE_CONNECTED:
                break
            if exc.winerror != winerror.ERROR_PIPE_LISTENING:
                raise OSError(exc.winerror, exc.strerror) from exc
        if loop.time() >= deadline:
            raise TimeoutError("RealVNC Viewer did not request the VNC password in time.")
        await asyncio.sleep(0.1)
    try:
        if win32pipe.GetNamedPipeClientProcessId(pipe) != viewer_pid:
            raise OSError("The password pipe was opened by a different process.")
        _, written = win32file.WriteFile(pipe, encoded_password)
    except pywintypes.error as exc:
        raise OSError(exc.winerror, exc.strerror) from exc
    if written != len(encoded_password):
        raise OSError("RealVNC Viewer could not receive the VNC password.")
