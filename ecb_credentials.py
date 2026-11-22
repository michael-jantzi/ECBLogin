"""Store passwords for the current user in Windows Credential Manager."""

try:
    import pywintypes
    import win32cred
    import winerror
except ImportError:
    win32cred = None


def _require_win32cred():
    if win32cred is None:
        raise RuntimeError(
            "Windows Credential Manager requires pywin32. On Windows, install the project requirements."
        )


def read_password(target: str) -> str | None:
    _require_win32cred()
    try:
        credential = win32cred.CredRead(target, win32cred.CRED_TYPE_GENERIC)
    except pywintypes.error as exc:
        if exc.winerror == winerror.ERROR_NOT_FOUND:
            return None
        raise RuntimeError(f"Windows Credential Manager could not read {target!r} (error {exc.winerror}).") from exc

    try:
        return credential["CredentialBlob"].decode("utf-16-le")
    except (KeyError, AttributeError, UnicodeDecodeError):
        raise RuntimeError(f"Windows Credential Manager returned an invalid password for {target!r}.") from None


def save_password(target: str, username: str, password: str) -> None:
    _require_win32cred()
    credential = {
        "Type": win32cred.CRED_TYPE_GENERIC,
        "TargetName": target,
        "UserName": username,
        # CredWrite accepts a Python str and writes its UTF-16LE bytes.
        "CredentialBlob": password,
        "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
    }
    try:
        win32cred.CredWrite(credential)
    except pywintypes.error as exc:
        raise RuntimeError(f"Windows Credential Manager could not save {target!r} (error {exc.winerror}).") from exc
