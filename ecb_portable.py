"""USB-local settings and KeePassXC-backed credentials for the portable app."""

import ctypes
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import asyncssh

from ecb_viewer_profile import _profile_port


DEFAULT_SETTINGS = {"username": "mtjantzi", "local_port": 5905, "password_entry": None}


def application_directory():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


@contextmanager
def external_program():
    """Keep the frozen Python DLL directory out of third-party processes."""
    frozen_windows = sys.platform == "win32" and getattr(sys, "frozen", False)
    if frozen_windows:
        ctypes.windll.kernel32.SetDllDirectoryW(None)
    try:
        yield
    finally:
        if frozen_windows:
            ctypes.windll.kernel32.SetDllDirectoryW(sys._MEIPASS)


def run_cli(cli, arguments, secret_input=b""):
    try:
        with external_program():
            return subprocess.run(
                [str(cli), *map(str, arguments)], input=secret_input,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                check=False,
            )
    except subprocess.TimeoutExpired:
        raise RuntimeError("KeePassXC did not finish within 60 seconds.") from None
    except OSError:
        raise RuntimeError("Could not start portable KeePassXC. Run Connect-ECB.exe --check.") from None


def _input_line(value):
    if any(char in value for char in "\r\n\0"):
        raise ValueError("KeePassXC passwords cannot contain line breaks or NUL.")
    return (value + "\n").encode("utf-8")


class PortableVault:
    def __init__(self, cli, database, prompt):
        self.cli = Path(cli)
        self.database = Path(database)
        self.prompt = prompt
        self._password = None

    def unlock(self):
        if self._password is not None:
            return
        password = self.prompt("Unlock the USB vault (otp.kdbx): ")
        result = run_cli(self.cli, ["ls", "--quiet", "--", self.database], _input_line(password))
        if result.returncode:
            raise RuntimeError("Could not unlock the USB vault. Check its password and try again.")
        self._password = password

    def _command(self, command, options=(), entry=None, password=None):
        self.unlock()
        arguments = [command, "--quiet", *options, "--", self.database]
        if entry is not None:
            arguments.append(entry)
        secret_input = _input_line(self._password)
        if password is not None:
            secret_input += _input_line(password)
        return run_cli(self.cli, arguments, secret_input)

    def read_entry(self, entry, *options):
        result = self._command("show", options, entry)
        if result.returncode:
            raise RuntimeError(f"KeePassXC could not read {entry!r} from the USB vault.")
        return self._value(result.stdout)

    @staticmethod
    def _value(output):
        value = output.decode("utf-8")
        return value.removesuffix("\r\n") if value.endswith("\r\n") else value.removesuffix("\n")

    @staticmethod
    def entry_name(target):
        # Reuse the existing case-sensitive, account-specific credential identity.
        _, service, _gateway, account = target.split("/")
        if service not in {"SSH", "VNC"}:
            raise ValueError("Unsupported portable credential type.")
        return f"ECB {service} {account}"

    def read_password(self, target):
        result = self._command("show", ("--attributes", "Password"), self.entry_name(target))
        return None if result.returncode else self._value(result.stdout)

    def save_password(self, target, username, password):
        # Only invoked after the corresponding SSH or VNC authentication succeeds.
        try:
            _input_line(password)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from None
        entry = self.entry_name(target)
        existing = self._command("show", ("--attributes", "Password"), entry)
        command = "edit" if existing.returncode == 0 else "add"
        result = self._command(command, ("--username", username, "--password-prompt"), entry, password)
        if result.returncode:
            raise RuntimeError("Could not save the confirmed password to the USB vault. Check that it is writable.")

    def clear(self):
        self._password = None


class PortableSession:
    def __init__(self, root, prompt):
        self.root = Path(root).resolve()
        self.data = self.root / "data"
        self.cli = self.root / "tools" / "KeePassXC" / "keepassxc-cli.exe"
        self.viewer = self.root / "tools" / "RealVNC" / "vncviewer.exe"
        self.database = self.data / "otp.kdbx"
        self.known_hosts = self.data / "known_hosts"
        self.settings = dict(DEFAULT_SETTINGS)
        settings_file = self.data / "settings.json"
        if settings_file.is_file():
            try:
                supplied = json.loads(settings_file.read_text(encoding="utf-8-sig"))
            except (ValueError, UnicodeError):
                raise ValueError("data/settings.json must contain valid JSON.") from None
            if not isinstance(supplied, dict) or supplied.keys() - DEFAULT_SETTINGS.keys():
                raise ValueError("data/settings.json accepts username, local_port, and password_entry only.")
            self.settings.update(supplied)
        username = self.settings["username"]
        port = self.settings["local_port"]
        entry = self.settings["password_entry"]
        if not isinstance(username, str) or not username or any(ord(c) < 32 for c in username):
            raise ValueError("Set a nonempty username in data/settings.json.")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("local_port in data/settings.json must be between 1 and 65535.")
        if entry is not None and (not isinstance(entry, str) or not entry):
            raise ValueError("password_entry in data/settings.json must be null or an entry name.")
        self.vault = PortableVault(self.cli, self.database, prompt)

    def validate(self, gateway):
        for path in (self.cli, self.viewer, self.database, self.known_hosts):
            if not path.is_file():
                raise FileNotFoundError(f"Required portable file is missing: {path}")
        try:
            hosts = asyncssh.read_known_hosts(str(self.known_hosts))
            trusted, ca, *_ = hosts.match(gateway, "", 22)
        except (OSError, ValueError):
            raise ValueError("data/known_hosts is not a valid SSH host-key file.") from None
        if not trusted and not ca:
            raise ValueError(f"data/known_hosts needs a verified SSH key for {gateway}.")

    def viewer_profile(self, port):
        profile = self.data / "viewer.vnc"
        if not profile.is_file():
            return None
        try:
            if _profile_port(profile) == port:
                return profile
        except (OSError, UnicodeError):
            pass
        raise ValueError("data/viewer.vnc must describe this local port without password or logging overrides.")

    def check(self, gateway):
        self.validate(gateway)
        result = run_cli(self.cli, ["--version"])
        if result.returncode:
            raise RuntimeError("Portable KeePassXC failed to start. Check the bundled runtime DLLs.")
        self.viewer_profile(self.settings["local_port"])
        print(f"Portable files and SSH trust are ready: {self.root}")
        print("KeePassXC starts successfully. Vault unlock and the school connection are checked when you connect.")
