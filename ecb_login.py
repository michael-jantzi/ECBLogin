"""Open the desktop assigned by Pascal in RealVNC Viewer through an SSH tunnel."""

import argparse
import asyncio
import getpass
import os
import re
import subprocess
import sys
from pathlib import Path

import asyncssh

from ecb_credentials import read_password, save_password


GATEWAY = "pascal.ee.ryerson.ca"
LOOPBACK = "127.0.0.1"
DEFAULT_LOCAL_PORT = 5905
OTP_ENTRY = "ECB_Dept_AuthCode"
VNC_IDLE_TIMEOUT = 90
HOST_PROMPT = re.compile(r"^[ \t]*(Password|Verification code):[ \t\r\n]*\Z", re.IGNORECASE | re.MULTILINE)
# Pascal wraps this notice across lines and spells "invoke" as "envoke".
DEPARTMENT_NOTICE = re.compile(
    r"\bFound system: (?P<host>[a-z0-9][a-z0-9.-]*) Connecting you to the host\. "
    r"You will be asked for your departmental network password to [ei]nvoke "
    r"the VNC session on the host (?P=host)\. Password:\Z", re.IGNORECASE
)
FORWARD = re.compile(
    r"(?<!\S)-L[ \t]*127\.0\.0\.1:[0-9]{1,5}:"
    r"([A-Za-z0-9][A-Za-z0-9.-]*):([0-9]{1,5})(?!\S)"
)


def read_secret(prompt):
    if not sys.stdin.isatty():
        raise RuntimeError("Run Connect-ECB in an interactive terminal to enter your password.")
    return getpass.getpass(prompt)


class LoginClient(asyncssh.SSHClient):
    def __init__(self, username, password_entry, refresh_passwords=False):
        self.username = username
        self.password_entry = password_entry
        self.refresh_passwords = refresh_passwords
        self.pending_passwords = {}
        self.database_password = None
        self.department_password = None
        self.gateway_code = None
        self.answered = set()

    def get_password(self, target, account, prompt):
        if not self.refresh_passwords:
            try:
                saved = read_password(target)
            except RuntimeError as exc:
                print(f"{exc} Enter the password for this session.", file=sys.stderr)
                return read_secret(prompt)
            if saved is not None:
                return saved
        password = read_secret(prompt)
        self.pending_passwords[target] = (account, password)
        return password

    def read_entry(self, entry, *options):
        cli = Path(os.environ["ProgramFiles"]) / "KeePassXC" / "keepassxc-cli.exe"
        database = Path(os.environ["LOCALAPPDATA"]) / "ECB" / "otp.kdbx"
        if not cli.is_file():
            raise FileNotFoundError(f"KeePassXC CLI was not found at {cli}.")
        if not database.is_file():
            raise FileNotFoundError(f"The OTP database was not found at {database}.")
        if self.database_password is None:
            self.database_password = self.get_password(
                f"ECB Login Script/KeePassXC/{database.resolve()}",
                database.name,
                "KeePassXC password for otp.kdbx: ",
            )
        result = subprocess.run(
            [cli, "show", "--quiet", *options, "--", database, entry],
            input=(self.database_password + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(
                f"KeePassXC could not read {entry!r}. Check the vault password and entry name. "
                r"If the saved vault password changed, run .\Connect-ECB.ps1 -RefreshPasswords."
            )
        value = result.stdout.decode("utf-8")
        return value.removesuffix("\r\n") if value.endswith("\r\n") else value.removesuffix("\n")

    def answer_once(self, factor):
        if factor in self.answered:
            raise asyncssh.PermissionDenied(
                f"Pascal requested the {factor} again. Check your credentials and reconnect."
            )
        self.answered.add(factor)
        if factor == "password":
            if self.password_entry:
                self.department_password = self.read_entry(self.password_entry, "--attributes", "Password")
            else:
                # Credential Manager matches targets without case sensitivity. SSH usernames are case-sensitive.
                account_key = self.username.encode("utf-8").hex()
                self.department_password = self.get_password(
                    f"ECB Login Script/SSH/{GATEWAY}/{account_key}",
                    self.username,
                    f"Department password for {self.username}: ",
                )
            return self.department_password
        self.gateway_code = self.read_verification_code()
        return self.gateway_code

    def read_verification_code(self):
        code = self.read_entry(OTP_ENTRY, "--totp")
        if not re.fullmatch(r"[0-9]{6,8}", code):
            raise RuntimeError(f"KeePassXC did not return a numeric verification code for {OTP_ENTRY}.")
        return code

    async def host_verification_code(self):
        code = self.read_verification_code()
        if code == self.gateway_code:
            print("Waiting for KeePassXC to generate the next verification code ...", flush=True)
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 90
            while code == self.gateway_code:
                if loop.time() >= deadline:
                    raise RuntimeError("KeePassXC did not generate a new verification code within 90 seconds.")
                await asyncio.sleep(2)
                if self.gateway_code is None:
                    raise RuntimeError("The SSH connection closed while waiting for the VNC verification code.")
                code = self.read_verification_code()
        return code

    def kbdint_auth_requested(self):
        return ""  # Let Pascal select its keyboard-interactive mechanism.

    def kbdint_challenge_received(self, name, instructions, lang, prompts):
        responses = []
        for prompt, _echo in prompts:
            label = prompt.rsplit(")", 1)[-1].strip().rstrip(":").strip().lower()
            if label not in {"password", "verification code"}:
                raise asyncssh.PermissionDenied("Pascal sent an unrecognized authentication prompt.")
            responses.append(self.answer_once(label))
        return responses

    def password_auth_requested(self):
        return self.answer_once("password")

    def auth_completed(self):
        self.save_pending_passwords()

    def save_pending_passwords(self):
        for target, (account, password) in self.pending_passwords.items():
            try:
                save_password(target, account, password)
            except RuntimeError as exc:
                print(f"{exc} The SSH login succeeded, but this password was not saved.", file=sys.stderr)
        self.pending_passwords.clear()

    def clear_credentials(self):
        self.database_password = None
        self.department_password = None
        self.gateway_code = None
        self.pending_passwords.clear()

    def connection_lost(self, exc):
        self.clear_credentials()


def vnc_destination(output):
    targets = {
        (host, int(port))
        for line in output.splitlines()
        if re.match(r"^\s*ssh\s", line)
        for host, port in FORWARD.findall(line)
    }
    if len(targets) != 1:
        raise ValueError(
            "Expected one SSH forwarding destination in the vncconnect output. "
            "Run vncconnect on Pascal to inspect the session."
        )
    host, port = targets.pop()
    if not 1 <= port <= 65535:
        raise ValueError("vncconnect returned an invalid destination port.")
    return host, port


def terminal_text(text):
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text).replace("\r\n", "\n")


async def discover_vnc(connection, department_password=None, get_verification_code=None):
    # An SSH shell request loads the account's interactive login environment on Pascal.
    marker = "__ECB_VNC_OUTPUT__"
    marker_line = f"\n{marker}\n"
    chunks = []
    pending = ""
    started = False
    last_factor = None
    failure = None
    async with connection.create_process(
        term_type="dumb",
        term_size=(240, 24),
        term_modes={asyncssh.PTY_ECHO: 0},
        stderr=asyncssh.STDOUT,
    ) as shell:
        # Start a fresh output line after the shell prompt. Keep stdin open while vncconnect runs.
        shell.stdin.write(f"printf '\\n{marker}\\n'; vncconnect; exit\n")
        try:
            while True:
                # Spinner updates count as activity. Both prompts can arrive split across reads.
                chunk = await asyncio.wait_for(shell.stdout.read(4096), VNC_IDLE_TIMEOUT)
                if not chunk:
                    break
                chunks.append(chunk)
                # Only the most recent lines are needed to recognize a prompt. Parse the full result once at EOF.
                pending = terminal_text(pending[-4096:] + chunk)
                if not started:
                    _, separator, body = ("\n" + pending).partition(marker_line)
                    if not separator:
                        continue
                    started, pending = True, body
                prompt = HOST_PROMPT.search(pending)
                if not prompt:
                    continue
                factor = prompt[1].lower()
                if factor == "password":
                    if last_factor is not None or not DEPARTMENT_NOTICE.search(" ".join(pending.split())):
                        failure = "vncconnect requested an unexpected password. Run it interactively on Pascal."
                        break
                    if department_password is None or re.search(r"[\x00-\x1f\x7f]", department_password):
                        failure = "The SSH password cannot be used for this terminal prompt. Run vncconnect on Pascal."
                        break
                    shell.stdin.write(department_password + "\n")
                else:
                    if last_factor != "password" or get_verification_code is None:
                        failure = "vncconnect requested an unexpected verification code. Run it interactively on Pascal."
                        break
                    code = await get_verification_code()
                    if not re.fullmatch(r"[0-9]{6,8}", code):
                        raise RuntimeError("KeePassXC returned an invalid verification code for the VNC host.")
                    shell.stdin.write(code + "\n")
                    print("Verification code sent. Waiting for the VNC service to start ...", flush=True)
                last_factor = factor
                pending = ""
            if failure is None:
                await asyncio.wait_for(shell.wait_closed(), VNC_IDLE_TIMEOUT)
        except asyncio.TimeoutError:
            failure = f"vncconnect timed out after {VNC_IDLE_TIMEOUT} seconds without output from Pascal."

    transcript = terminal_text("".join(chunks))
    _, separator, output = ("\n" + transcript).partition(marker_line)
    if failure is None:
        if shell.exit_status != 0:
            failure = f"Pascal's login shell exited with status {shell.exit_status} while running vncconnect."
        elif not separator:
            failure = "Pascal's login shell closed before running vncconnect."
        else:
            try:
                return vnc_destination(output)
            except ValueError as exc:
                failure = str(exc)

    # A remote program may echo terminal input despite the initial PTY settings.
    if last_factor is not None:
        raise RuntimeError(failure)
    last_lines = (output if separator else transcript).strip().splitlines()[-6:]
    detail = "\n".join("".join(c for c in line if c.isprintable()) for line in last_lines)[-1000:]
    raise RuntimeError(f"{failure}\n{detail}" if detail else failure)


def open_realvnc(local_port):
    # Match the saved ECB address exactly. For custom ports, :: forces a TCP port even below 100.
    address = f"{LOOPBACK}:{local_port}" if local_port == DEFAULT_LOCAL_PORT else f"{LOOPBACK}::{local_port}"
    viewer = Path(os.environ["ProgramFiles"]) / "RealVNC" / "VNC Viewer" / "vncviewer.exe"
    try:
        os.startfile(viewer, arguments=f"-useaddressbook {address}")
    except OSError as exc:
        print(f"Could not open RealVNC Viewer ({exc}). Enter {address} in your viewer.", file=sys.stderr)


async def connect_vnc(username, local_port, password_entry=None, refresh_passwords=False):
    print(f"Connecting to {username}@{GATEWAY} ...", flush=True)
    client = LoginClient(username, password_entry, refresh_passwords)
    async with asyncssh.connect(
        GATEWAY,
        username=username,
        client_factory=lambda: client,
        config=None,
        preferred_auth=("keyboard-interactive", "password"),
        agent_path=None,
        compression_algs=("zlib@openssh.com", "none"),
        keepalive_interval=30,
    ) as connection:
        print("Running vncconnect in Pascal's login shell ...", flush=True)
        try:
            host, port = await discover_vnc(connection, client.department_password, client.host_verification_code)
            client.save_pending_passwords()
        finally:
            client.clear_credentials()
        try:
            listener = await connection.forward_local_port(LOOPBACK, local_port, host, port)
        except OSError as exc:
            raise RuntimeError(f"Could not listen on {LOOPBACK}:{local_port}. Try another -LocalPort. {exc}") from exc
        async with listener:
            print(f"VNC tunnel ready: {LOOPBACK}:{local_port} -> {host}:{port}", flush=True)
            open_realvnc(local_port)
            print("Keep this window open while using VNC. Press Ctrl+C to close the tunnel.", flush=True)
            await connection.wait_closed()
            raise RuntimeError("The SSH connection closed. Run Connect-ECB again to reconnect.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", default="mtjantzi")
    parser.add_argument("--local-port", type=int, default=DEFAULT_LOCAL_PORT)
    parser.add_argument("--password-entry", help="KeePassXC entry containing the department password")
    parser.add_argument("--refresh-passwords", action="store_true", help="replace remembered passwords after login")
    args = parser.parse_args()
    if not 1 <= args.local_port <= 65535:
        parser.error("--local-port must be between 1 and 65535")
    try:
        asyncio.run(connect_vnc(args.username, args.local_port, args.password_entry, args.refresh_passwords))
    except KeyboardInterrupt:
        print("\nConnection closed.")
    except asyncssh.HostKeyNotVerifiable:
        sys.exit(
            f"Could not verify the SSH host key for {GATEWAY}. Verify its fingerprint with the department, "
            f"then check the saved key using ssh {args.username}@{GATEWAY}."
        )
    except asyncssh.PermissionDenied as exc:
        if args.password_entry:
            hint = "Check the department password in your KeePassXC entry."
        else:
            hint = r"If your department password changed, run .\Connect-ECB.ps1 -RefreshPasswords."
        sys.exit(f"Login failed: {exc}\n{hint}")
    except (asyncssh.Error, OSError, ValueError, RuntimeError, EOFError) as exc:
        sys.exit(f"Connection failed: {exc}")


if __name__ == "__main__":
    main()
