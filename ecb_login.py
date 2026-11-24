"""Open the desktop assigned by Pascal in RealVNC Viewer through an SSH tunnel."""

import argparse
import asyncio
import getpass
import os
import re
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

import asyncssh

from ecb_credentials import read_password, save_password
from ecb_portable import PortableSession, application_directory, external_program
from ecb_viewer_profile import find_viewer_profile
from vnc_password import deliver_password, encode_vnc_password, password_pipe


GATEWAY = "pascal.ee.ryerson.ca"
LOOPBACK = "127.0.0.1"
DEFAULT_LOCAL_PORT = 5905
OTP_ENTRY = "ECB_Dept_AuthCode"
VNC_IDLE_TIMEOUT = 90
HOST_PROMPT = re.compile(r"^[ \t]*(Password|Verification code):[ \t\r\n]*\Z", re.IGNORECASE | re.MULTILINE)
HOST_RETRY_PROMPT = re.compile(
    r"\s*(?:Permission denied, please try again\.\s*)?Password:\s*\Z", re.IGNORECASE
)
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
    def __init__(self, username, password_entry, refresh_passwords=False, portable=None):
        self.username = username
        self.password_entry = password_entry
        self.refresh_passwords = refresh_passwords
        self.portable = portable
        self.pending_passwords = {}
        self.database_password = None
        self.department_password = None
        self.gateway_code = None
        self.gateway_retries = 0
        self.gateway_retry_code = False
        self.used_verification_codes = set()
        self.answered = set()

    def account_target(self, service):
        # Credential Manager targets are case-insensitive, but department usernames are case-sensitive.
        account_key = self.username.encode("utf-8").hex()
        return f"ECB Login Script/{service}/{GATEWAY}/{account_key}"

    def get_password(self, target, account, prompt):
        if not self.refresh_passwords:
            if self.portable:
                saved = self.portable.vault.read_password(target)
            else:
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
        if self.portable:
            return self.portable.vault.read_entry(entry, *options)
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
            if factor == "password":
                if self.gateway_code is not None:
                    raise asyncssh.PermissionDenied(
                        "Pascal restarted login after the verification code. The code may have expired or been used already. "
                        "Check the computer's date/time and reconnect with a fresh code."
                    )
                raise asyncssh.PermissionDenied(
                    "Pascal rejected the department password before requesting a verification code."
                )
            raise asyncssh.PermissionDenied(
                f"Pascal requested the {factor} again. Check your credentials and reconnect."
            )
        self.answered.add(factor)
        if factor == "password":
            if self.password_entry:
                self.department_password = self.read_entry(self.password_entry, "--attributes", "Password")
            else:
                self.department_password = self.get_password(
                    self.account_target("SSH"),
                    self.username,
                    f"Department password for {self.username}: ",
                )
            return self.department_password
        self.gateway_code = self.read_verification_code()
        self.used_verification_codes.add(self.gateway_code)
        return self.gateway_code

    def read_verification_code(self):
        code = self.read_entry(OTP_ENTRY, "--totp")
        if not re.fullmatch(r"[0-9]{6,8}", code):
            raise RuntimeError(f"KeePassXC did not return a numeric verification code for {OTP_ENTRY}.")
        return code

    async def unused_verification_code(self, context):
        if self.gateway_code is None:
            raise RuntimeError(f"The SSH connection closed before requesting the {context} verification code.")
        code = self.read_verification_code()
        if code in self.used_verification_codes:
            print("Waiting for KeePassXC to generate the next verification code ...", flush=True)
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 90
            while code in self.used_verification_codes:
                if loop.time() >= deadline:
                    raise RuntimeError("KeePassXC did not generate a new verification code within 90 seconds.")
                await asyncio.sleep(2)
                if self.gateway_code is None:
                    raise RuntimeError(f"The SSH connection closed while waiting for the {context} verification code.")
                code = self.read_verification_code()
        self.used_verification_codes.add(code)
        return code

    async def host_verification_code(self):
        return await self.unused_verification_code("VNC")

    def kbdint_auth_requested(self):
        return ""  # Let Pascal select its keyboard-interactive mechanism.

    async def kbdint_challenge_received(self, name, instructions, lang, prompts):
        responses = []
        for prompt, _echo in prompts:
            label = prompt.rsplit(")", 1)[-1].strip().rstrip(":").strip().lower()
            if label not in {"password", "verification code"}:
                raise asyncssh.PermissionDenied("Pascal sent an unrecognized authentication prompt.")
            if (label == "password" and label in self.answered and self.gateway_code is not None
                    and self.gateway_retries == 0 and self.department_password is not None):
                # PAM can restart the entire conversation after rejecting an OTP.
                # Reuse the department password once, then wait for an unused code.
                self.gateway_retries += 1
                self.gateway_retry_code = True
                self.answered = {"password"}
                responses.append(self.department_password)
                print("Pascal restarted login after verification. Retrying once with a fresh verification code ...", flush=True)
            elif label == "verification code" and self.gateway_retry_code and label not in self.answered:
                self.gateway_code = await self.unused_verification_code("Pascal")
                self.gateway_retry_code = False
                self.answered.add(label)
                responses.append(self.gateway_code)
            else:
                responses.append(self.answer_once(label))
            if label == "password":
                print("Department password sent to Pascal.", flush=True)
            else:
                print("Verification code sent to Pascal.", flush=True)
        return responses

    def password_auth_requested(self):
        password = self.answer_once("password")
        print("Department password sent to Pascal.", flush=True)
        return password

    def auth_completed(self):
        self.save_pending_passwords()

    def save_pending_passwords(self):
        for target, (account, password) in self.pending_passwords.items():
            try:
                if self.portable:
                    self.portable.vault.save_password(target, account, password)
                else:
                    save_password(target, account, password)
            except RuntimeError as exc:
                print(f"{exc} This password could not be saved for the next login.", file=sys.stderr)
        self.pending_passwords.clear()

    def clear_credentials(self):
        self.database_password = None
        self.department_password = None
        self.gateway_code = None
        self.gateway_retries = 0
        self.gateway_retry_code = False
        self.used_verification_codes.clear()
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
    password_retries = 0
    service_started = False
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
                service_started = service_started or "Please wait for service to begin ..." in pending
                prompt = HOST_PROMPT.search(pending)
                if not prompt:
                    continue
                if service_started:
                    failure = (
                        "The lab PC logged in, but VNC startup requested additional authentication. "
                        "Run vncconnect interactively on Pascal to inspect the request."
                    )
                    break
                factor = prompt[1].lower()
                if factor == "password":
                    if last_factor == "verification code":
                        # Some PTYs echo the submitted code and erase it with backspaces.
                        pending = pending.replace(code, "").replace("\b", "")
                    if last_factor is None:
                        if not DEPARTMENT_NOTICE.search(" ".join(pending.split())):
                            failure = "vncconnect requested an unexpected password. Run it interactively on Pascal."
                            break
                    elif (
                        last_factor == "verification code" and password_retries == 0
                        and HOST_RETRY_PROMPT.fullmatch(pending)
                    ):
                        password_retries += 1
                        print(
                            "The lab PC requested another SSH login. Retrying once with a fresh verification code ...",
                            flush=True,
                        )
                    else:
                        failure = (
                            "The lab PC repeated its SSH password prompt. "
                            "Check the department password and verification code, then reconnect."
                        )
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


async def viewer_accepted_password(process):
    # Read only this Viewer's authentication result. A later manual retry can use a different password.
    header = re.compile(
        rb"^(?:<[0-9]+> \S+ \S+ )?vncviewer\[" + str(process.pid).encode("ascii") + rb"\]: CConnection: "
    )
    while line := await process.stderr.readline():
        match = header.match(line)
        if not match:
            continue
        message = line[match.end():].rstrip(b"\r\n")
        if message == b"Authentication successful":
            return True
        if message.startswith(b"close:"):
            break
    return False


async def open_realvnc(local_port, client):
    # Match the saved ECB address exactly. For custom ports, :: forces a TCP port even below 100.
    address = f"{LOOPBACK}:{local_port}" if local_port == DEFAULT_LOCAL_PORT else f"{LOOPBACK}::{local_port}"
    portable = client.portable
    viewer = portable.viewer if portable else Path(os.environ["ProgramFiles"]) / "RealVNC" / "VNC Viewer" / "vncviewer.exe"
    target = client.account_target("VNC")
    process = None
    try:
        try:
            if not viewer.is_file():
                raise FileNotFoundError(viewer)
            encoded = encode_vnc_password(client.get_password(
                target, client.username, f"VNC desktop password for {client.username}: ",
            ))
            profile = portable.viewer_profile(local_port) if portable else find_viewer_profile(local_port)
            with password_pipe() as (path, pipe):
                args = [
                    viewer, "-UseAddressBook=0", "-LogToAddressBook=0", "-Log=CConnection:stderr:10",
                    f"-PasswordFile={path}", address,
                ]
                if profile is not None:
                    args.extend(["-config", profile])
                with external_program():
                    process = await asyncio.create_subprocess_exec(
                        *args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    )
                await deliver_password(pipe, encoded, process.pid)
            del encoded
            try:
                accepted = await asyncio.wait_for(viewer_accepted_password(process), 120)
            except asyncio.TimeoutError:
                accepted = False
            if accepted:
                client.save_pending_passwords()
            else:
                print(
                    ("VNC login was not confirmed. Run Connect-ECB.exe --refresh-passwords to replace the USB password."
                     if portable else r"VNC login was not confirmed. To replace a saved password, run .\Connect-ECB.ps1 -RefreshPasswords."),
                    file=sys.stderr,
                )
        except (OSError, RuntimeError, ValueError, EOFError) as exc:
            print(f"Automatic VNC login unavailable ({exc}). Enter the password in RealVNC Viewer.", file=sys.stderr)
            if process is None:
                try:
                    if portable:
                        args = [viewer, "-UseAddressBook=0", "-LogToAddressBook=0", "-Log=CConnection:stderr:10", address]
                        profile = portable.viewer_profile(local_port)
                        if profile is not None:
                            args.extend(["-config", profile])
                        with external_program():
                            process = await asyncio.create_subprocess_exec(
                                *args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            )
                    else:
                        os.startfile(viewer, arguments=f"-useaddressbook {address}")
                except OSError as launch_error:
                    print(f"Could not open RealVNC Viewer ({launch_error}). Enter {address} in your viewer.", file=sys.stderr)
        finally:
            client.pending_passwords.pop(target, None)

        if process is not None:
            # Keep stderr drained while the desktop is open, including after a manual retry.
            while await process.stderr.read(4096):
                pass
            await process.wait()
    finally:
        if process is not None and process.returncode is None:
            with suppress(ProcessLookupError):
                process.terminate()
            await process.communicate()


async def connect_vnc(username, local_port, password_entry=None, refresh_passwords=False, portable=None):
    print(f"Connecting to {username}@{GATEWAY} ...", flush=True)
    client = LoginClient(username, password_entry, refresh_passwords, portable)
    try:
        await _connect_vnc(client, local_port)
    finally:
        client.clear_credentials()
        if portable:
            portable.vault.clear()


async def _connect_vnc(client, local_port):
    portable = client.portable
    options = {"known_hosts": str(portable.known_hosts), "client_keys": []} if portable else {}
    async with asyncssh.connect(
        GATEWAY,
        username=client.username,
        client_factory=lambda: client,
        config=None,
        preferred_auth=("keyboard-interactive", "password"),
        agent_path=None,
        compression_algs=("zlib@openssh.com", "none"),
        keepalive_interval=30,
        **options,
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
            print("Keep this window open while using VNC. Press Ctrl+C to close the tunnel.", flush=True)
            viewer_task = asyncio.create_task(open_realvnc(local_port, client))
            connection_task = None
            try:
                if portable:
                    connection_task = asyncio.create_task(connection.wait_closed())
                    done, _ = await asyncio.wait((viewer_task, connection_task), return_when=asyncio.FIRST_COMPLETED)
                    if viewer_task in done:
                        await viewer_task
                        return
                else:
                    await connection.wait_closed()
            finally:
                viewer_task.cancel()
                with suppress(asyncio.CancelledError):
                    await viewer_task
                if connection_task is not None:
                    connection_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await connection_task
            raise RuntimeError("The SSH connection closed. Run Connect-ECB again to reconnect.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username")
    parser.add_argument("--local-port", type=int)
    parser.add_argument("--password-entry", help="KeePassXC entry containing the department password")
    parser.add_argument("--refresh-passwords", action="store_true", help="replace remembered passwords after login")
    parser.add_argument("--portable", action="store_true", help="use USB-local tools, vault, and settings")
    parser.add_argument("--portable-root", type=Path, help="portable folder (defaults to the executable folder)")
    parser.add_argument("--check", action="store_true", help="check portable files without unlocking or connecting")
    args = parser.parse_args()
    if args.local_port is not None and not 1 <= args.local_port <= 65535:
        parser.error("--local-port must be between 1 and 65535")
    portable = None
    try:
        if args.portable or args.portable_root is not None or getattr(sys, "frozen", False):
            portable = PortableSession(args.portable_root or application_directory(), read_secret)
            portable.validate(GATEWAY)
            if args.check:
                portable.check(GATEWAY)
                return
        elif args.check:
            parser.error("--check requires --portable or --portable-root")
        settings = portable.settings if portable else {}
        username = args.username if args.username is not None else settings.get("username", "mtjantzi")
        port = args.local_port if args.local_port is not None else settings.get("local_port", DEFAULT_LOCAL_PORT)
        password_entry = args.password_entry if args.password_entry is not None else settings.get("password_entry")
        if portable:
            portable.viewer_profile(port)
        asyncio.run(connect_vnc(username, port, password_entry, args.refresh_passwords, portable))
    except KeyboardInterrupt:
        print("\nConnection closed.")
    except asyncssh.HostKeyNotVerifiable:
        if portable:
            sys.exit(f"Could not verify the SSH key for {GATEWAY}. Verify the fingerprint with the department and update data/known_hosts.")
        sys.exit(
            f"Could not verify the SSH host key for {GATEWAY}. Verify its fingerprint with the department, "
            f"then check the saved key using ssh {username}@{GATEWAY}."
        )
    except asyncssh.PermissionDenied as exc:
        if args.password_entry or (portable and portable.settings["password_entry"]):
            hint = "Check the department password in your KeePassXC entry."
        else:
            hint = ("If your department password changed, run Connect-ECB.exe --refresh-passwords."
                    if portable else r"If your department password changed, run .\Connect-ECB.ps1 -RefreshPasswords.")
        sys.exit(f"Login failed: {exc}\n{hint}")
    except (asyncssh.Error, OSError, ValueError, RuntimeError, EOFError) as exc:
        sys.exit(f"Connection failed: {exc}")
    finally:
        if portable:
            portable.vault.clear()


if __name__ == "__main__":
    main()
