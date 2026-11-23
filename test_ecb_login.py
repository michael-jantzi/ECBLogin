import asyncio
import io
import os
import unittest
from contextlib import ExitStack, asynccontextmanager, nullcontext, redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh

from ecb_login import LoginClient, connect_vnc, discover_vnc, open_realvnc
from vnc_password import encode_vnc_password


FORWARD = "ssh student@gateway -L 127.0.0.1:5900:cmp10.example:5901\n"
PASSWORD = "  fixture '$pw' & !  "
VERIFICATION_CODE = "004217"
VNC_PROMPT = (
    "\nFound system: cmp10\n"
    "Connecting you to the host.  You will be asked for your departmental\n"
    "network password to envoke the VNC session on the host cmp10.\n\n"
    "Password:"
)


async def write_prompt(process, prompt=VNC_PROMPT, *, trailing_space=False):
    # Deliver a partial prompt and leave the completed prompt without a newline.
    process.stdout.write(prompt[:-4])
    await asyncio.sleep(0.02)
    process.stdout.write(prompt[-4:])
    if trailing_space:
        await asyncio.sleep(0.02)
        process.stdout.write(" ")


async def read_response(process, timeout):
    try:
        return await asyncio.wait_for(process.stdin.readline(), timeout)
    except asyncio.TimeoutError:
        return ""


async def request_both_factors(process):
    await write_prompt(process, VNC_PROMPT.replace("cmp10", "cmp11"), trailing_space=True)
    password = await read_response(process, 2)
    await write_prompt(process, "\nVerification code:", trailing_space=True)
    code = await read_response(process, 2)
    return [password, code]


class FixtureGateway(asyncssh.SSHServer):
    def begin_auth(self, username):
        return False


@asynccontextmanager
async def gateway(output, status=0, *, before_marker=None, after_marker=None):
    async def session(process):
        # Reproduce a server where only the interactive login shell can find vncconnect.
        if process.command is not None or not process.term_type:
            process.stderr.write("vncconnect: command not found\n")
            process.exit(127)
            return
        process.stdout.write("Old example from the login banner:\n")
        process.stdout.write("ssh student@gateway -L 127.0.0.1:5900:obsolete.example:5901\n")
        command = await process.stdin.readline()
        if command.strip() != r"printf '\n__ECB_VNC_OUTPUT__\n'; vncconnect; exit":
            process.exit(2)
            return
        if before_marker:
            await before_marker(process)
        process.stdout.write("\n__ECB_VNC_OUTPUT__\n")
        if after_marker:
            await after_marker(process)
        (process.stderr if status else process.stdout).write(output)
        process.exit(status)

    key = asyncssh.generate_private_key("ssh-ed25519")
    async with asyncssh.listen(
        "127.0.0.1", 0,
        server_factory=FixtureGateway,
        server_host_keys=[key],
        process_factory=session,
    ) as server:
        async with asyncssh.connect(
            "127.0.0.1", server.get_port(),
            username="fixture",
            config=None,
            known_hosts=([key.convert_to_public()], [], []),
            agent_path=None,
            client_keys=None,
        ) as connection:
            yield connection


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovers_current_forward_in_login_shell(self):
        responses = []
        get_code = AsyncMock()

        async def existing_session(process):
            process.stdout.write("Active session on: cmp10.example.\n")
            responses.append(await read_response(process, 0.25))

        async with gateway(FORWARD, after_marker=existing_session) as connection:
            result = await asyncio.wait_for(discover_vnc(connection, PASSWORD, get_code), 5)
        self.assertEqual(result, ("cmp10.example", 5901))
        self.assertEqual(responses, [""])
        get_code.assert_not_awaited()

    async def test_reports_shell_diagnostic_if_command_is_missing(self):
        async with gateway("vncconnect: Command not found.\n", status=127) as connection:
            with self.assertRaisesRegex(RuntimeError, "vncconnect: Command not found"):
                await asyncio.wait_for(discover_vnc(connection), 5)

    async def test_starts_session_after_fragmented_department_password_prompt(self):
        responses = []
        get_code = AsyncMock()

        async def start_session(process):
            await write_prompt(process)
            responses.append(await read_response(process, 2))
            process.stdout.write("\n")

        async with gateway(FORWARD, after_marker=start_session) as connection:
            result = await asyncio.wait_for(discover_vnc(connection, PASSWORD, get_code), 5)
        self.assertEqual(result, ("cmp10.example", 5901))
        self.assertEqual(responses, [PASSWORD + "\n"])
        get_code.assert_not_awaited()

    async def test_repeated_department_prompt_receives_only_one_password(self):
        responses = []

        async def repeat_prompt(process):
            await write_prompt(process)
            responses.append(await read_response(process, 2))
            process.stdout.write("\nPermission denied, please try again.\n")
            await write_prompt(process)
            responses.append(await read_response(process, 0.25))

        async with gateway("\nPermission denied.\n", 1, after_marker=repeat_prompt) as connection:
            with self.assertRaises(RuntimeError) as caught:
                await asyncio.wait_for(discover_vnc(connection, PASSWORD), 5)
        self.assertEqual([response for response in responses if response], [PASSWORD + "\n"])
        self.assertNotIn(PASSWORD, str(caught.exception))

    async def test_ignores_precommand_and_unrelated_password_prompts(self):
        responses = []

        async def banner(process):
            await write_prompt(process)
            responses.append(await read_response(process, 0.25))

        async def unrelated(process):
            process.stdout.write("Create a new VNC viewer password.\nPassword:")
            responses.append(await read_response(process, 0.25))
            process.stdout.write("\n")

        async with gateway("Viewer setup cancelled.\n", 1, before_marker=banner, after_marker=unrelated) as connection:
            with self.assertRaises(RuntimeError):
                await asyncio.wait_for(discover_vnc(connection, PASSWORD), 5)
        self.assertEqual(responses, ["", ""])

    async def test_verification_then_processing_continues_beyond_one_idle_interval(self):
        responses = []
        get_code = AsyncMock(return_value=VERIFICATION_CODE)

        async def start_desktop(process):
            responses.extend(await request_both_factors(process))
            process.stdout.write("\nPlease wait for service to begin ...\n")
            for _ in range(5):
                await asyncio.sleep(0.2)
                process.stdout.write("\r           | ... Processing ... |")
            process.stdout.write("\n")

        with patch("ecb_login.VNC_IDLE_TIMEOUT", 0.6):
            async with gateway(FORWARD.replace("cmp10", "cmp11"), after_marker=start_desktop) as connection:
                result = await asyncio.wait_for(discover_vnc(connection, PASSWORD, get_code), 5)
        self.assertEqual(result, ("cmp11.example", 5901))
        self.assertEqual(responses, [PASSWORD + "\n", VERIFICATION_CODE + "\n"])
        get_code.assert_awaited_once_with()

    async def test_verification_prompt_before_department_password_receives_no_code(self):
        responses = []
        get_code = AsyncMock(return_value=VERIFICATION_CODE)

        async def unexpected_code(process):
            await write_prompt(process, "\nVerification code:")
            responses.append(await read_response(process, 0.25))

        async with gateway(
            "\nLogin failed.\n", 1, before_marker=unexpected_code, after_marker=unexpected_code,
        ) as connection:
            with self.assertRaises(RuntimeError):
                await asyncio.wait_for(discover_vnc(connection, PASSWORD, get_code), 5)
        self.assertEqual(responses, ["", ""])
        get_code.assert_not_awaited()

    async def test_repeated_verification_prompt_receives_only_one_code(self):
        responses = []
        get_code = AsyncMock(return_value=VERIFICATION_CODE)

        async def retry_code(process):
            responses.extend(await request_both_factors(process))
            await write_prompt(process, "\nVerification code:")
            responses.append(await read_response(process, 0.25))

        async with gateway("\nLogin failed.\n", 1, after_marker=retry_code) as connection:
            with self.assertRaises(RuntimeError):
                await asyncio.wait_for(discover_vnc(connection, PASSWORD, get_code), 5)
        self.assertEqual(
            [response for response in responses if response],
            [PASSWORD + "\n", VERIFICATION_CODE + "\n"],
        )
        get_code.assert_awaited_once_with()

    async def test_idle_startup_times_out_and_omits_echoed_credentials(self):
        responses = []
        get_code = AsyncMock(return_value=VERIFICATION_CODE)

        async def stalled_desktop(process):
            responses.extend(await request_both_factors(process))
            process.stdout.write("\n" + "".join(responses) + "Please wait for service to begin ...\n")
            await read_response(process, 2)

        messages = io.StringIO()
        with patch("ecb_login.VNC_IDLE_TIMEOUT", 0.6), redirect_stdout(messages), redirect_stderr(messages):
            async with gateway(FORWARD, after_marker=stalled_desktop) as connection:
                with self.assertRaisesRegex(RuntimeError, r"(?i)timed? ?out|no output|idle") as caught:
                    await asyncio.wait_for(discover_vnc(connection, PASSWORD, get_code), 5)
        self.assertEqual(responses, [PASSWORD + "\n", VERIFICATION_CODE + "\n"])
        diagnostics = messages.getvalue() + str(caught.exception)
        self.assertNotIn(PASSWORD.strip(), diagnostics)
        self.assertNotIn(VERIFICATION_CODE, diagnostics)
        get_code.assert_awaited_once_with()

    async def test_omits_echoed_password_from_remote_errors(self):
        responses = []

        async def echo_password(process):
            await write_prompt(process)
            response = await read_response(process, 2)
            responses.append(response)
            process.stdout.write(response)

        async with gateway("VNC session failed.\n", 1, after_marker=echo_password) as connection:
            with self.assertRaises(RuntimeError) as caught:
                await asyncio.wait_for(discover_vnc(connection, PASSWORD), 5)
        self.assertEqual(responses, [PASSWORD + "\n"])
        self.assertNotIn(PASSWORD.strip(), str(caught.exception))


class ViewerLaunchTests(unittest.IsolatedAsyncioTestCase):
    pipe_path = r"\\.\pipe\fixture"
    viewer_pid = 4321

    def setUp(self):
        fixtures = ExitStack()
        self.addCleanup(fixtures.close)
        ssh = fixtures.enter_context(patch("ecb_login.asyncssh.connect"))
        self.connection = ssh.return_value.__aenter__.return_value
        self.listener = MagicMock()
        self.connection.forward_local_port = AsyncMock(return_value=self.listener)
        self.viewer_done = asyncio.Event()

        async def wait_for_viewer():
            await asyncio.wait_for(self.viewer_done.wait(), 2)

        self.connection.wait_closed = AsyncMock(side_effect=wait_for_viewer)
        fixtures.enter_context(patch("ecb_login.discover_vnc", return_value=("assigned.example", 5990)))
        root = Path(fixtures.enter_context(TemporaryDirectory()))
        fixtures.enter_context(patch.dict(os.environ, {"ProgramFiles": str(root)}))
        self.executable = root / "RealVNC" / "VNC Viewer" / "vncviewer.exe"
        self.executable.parent.mkdir(parents=True)
        self.executable.touch()
        self.profile = fixtures.enter_context(patch("ecb_login.find_viewer_profile", return_value=None))
        self.launch = fixtures.enter_context(patch("ecb_login.asyncio.create_subprocess_exec"))
        self.manual = fixtures.enter_context(patch("ecb_login.os.startfile", create=True))
        self.pipe = object()
        fixtures.enter_context(patch("ecb_login.password_pipe", return_value=nullcontext((self.pipe_path, self.pipe))))
        self.delivered = asyncio.Event()
        self.deliver = fixtures.enter_context(patch(
            "ecb_login.deliver_password", side_effect=lambda *_: self.delivered.set(),
        ))
        self.saved = {}
        fixtures.enter_context(patch("ecb_login.read_password", side_effect=lambda key: self.saved.get(key.casefold())))
        fixtures.enter_context(patch("ecb_login.save_password", side_effect=self.save))
        self.prompt = fixtures.enter_context(patch("ecb_login.read_secret", return_value="VncTest!"))
        self.errors = fixtures.enter_context(redirect_stderr(io.StringIO()))
        fixtures.enter_context(redirect_stdout(io.StringIO()))

    def save(self, target, username, password):
        self.saved[target.casefold()] = password

    def prepare_viewer(self):
        process = self.launch.return_value
        process.pid = self.viewer_pid
        process.stderr = asyncio.StreamReader()
        process.returncode = 0
        process.wait = AsyncMock(side_effect=self.viewer_done.set)
        return process.stderr

    def audit(self, message, pid=None):
        pid = self.viewer_pid if pid is None else pid
        return f"<13> 2026-11-23T16:21:46.336Z FIXTURE vncviewer[{pid}]: CConnection: {message}\r\n".encode()

    def accepted_viewer(self):
        stream = self.prepare_viewer()
        stream.feed_data(self.audit("Authentication successful"))
        stream.feed_eof()

    async def run_until_disconnect(self, local_port):
        with self.assertRaisesRegex(RuntimeError, "SSH connection closed"):
            await connect_vnc("fixture", local_port)
        self.connection.wait_closed.assert_awaited_once()

    async def test_opens_saved_connection_after_local_tunnel_is_ready(self):
        self.accepted_viewer()
        profile = Path("School desktop.vnc")
        self.profile.return_value = profile

        def check_listener(*args, **kwargs):
            self.listener.__aenter__.assert_awaited_once()
            self.listener.__aexit__.assert_not_awaited()
            return self.launch.return_value

        self.launch.side_effect = check_listener
        await self.run_until_disconnect(5905)
        self.connection.forward_local_port.assert_awaited_once_with("127.0.0.1", 5905, "assigned.example", 5990)
        args = self.launch.await_args.args
        self.assertEqual(args[0], self.executable)
        self.assertEqual(args[-3:], ("127.0.0.1:5905", "-config", profile))
        self.assertIn(f"-PasswordFile={self.pipe_path}", args)
        self.assertNotIn(self.prompt.return_value, repr(self.launch.await_args))

    async def test_bind_failure_skips_viewer_and_vnc_password_prompt(self):
        self.connection.forward_local_port.side_effect = OSError("port busy")
        with self.assertRaisesRegex(RuntimeError, "port busy"):
            await connect_vnc("fixture", 5905)
        self.launch.assert_not_awaited()
        self.prompt.assert_not_called()

    async def test_launch_failure_keeps_manual_connection_available(self):
        self.launch.side_effect = FileNotFoundError("missing viewer")

        def manual_launch_fails(*args, **kwargs):
            self.viewer_done.set()
            raise FileNotFoundError("missing viewer")

        self.manual.side_effect = manual_launch_fails
        await self.run_until_disconnect(5910)
        self.manual.assert_called_once_with(self.executable, arguments="-useaddressbook 127.0.0.1::5910")
        self.assertIn("127.0.0.1::5910", self.errors.getvalue())
        self.assertEqual(self.saved, {})

    async def test_stores_confirmed_password_per_account_and_reuses_it_across_tunnel_ports(self):
        self.prompt.side_effect = ["ssh fixture", "VncTest!", "OtherVnc"]
        client = LoginClient("student", None)
        self.assertEqual(client.password_auth_requested(), "ssh fixture")
        client.auth_completed()
        before_vnc = self.saved.copy()

        stream = self.prepare_viewer()
        pending = asyncio.create_task(open_realvnc(5905, client))
        try:
            await asyncio.wait_for(self.delivered.wait(), 2)
            self.assertEqual(self.saved, before_vnc)
            self.deliver.assert_awaited_once_with(self.pipe, encode_vnc_password("VncTest!"), self.viewer_pid)
        finally:
            stream.feed_data(self.audit("Authentication successful"))
            stream.feed_eof()
            await asyncio.wait_for(pending, 2)
        self.assertCountEqual(self.saved.values(), ["ssh fixture", "VncTest!"])

        self.accepted_viewer()
        await open_realvnc(5, LoginClient("student", None))
        self.assertEqual(self.prompt.call_count, 2)
        self.assertIn("127.0.0.1::5", self.launch.await_args.args)
        self.deliver.assert_awaited_with(self.pipe, encode_vnc_password("VncTest!"), self.viewer_pid)

        self.accepted_viewer()
        await open_realvnc(5905, LoginClient("Student", None))
        self.deliver.assert_awaited_with(self.pipe, encode_vnc_password("OtherVnc"), self.viewer_pid)
        self.assertCountEqual(self.saved.values(), ["ssh fixture", "VncTest!", "OtherVnc"])

    async def test_refresh_preserves_password_on_rejection_unrelated_success_or_eof(self):
        self.accepted_viewer()
        await open_realvnc(5905, LoginClient("student", None))
        original = self.saved.copy()
        self.prompt.return_value = "NewVnc!!"
        success = self.audit("Authentication successful")
        rejected = self.audit("close: [AuthFailure] vncviewer[4321]: CConnection: Authentication successful")
        for log in [b"", self.audit("Authentication successful", pid=9876), rejected + success]:
            with self.subTest(log=log):
                stream = self.prepare_viewer()
                stream.feed_data(log)
                stream.feed_eof()
                client = LoginClient("student", None, refresh_passwords=True)
                await open_realvnc(5905, client)
                self.assertEqual(self.saved, original)
                self.assertEqual(client.pending_passwords, {})

        self.accepted_viewer()
        await open_realvnc(5905, LoginClient("student", None, refresh_passwords=True))
        self.assertEqual(self.saved.keys(), original.keys())
        self.assertEqual(list(self.saved.values()), ["NewVnc!!"])
        self.assertNotIn("NewVnc!!", self.errors.getvalue())
