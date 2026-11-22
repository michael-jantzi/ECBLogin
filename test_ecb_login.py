import asyncio
import io
import unittest
from contextlib import asynccontextmanager, redirect_stderr, redirect_stdout
from unittest.mock import AsyncMock, patch

import asyncssh

from ecb_login import discover_vnc


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
