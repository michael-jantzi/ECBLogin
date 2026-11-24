import asyncio
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import asyncssh

import ecb_login
from build_portable import export_trust, prepare_existing
from ecb_portable import PortableSession, PortableVault, _input_line, application_directory, run_cli


CLI = Path(os.environ.get("ProgramFiles", ".")) / "KeePassXC" / "keepassxc-cli.exe"


class PortableSettingsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ECB USB's ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.key = asyncssh.generate_private_key("ssh-ed25519")
        (self.data / "known_hosts").write_bytes(
            ecb_login.GATEWAY.encode() + b" " + self.key.export_public_key()
        )
        for name in ("tools/KeePassXC/keepassxc-cli.exe", "tools/RealVNC/vncviewer.exe", "data/otp.kdbx"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()

    def settings(self, values):
        (self.data / "settings.json").write_text(json.dumps(values), encoding="utf-8")

    def test_paths_follow_the_folder_independently_of_current_directory_and_profile(self):
        with patch.dict(os.environ, {"ProgramFiles": "missing", "APPDATA": "missing", "LOCALAPPDATA": "missing"}):
            session = PortableSession(self.root, Mock())
            session.validate(ecb_login.GATEWAY)
            self.assertEqual(session.database, self.root / "data" / "otp.kdbx")
            self.assertEqual(session.viewer, self.root / "tools" / "RealVNC" / "vncviewer.exe")

    def test_frozen_root_comes_from_executable_instead_of_bundle_internal_directory(self):
        with patch("sys.frozen", True, create=True), patch("sys.executable", str(self.root / "Connect-ECB.exe")):
            self.assertEqual(application_directory(), self.root)

    def test_invalid_settings_fail_without_connecting(self):
        for settings in (["bad"], {"local_port": True}, {"local_port": 0}, {"username": ""},
                         {"username": "bad\nname"}, {"password_entry": []}, {"vault_password": "bad"}):
            with self.subTest(settings=settings):
                self.settings(settings)
                with self.assertRaises(ValueError):
                    PortableSession(self.root, Mock())

    def test_missing_trust_fails_even_when_the_users_host_key_store_exists(self):
        (self.data / "known_hosts").unlink()
        with self.assertRaisesRegex(FileNotFoundError, "known_hosts"):
            PortableSession(self.root, Mock()).validate(ecb_login.GATEWAY)

    def test_unrelated_host_keys_cannot_authorize_the_gateway(self):
        (self.data / "known_hosts").write_bytes(b"other.example " + self.key.export_public_key())
        with self.assertRaisesRegex(ValueError, "verified SSH key"):
            PortableSession(self.root, Mock()).validate(ecb_login.GATEWAY)

    def test_viewer_profile_cannot_override_password_or_tunnel(self):
        session = PortableSession(self.root, Mock())
        profile = self.data / "viewer.vnc"
        for setting in ("PasswordFile=elsewhere", "Log=file:100", "ProxyServer=outside", "Host=outside:5"):
            profile.write_text("Host=127.0.0.1::5905\n" + setting + "\n", encoding="utf-8")
            with self.subTest(setting=setting), self.assertRaisesRegex(ValueError, "viewer.vnc"):
                session.viewer_profile(5905)
        profile.write_text("Host=127.0.0.1::5905\nFullScreen=1\n", encoding="utf-8")
        self.assertEqual(session.viewer_profile(5905), profile)

    def test_trust_export_keeps_gateway_revocations_and_excludes_other_hosts(self):
        source = self.root / "source_known_hosts"
        public_key = self.key.export_public_key()
        revoked = asyncssh.generate_private_key("ssh-ed25519").export_public_key()
        source.write_bytes(b"other.example " + public_key + ecb_login.GATEWAY.encode() + b" " + public_key
                           + b"@revoked " + ecb_login.GATEWAY.encode() + b" " + revoked)
        destination = self.data / "known_hosts"
        export_trust(source, destination)
        self.assertNotIn("other.example", destination.read_text())
        hosts = asyncssh.read_known_hosts(str(destination)).match(ecb_login.GATEWAY, "", 22)
        self.assertEqual(len(hosts[0]), 1)
        self.assertEqual(len(hosts[2]), 1)

    def test_check_does_not_unlock_the_vault_or_contact_the_school(self):
        prompt = Mock(side_effect=AssertionError("unexpected password prompt"))
        session = PortableSession(self.root, prompt)
        with patch("ecb_portable.run_cli", return_value=subprocess.CompletedProcess([], 0)), \
                patch("ecb_login.asyncssh.connect", side_effect=AssertionError("unexpected connection")):
            session.check(ecb_login.GATEWAY)
        prompt.assert_not_called()

    def test_preparing_a_folder_cannot_overwrite_an_existing_personal_vault(self):
        (self.root / "Connect-ECB.exe").touch()
        self.settings({"username": "fixture"})
        original = b"fixture personal data must survive"
        (self.data / "otp.kdbx").write_bytes(original)
        with patch("build_portable.import_personal_data") as migrate:
            with self.assertRaises(FileExistsError):
                prepare_existing(SimpleNamespace(output=self.root))
            migrate.assert_not_called()
        self.assertEqual((self.data / "otp.kdbx").read_bytes(), original)


class PortableCredentialTests(unittest.TestCase):
    def test_portable_login_uses_vault_and_never_windows_credentials(self):
        vault = Mock()
        vault.read_password.side_effect = ["fixture department", "fixture VNC"]
        vault.read_entry.return_value = "123456"
        client = ecb_login.LoginClient("fixture", None, portable=SimpleNamespace(vault=vault))
        with patch("ecb_login.read_password", side_effect=AssertionError("Windows read")), \
                patch("ecb_login.save_password", side_effect=AssertionError("Windows write")):
            self.assertEqual(client.password_auth_requested(), "fixture department")
            self.assertEqual(client.answer_once("verification code"), "123456")
            self.assertEqual(client.get_password(client.account_target("VNC"), "fixture", "unused"), "fixture VNC")
            client.auth_completed()
        vault.read_entry.assert_called_once_with(ecb_login.OTP_ENTRY, "--totp")

    def test_wrong_vault_unlock_stops_instead_of_prompting_for_another_password(self):
        vault = Mock()
        vault.read_password.side_effect = RuntimeError("Could not unlock the USB vault")
        client = ecb_login.LoginClient("fixture", None, portable=SimpleNamespace(vault=vault))
        with patch("ecb_login.read_secret") as prompt, self.assertRaisesRegex(RuntimeError, "unlock"):
            client.password_auth_requested()
        prompt.assert_not_called()

    def test_rejected_refresh_does_not_replace_the_saved_password(self):
        vault = Mock()
        client = ecb_login.LoginClient("fixture", None, refresh_passwords=True, portable=SimpleNamespace(vault=vault))
        with patch("ecb_login.read_secret", return_value="fixture replacement"):
            client.password_auth_requested()
        vault.save_password.assert_not_called()
        client.connection_lost(None)
        self.assertEqual(client.pending_passwords, {})
        vault.save_password.assert_not_called()

    def test_successful_refresh_saves_only_to_the_usb_vault(self):
        vault = Mock()
        client = ecb_login.LoginClient("fixture", None, refresh_passwords=True, portable=SimpleNamespace(vault=vault))
        with patch("ecb_login.read_secret", return_value="fixture replacement"), \
                patch("ecb_login.save_password", side_effect=AssertionError("Windows write")):
            client.password_auth_requested()
            client.auth_completed()
        vault.save_password.assert_called_once_with(client.account_target("SSH"), "fixture", "fixture replacement")


class PortableLifetimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_login_check_disconnects_without_starting_a_remote_desktop_or_viewer(self):
        session = SimpleNamespace(vault=Mock(), known_hosts=Path("USB/data/known_hosts"))
        context = AsyncMock()

        def connected_after_unlock(*args, **kwargs):
            session.vault.unlock.assert_called_once()
            return context

        with patch("ecb_login.asyncssh.connect", side_effect=connected_after_unlock), \
                patch("ecb_login.discover_vnc", AsyncMock()) as discover, \
                patch("ecb_login.open_realvnc", AsyncMock()) as viewer:
            await ecb_login.connect_vnc("fixture", 5905, portable=session, check_login=True)
        discover.assert_not_awaited()
        viewer.assert_not_awaited()
        context.__aexit__.assert_awaited_once()
        session.vault.clear.assert_called_once()

    async def test_failed_vault_unlock_does_not_start_ssh_authentication(self):
        session = SimpleNamespace(vault=Mock(), known_hosts=Path("USB/data/known_hosts"))
        session.vault.unlock.side_effect = RuntimeError("fixture wrong vault unlock")
        with patch("ecb_login.asyncssh.connect") as connect:
            with self.assertRaisesRegex(RuntimeError, "wrong vault unlock"):
                await ecb_login.connect_vnc("fixture", 5905, portable=session)
        connect.assert_not_called()
        session.vault.clear.assert_called_once()

    async def test_closing_viewer_closes_the_tunnel_and_clears_the_vault_unlock(self):
        vault = Mock()
        session = SimpleNamespace(vault=vault, known_hosts=Path("USB/data/known_hosts"))
        connection = AsyncMock()
        connection.forward_local_port.return_value = AsyncMock()

        async def never_closed():
            await asyncio.Event().wait()

        connection.wait_closed.side_effect = never_closed
        context = AsyncMock()
        context.__aenter__.return_value = connection
        with ExitStack() as fixtures:
            connect = fixtures.enter_context(patch("ecb_login.asyncssh.connect", return_value=context))
            fixtures.enter_context(patch("ecb_login.discover_vnc", AsyncMock(return_value=("fixture.example", 5990))))
            fixtures.enter_context(patch("ecb_login.open_realvnc", AsyncMock()))
            await asyncio.wait_for(ecb_login.connect_vnc("fixture", 5905, portable=session), 2)
        self.assertEqual(connect.call_args.kwargs["known_hosts"], str(session.known_hosts))
        self.assertEqual(connect.call_args.kwargs["client_keys"], [])
        connection.forward_local_port.return_value.__aexit__.assert_awaited_once()
        context.__aexit__.assert_awaited_once()
        vault.clear.assert_called_once()

    async def test_handshake_failure_still_clears_vault_memory(self):
        session = SimpleNamespace(vault=Mock(), known_hosts=Path("USB/data/known_hosts"))
        context = AsyncMock()
        context.__aenter__.side_effect = asyncssh.PermissionDenied("fixture failure")
        with patch("ecb_login.asyncssh.connect", return_value=context):
            with self.assertRaises(asyncssh.PermissionDenied):
                await ecb_login.connect_vnc("fixture", 5905, portable=session)
        session.vault.clear.assert_called_once()


class PortableViewerTests(unittest.IsolatedAsyncioTestCase):
    async def launch(self, *, password_pipe_works):
        vault = Mock()
        vault.read_password.return_value = "Fixture!"
        temporary = tempfile.TemporaryDirectory(prefix="USB's folder ")
        self.addCleanup(temporary.cleanup)
        viewer = Path(temporary.name) / "tools" / "RealVNC" / "vncviewer.exe"
        viewer.parent.mkdir(parents=True)
        viewer.touch()
        session = SimpleNamespace(vault=vault, viewer=viewer,
                                  viewer_profile=Mock(return_value=None))
        client = ecb_login.LoginClient("fixture", None, portable=session)
        process = Mock(pid=1234, returncode=0)
        process.wait = AsyncMock()
        process.stderr = asyncio.StreamReader()
        process.stderr.feed_data(b"vncviewer[1234]: CConnection: Authentication successful\n")
        process.stderr.feed_eof()
        with ExitStack() as fixtures:
            launch = fixtures.enter_context(patch("ecb_login.asyncio.create_subprocess_exec", AsyncMock(return_value=process)))
            fixtures.enter_context(patch("ecb_login.find_viewer_profile", side_effect=AssertionError("host profile lookup")))
            manual = fixtures.enter_context(patch("ecb_login.os.startfile", side_effect=AssertionError("host address book")))
            fixtures.enter_context(patch.dict(os.environ, {}, clear=True))
            fixtures.enter_context(patch("ecb_login.password_pipe", return_value=nullcontext(("fixture pipe", object()))))
            deliver = fixtures.enter_context(patch("ecb_login.deliver_password", AsyncMock()))
            if not password_pipe_works:
                fixtures.enter_context(patch("ecb_login.encode_vnc_password", side_effect=ValueError("fixture unsupported encoding")))
            await ecb_login.open_realvnc(5905, client)
        args = launch.await_args.args
        self.assertEqual(args[0], session.viewer)
        self.assertIn("-UseAddressBook=0", args)
        self.assertNotIn("Fixture!", repr(launch.await_args))
        manual.assert_not_called()
        process.wait.assert_awaited_once()
        return args, deliver

    async def test_portable_viewer_uses_usb_path_and_private_pipe(self):
        args, deliver = await self.launch(password_pipe_works=True)
        self.assertIn("-PasswordFile=fixture pipe", args)
        deliver.assert_awaited_once()

    async def test_manual_password_fallback_still_uses_usb_viewer_without_host_address_book(self):
        args, deliver = await self.launch(password_pipe_works=False)
        self.assertFalse(any(str(arg).startswith("-PasswordFile=") for arg in args))
        deliver.assert_not_awaited()


@unittest.skipUnless(os.name == "nt" and CLI.is_file(), "requires a local KeePassXC CLI for native vault integration")
class NativeVaultTests(unittest.TestCase):
    def test_encrypted_password_round_trip_refresh_and_one_unlock(self):
        with tempfile.TemporaryDirectory(prefix="ECB USB's ") as directory:
            database = Path(directory) / "fixture.kdbx"
            master = "synthetic fixture master"
            result = run_cli(CLI, ["db-create", "--quiet", "--set-password", "-t", "100", "--", database], _input_line(master) * 2)
            self.assertEqual(result.returncode, 0)
            prompt = Mock(return_value=master)
            vault = PortableVault(CLI, database, prompt)
            client = ecb_login.LoginClient("fixture", None)
            target = client.account_target("SSH")
            self.assertIsNone(vault.read_password(target))
            vault.save_password(target, "fixture", "synthetic department")
            self.assertEqual(vault.read_password(target), "synthetic department")
            vault.save_password(target, "fixture", "synthetic replacement")
            self.assertEqual(vault.read_password(target), "synthetic replacement")
            other = ecb_login.LoginClient("Fixture", None).account_target("SSH")
            self.assertIsNone(vault.read_password(other))
            vault.save_password(client.account_target("VNC"), "fixture", "synthetic VNC")
            self.assertEqual(vault.read_password(client.account_target("VNC")), "synthetic VNC")
            prompt.assert_called_once()
            self.assertNotIn(b"synthetic replacement", database.read_bytes())
            vault.clear()
            self.assertIsNone(vault._password)
            wrong = PortableVault(CLI, database, Mock(return_value="incorrect fixture password"))
            with self.assertRaisesRegex(RuntimeError, "Could not unlock") as caught:
                wrong.read_password(target)
            self.assertNotIn("incorrect fixture password", str(caught.exception))
            self.assertIsNone(wrong._password)


if __name__ == "__main__":
    unittest.main()
