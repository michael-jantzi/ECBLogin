import asyncio
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import ecb_login


class SavedPasswordTests(unittest.TestCase):
    def setUp(self):
        fixtures = ExitStack()
        self.addCleanup(fixtures.close)
        root = Path(fixtures.enter_context(tempfile.TemporaryDirectory()))
        self.cli = root / "KeePassXC" / "keepassxc-cli.exe"
        self.database = root / "ECB" / "otp.kdbx"
        for path in (self.cli, self.database):
            path.parent.mkdir()
            path.touch()
        fixtures.enter_context(patch.dict(os.environ, {"ProgramFiles": str(root), "LOCALAPPDATA": str(root)}))

        self.saved = {}
        fixtures.enter_context(patch.object(ecb_login, "read_password", side_effect=self.load))
        fixtures.enter_context(patch.object(ecb_login, "save_password", side_effect=self.save))
        self.prompt = fixtures.enter_context(patch.object(ecb_login, "read_secret"))
        fixtures.enter_context(patch.object(ecb_login.subprocess, "run", side_effect=self.keepass))
        self.codes = iter(["123456", "234567", "345678", "456789"])
        self.unlock = "fixture vault password"

    def load(self, target):
        return self.saved.get(target.casefold())

    def save(self, target, username, password):
        self.saved[target.casefold()] = password

    def keepass(self, args, *, input, **kwargs):
        self.assertEqual(Path(args[0]), self.cli)
        self.assertEqual(Path(args[-2]), self.database)
        if input != (self.unlock + "\n").encode():
            return subprocess.CompletedProcess(args, 1, stdout=b"")
        if "--totp" in args:
            self.assertEqual(args[-1], ecb_login.OTP_ENTRY)
            value = next(self.codes)
        else:
            self.assertIn("--attributes", args)
            self.assertEqual(args[args.index("--attributes") + 1], "Password")
            self.assertEqual(args[-1], "Department Login")
            value = "password from vault"
        return subprocess.CompletedProcess(args, 0, stdout=(value + "\r\n").encode())

    def challenge(self, client, prompt):
        return client.kbdint_challenge_received("", "", "", [(prompt, False)])[0]

    def login(self, username, password, code, *, password_entry=None, refresh_passwords=False):
        client = ecb_login.LoginClient(username, password_entry, refresh_passwords=refresh_passwords)
        self.assertEqual(self.challenge(client, "Password:"), password)
        self.assertEqual(self.challenge(client, "Verification code:"), code)
        return client

    def test_success_saves_both_passwords_and_next_login_generates_a_fresh_code(self):
        self.prompt.side_effect = ["department password", self.unlock]
        first = self.login("fixture", "department password", "123456")
        self.assertEqual(self.saved, {})
        first.auth_completed()
        self.assertCountEqual(self.saved.values(), ["department password", self.unlock])

        self.prompt.side_effect = AssertionError("Unexpected prompt on repeat login")
        self.login("fixture", "department password", "234567").auth_completed()
        self.assertCountEqual(self.saved.values(), ["department password", self.unlock])

    def test_failed_refresh_preserves_both_passwords_until_a_successful_refresh(self):
        self.prompt.side_effect = ["old department password", self.unlock]
        self.login("fixture", "old department password", "123456").auth_completed()
        previous = self.saved.copy()

        self.unlock = "new vault password"
        self.prompt.side_effect = ["mistyped department password", "mistyped vault password"]
        rejected = ecb_login.LoginClient("fixture", None, refresh_passwords=True)
        self.assertEqual(self.challenge(rejected, "Password:"), "mistyped department password")
        with self.assertRaisesRegex(RuntimeError, "KeePassXC"):
            self.challenge(rejected, "Verification code:")
        self.assertEqual(self.saved, previous)

        self.prompt.side_effect = ["new department password", self.unlock]
        refreshed = self.login("fixture", "new department password", "234567", refresh_passwords=True)
        self.assertEqual(self.saved, previous)
        refreshed.auth_completed()
        self.assertEqual(self.saved.keys(), previous.keys())
        self.assertCountEqual(self.saved.values(), ["new department password", self.unlock])

    def test_password_entry_only_saves_the_vault_password(self):
        self.prompt.side_effect = [self.unlock]
        for code in ("123456", "234567"):
            self.login("fixture", "password from vault", code, password_entry="Department Login").auth_completed()
        self.assertEqual(self.prompt.call_count, 1)
        self.assertEqual(list(self.saved.values()), [self.unlock])

    def test_usernames_have_their_own_department_password_and_share_the_vault_unlock(self):
        self.prompt.side_effect = ["alice password", self.unlock, "uppercase password"]
        self.login("alice", "alice password", "123456").auth_completed()
        self.login("Alice", "uppercase password", "234567").auth_completed()
        self.assertCountEqual(self.saved.values(), ["alice password", "uppercase password", self.unlock])
        self.login("alice", "alice password", "345678").auth_completed()
        self.login("Alice", "uppercase password", "456789").auth_completed()
        self.assertEqual(self.prompt.call_count, 3)

    def test_host_waits_for_a_new_code_after_refresh_without_another_password_prompt(self):
        self.prompt.side_effect = ["old department password", self.unlock]
        self.login("fixture", "old department password", "123456").auth_completed()
        self.prompt.reset_mock()
        self.unlock = "new vault password"
        self.prompt.side_effect = ["new department password", self.unlock]
        self.codes = iter(["234567", "234567", "345678"])

        client = self.login("fixture", "new department password", "234567", refresh_passwords=True)
        client.auth_completed()
        with patch.object(ecb_login.asyncio, "sleep") as rollover:
            self.assertEqual(asyncio.run(client.host_verification_code()), "345678")
        rollover.assert_awaited_once()
        self.assertEqual(self.prompt.call_count, 2)
        self.assertCountEqual(self.saved.values(), ["new department password", self.unlock])

        client.connection_lost(None)
        for secret in ("new department password", self.unlock, "234567", "345678"):
            self.assertNotIn(secret, vars(client).values())
        self.assertEqual(client.pending_passwords, {})

    def test_host_uses_an_already_changed_code_immediately(self):
        self.prompt.side_effect = ["department password", self.unlock]
        client = self.login("fixture", "department password", "123456")
        client.auth_completed()
        with patch.object(ecb_login.asyncio, "sleep") as rollover:
            self.assertEqual(asyncio.run(client.host_verification_code()), "234567")
        rollover.assert_not_awaited()
        self.assertCountEqual(self.saved.values(), ["department password", self.unlock])

    def test_lab_login_retry_waits_for_a_code_unused_by_either_ssh_login(self):
        self.codes = iter(["123456", "234567", "234567", "123456", "345678"])
        self.prompt.side_effect = ["department password", self.unlock]
        client = self.login("fixture", "department password", "123456")
        client.auth_completed()
        self.assertEqual(asyncio.run(client.host_verification_code()), "234567")
        with patch.object(ecb_login.asyncio, "sleep") as rollover:
            self.assertEqual(asyncio.run(client.host_verification_code()), "345678")
        self.assertEqual(rollover.await_count, 2)
        self.assertEqual(self.prompt.call_count, 2)

    def test_disconnect_while_waiting_for_rollover_stops_vault_access(self):
        self.codes = iter(["123456", "123456"])
        self.prompt.side_effect = ["department password", self.unlock]
        client = self.login("fixture", "department password", "123456", refresh_passwords=True)
        client.auth_completed()
        with patch.object(ecb_login.asyncio, "sleep", side_effect=lambda _: client.connection_lost(None)):
            with self.assertRaisesRegex(RuntimeError, "SSH connection closed"):
                asyncio.run(client.host_verification_code())
        self.assertEqual(self.prompt.call_count, 2)

    def test_invalid_host_code_fails_without_revealing_or_saving_it(self):
        invalid = "private invalid fixture code"
        self.codes = iter(["123456", invalid])
        self.prompt.side_effect = ["department password", self.unlock]
        client = self.login("fixture", "department password", "123456")
        client.auth_completed()
        with self.assertRaises(RuntimeError) as error:
            asyncio.run(client.host_verification_code())
        for secret in (invalid, "123456", "department password", self.unlock):
            self.assertNotIn(secret, str(error.exception))
        self.assertCountEqual(self.saved.values(), ["department password", self.unlock])

    def test_disconnect_during_authentication_discards_pending_passwords_and_code(self):
        self.prompt.side_effect = ["department password", self.unlock]
        client = self.login("fixture", "department password", "123456")
        client.connection_lost(ConnectionError("fixture disconnected"))
        self.assertIsNone(client.database_password)
        self.assertIsNone(client.department_password)
        self.assertNotIn("123456", vars(client).values())
        self.assertEqual(client.pending_passwords, {})
        self.assertEqual(client.used_verification_codes, set())
        self.assertEqual(self.saved, {})
