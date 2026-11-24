import sys
import unittest
from unittest.mock import patch

import vnc_password
from vnc_password import deliver_password, encode_vnc_password, password_pipe


class PasswordFileTests(unittest.TestCase):
    def test_classic_vnc_password_file_and_eight_byte_limit(self):
        expected = bytes.fromhex("dbd83cfd727a1458")
        self.assertEqual(encode_vnc_password("password"), expected)
        self.assertEqual(encode_vnc_password("password with a suffix"), expected)

    def test_unsupported_input_raises_a_secret_free_error(self):
        for password in ("", "bad\0input", "\ud800"):
            with self.subTest():
                with self.assertRaises(ValueError) as caught:
                    encode_vnc_password(password)
                if password:
                    self.assertNotIn(password, str(caught.exception))

    @unittest.skipUnless(sys.platform == "win32", "requires a Windows ANSI code page")
    def test_accented_password_uses_viewers_windows_encoding(self):
        if "\u00e9".encode("mbcs", errors="replace") != b"\xe9":
            self.skipTest("fixture uses a Western European ANSI code page")
        expected = bytes.fromhex("8b5230d6676c6489")
        self.assertEqual(encode_vnc_password("caf\u00e9123"), expected)
        self.assertEqual(encode_vnc_password("caf\u00e9123suffix"), expected)


@unittest.skipUnless(sys.platform == "win32", "requires a Windows named pipe")
class PasswordPipeTests(unittest.IsolatedAsyncioTestCase):
    async def test_other_reader_does_not_receive_password(self):
        with (
            patch.object(vnc_password.win32pipe, "ConnectNamedPipe"),
            patch.object(vnc_password.win32pipe, "GetNamedPipeClientProcessId", return_value=200),
            patch.object(vnc_password.win32file, "WriteFile") as write,
        ):
            with self.assertRaisesRegex(OSError, "different process"):
                await deliver_password(object(), encode_vnc_password("fixture"), viewer_pid=100)
        write.assert_not_called()

    async def test_timeout_removes_unread_pipe(self):
        with self.assertRaises(TimeoutError):
            with password_pipe() as (path, handle):
                await deliver_password(handle, encode_vnc_password("fixture"), viewer_pid=1, timeout=0)
        with self.assertRaises(FileNotFoundError):
            with open(path, "rb"):
                self.fail("The pipe still accepts readers after timeout.")
