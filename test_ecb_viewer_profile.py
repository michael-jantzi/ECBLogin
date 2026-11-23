import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ecb_viewer_profile import find_viewer_profile


class ViewerProfileTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        env = patch.dict(os.environ, {"APPDATA": temp.name})
        env.start()
        self.addCleanup(env.stop)
        self.store = Path(temp.name) / "RealVNC" / "ViewerStore"
        self.store.mkdir(parents=True)
        self.profile = self.store / "school pc.vnc"

    def test_recognizes_saved_host_and_display_forms(self):
        for host in ("127.0.0.1:5905", "127.0.0.1::5905", "localhost:5", ":5"):
            for encoding in ("utf-8-sig", "utf-16"):
                with self.subTest(host=host, encoding=encoding):
                    self.profile.write_text(
                        f"Host={host}\nFriendlyName=School PC\nCredentialStore=Windows\n",
                        encoding=encoding,
                    )
                    self.assertEqual(find_viewer_profile(5905), self.profile)
                    self.assertIsNone(find_viewer_profile(5))

    def test_skips_unrelated_and_malformed_profiles(self):
        (self.store / "outside.vnc").write_text("Host=assigned.example:5\n", encoding="utf-8")
        (self.store / "twice.vnc").write_text("Host=127.0.0.1::5\nhost=elsewhere\n", encoding="utf-8")
        (self.store / "broken.vnc").write_bytes(b"Host=127.0.0.1::5\n\xff")
        self.profile.write_text("Host=127.0.0.1::5\n", encoding="utf-8")
        self.assertEqual(find_viewer_profile(5), self.profile)
        self.assertIsNone(find_viewer_profile(5905))

    def test_profiles_cannot_override_login_logging_or_tunnel_destination(self):
        for override in (
            "PasswordFile=", "Passwd=other", "password=other", "EncryptedPassword=other",
            "Log=other", "LogToAddressBook=1", "UseAddressBook=1", "ProxyServer=socks://proxy",
            "ProxyAutoConfig=http://proxy/pac", "Config=other.vnc", "URI=vnc://elsewhere", "Via=gateway",
        ):
            with self.subTest(setting=override.partition("=")[0]):
                self.profile.write_text(f"Host=127.0.0.1::5905\n{override}\n", encoding="utf-8")
                self.assertIsNone(find_viewer_profile(5905))

    def test_ambiguous_profiles_do_not_select_one_arbitrarily(self):
        self.profile.write_text("Host=127.0.0.1:5905\n", encoding="utf-8")
        (self.store / "second.vnc").write_text("Host=localhost:5\n", encoding="utf-8")
        self.assertIsNone(find_viewer_profile(5905))
