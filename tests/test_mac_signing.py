"""An update must keep the developer identity macOS granted permissions to."""

import pathlib
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import mac_signing


DEV = ("1" * 40, "Developer ID Application: Example (TEAMONE)")
OTHER = ("2" * 40, "Developer ID Application: Other (TEAMTWO)")
DEBUG = ("3" * 40, "Apple Development: Example (TEAMONE)")
SIGNED = ('Authority=Developer ID Application: Example (TEAMONE)\n'
          'TeamIdentifier=TEAMONE\n'
          'designated => identifier "io.github.yusufipk.dikte" and anchor apple generic\n')
ADHOC = 'Signature=adhoc\nTeamIdentifier=not set\n# designated => cdhash H"1234"\n'


class SigningIdentity(unittest.TestCase):
    def test_distribution_identity_is_preferred_over_development(self):
        self.assertEqual(mac_signing.select_identity([DEBUG, DEV], ADHOC), DEV[0])

    def test_existing_team_and_certificate_kind_are_preserved(self):
        self.assertEqual(mac_signing.select_identity([OTHER, DEBUG, DEV], SIGNED), DEV[0])

    def test_an_unavailable_certificate_does_not_downgrade_to_adhoc(self):
        with self.assertRaisesRegex(mac_signing.SigningError, "identity"):
            mac_signing.select_identity([], SIGNED)

    def test_an_explicit_different_team_is_refused(self):
        with self.assertRaises(mac_signing.SigningError):
            mac_signing.select_identity([DEV, OTHER], SIGNED, OTHER[0])

    def test_multiple_distribution_teams_require_an_explicit_choice(self):
        with self.assertRaisesRegex(mac_signing.SigningError, "DIKTE_SIGN_IDENTITY"):
            mac_signing.select_identity([DEV, OTHER], ADHOC)

    def test_explicit_identity_can_select_a_fresh_install(self):
        self.assertEqual(mac_signing.select_identity([DEV, OTHER], "", DEV[1]), DEV[0])

    def test_unsigned_local_installs_remain_possible_without_a_certificate(self):
        self.assertEqual(mac_signing.select_identity([], ADHOC), "-")

    def test_adhoc_hash_is_not_a_requirement_for_the_migration(self):
        self.assertIsNone(mac_signing.designated_requirement(ADHOC))
        self.assertEqual(mac_signing.designated_requirement(SIGNED),
                         'identifier "io.github.yusufipk.dikte" and anchor apple generic')


class Publishing(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.app = self.root / "Dikte.app"
        self.stage = self.root / "stage" / "Dikte.app"
        for app, text in ((self.app, "old"), (self.stage, "new")):
            app.mkdir(parents=True)
            (app / "version").write_text(text)

    def test_the_old_bundle_is_kept_as_a_rollback_copy(self):
        mac_signing.publish(self.stage, self.app)
        self.assertEqual((self.app / "version").read_text(), "new")
        self.assertEqual((self.stage.parent / "previous.app/version").read_text(), "old")

    def test_a_failed_replacement_restores_the_old_bundle(self):
        real_replace = mac_signing.os.replace

        def replace(source, target):
            if pathlib.Path(source) == self.stage:
                raise OSError("replacement failed")
            return real_replace(source, target)

        with mock.patch.object(mac_signing.os, "replace", side_effect=replace):
            with self.assertRaises(OSError):
                mac_signing.publish(self.stage, self.app)
        self.assertEqual((self.app / "version").read_text(), "old")


class SignatureVerification(unittest.TestCase):
    def test_a_new_build_must_satisfy_the_previous_designated_requirement(self):
        plan = {"identity": DEV[0], "requirement": 'identifier "previous"'}
        with mock.patch.object(mac_signing, "run", return_value=SIGNED) as run:
            mac_signing.sign(pathlib.Path("Dikte.app"), plan)
        self.assertIn(mock.call("codesign", "--verify", "--strict", "-R",
                                "=" + plan["requirement"], "Dikte.app"), run.call_args_list)

    def test_a_failed_signature_is_never_published(self):
        plan = {"identity": DEV[0], "requirement": None}
        with mock.patch.object(mac_signing, "run", side_effect=mac_signing.SigningError("denied")):
            with self.assertRaises(mac_signing.SigningError):
                mac_signing.sign(pathlib.Path("Dikte.app"), plan)


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("DIKTE_TEST_NATIVE_SIGNING") == "1",
                     "requires opt-in to use the local signing certificate")
class NativeSigning(unittest.TestCase):
    def setUp(self):
        # tests/__init__.py isolates HOME. Only this explicitly enabled test
        # needs the real user's Keychain; bundles still live in a temp folder.
        import pwd
        self.enterContext(mock.patch.dict(os.environ, {
            "HOME": pwd.getpwuid(os.getuid()).pw_dir,
        }))

    def test_two_different_releases_have_the_same_secure_identity(self):
        with tempfile.TemporaryDirectory(prefix="dikte-signing-test-") as directory:
            root = pathlib.Path(directory)
            app = root / "Dikte.app"
            (app / "Contents/MacOS").mkdir(parents=True)
            (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": mac_signing.BUNDLE_ID,
                "CFBundleExecutable": "Dikte", "CFBundlePackageType": "APPL",
            }))
            binary = app / "Contents/MacOS/Dikte"
            source = root / "main.c"

            def build(version):
                source.write_text(f"int main(void) {{ return {version}; }}\n")
                subprocess.run(["xcrun", "clang", str(source), "-o", str(binary)],
                               check=True, capture_output=True)

            build(1)
            # A first install has no existing requirement to preserve.
            plan = mac_signing.prepare(root / "not-installed.app")
            self.assertNotEqual(plan["identity"], "-", "a signing certificate is needed")
            mac_signing.sign(app, plan)
            first = mac_signing.run("codesign", "-d", "--verbose=4", "-r-", str(app))
            next_plan = mac_signing.prepare(app)
            self.assertTrue(next_plan["requirement"])
            build(2)
            mac_signing.sign(app, next_plan)
            second = mac_signing.run("codesign", "-d", "--verbose=4", "-r-", str(app))
            self.assertEqual(mac_signing.designated_requirement(first),
                             mac_signing.designated_requirement(second))
            hashes = [next(line for line in details.splitlines() if line.startswith("CDHash="))
                      for details in (first, second)]
            self.assertNotEqual(*hashes)


if __name__ == "__main__":
    unittest.main()
