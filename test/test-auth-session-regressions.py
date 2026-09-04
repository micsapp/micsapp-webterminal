#!/usr/bin/env python3
"""Regression tests for auth restart/session behavior."""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
AUTH_PY = REPO / "auth.py"
INSTALLER = REPO / "cf_tunnel_install.sh"


class AuthSessionRegressionTests(unittest.TestCase):
    def _load_secret(self, secret_file, explicit_secret=None):
        env = os.environ.copy()
        env["TTYD_SECRET_FILE"] = str(secret_file)
        if explicit_secret is None:
            env.pop("TTYD_SECRET", None)
        else:
            env["TTYD_SECRET"] = explicit_secret
        result = subprocess.run(
            [sys.executable, "-c", "import auth; print(auth.SECRET_KEY)"],
            cwd=REPO,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip().splitlines()[-1]

    def test_generated_secret_survives_process_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret_file = Path(tmp) / "session-secret"
            first = self._load_secret(secret_file)
            second = self._load_secret(secret_file)

            self.assertEqual(first, second)
            self.assertRegex(first, r"^[0-9a-f]{64}$")
            self.assertEqual(stat.S_IMODE(secret_file.stat().st_mode), 0o600)

    def test_explicit_secret_takes_precedence_without_creating_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret_file = Path(tmp) / "session-secret"
            value = self._load_secret(secret_file, "configured-test-secret")

            self.assertEqual(value, "configured-test-secret")
            self.assertFalse(secret_file.exists())

    def test_embedded_login_refreshes_same_origin_parent(self):
        source = AUTH_PY.read_text(encoding="utf-8")

        self.assertIn("window.parent.location.origin === window.location.origin", source)
        self.assertIn("window.parent.location.replace('/')", source)

    def test_installer_embeds_current_auth_source(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        marker = "auth.py\" <<'AUTHEOF'\n"
        embedded = installer.split(marker, 1)[1].split("\nAUTHEOF", 1)[0]

        self.assertEqual(AUTH_PY.read_text(encoding="utf-8").rstrip("\n"), embedded)

    def test_mobile_voice_latency_settings_remain_fast(self):
        source = AUTH_PY.read_text(encoding="utf-8")

        self.assertIn("now - session.lastLoudAt >= 900", source)
        self.assertIn("beam_size=1", source)
        self.assertIn("cpu_threads=min(8, os.cpu_count() or 1)", source)
        self.assertIn('VOICE_TRANSCRIPTION_MODEL", "base"', source)
        self.assertIn("target=preload_voice_transcription_model", source)


if __name__ == "__main__":
    unittest.main()
