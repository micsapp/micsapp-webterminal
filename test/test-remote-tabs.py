#!/usr/bin/env python3
"""Focused tests for the protected remote-server catalog and tab launcher."""

import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import auth  # noqa: E402


def repository_document():
    return {
        "kind": "micsapp-webterminal-server-list",
        "schema_version": 2,
        "revision": 8,
        "servers": [
            {
                "id": "minipc2.micstec.com",
                "name": "minipc2",
                "web_hostname": "minipc2.micstec.com",
                "ssh_mode": "tunnel",
                "ssh_hostname": "ssh-minipc2.micstec.com",
                "enabled": True,
            },
            {
                "id": "dev-ssh.wetigu.com",
                "name": "dev-ssh",
                "web_hostname": "dev-ssh.wetigu.com",
                "ssh_mode": "direct",
                "ssh_hostname": "dev.wetigu.com",
                "enabled": True,
            },
            {
                "id": "legacy.example.com",
                "ssh_hostname": "ssh-legacy.example.com",
                "enabled": True,
            },
            {
                "id": "web-only.example.com",
                "ssh_mode": "none",
                "enabled": True,
            },
            {
                "id": "disabled.example.com",
                "ssh_mode": "direct",
                "ssh_hostname": "disabled.example.com",
                "enabled": False,
            },
            {
                "id": "bad id",
                "ssh_mode": "direct",
                "ssh_hostname": "example.com",
                "enabled": True,
            },
        ],
    }


class RemoteTabTests(unittest.TestCase):
    def setUp(self):
        with auth.SERVER_REPO_LOCK:
            auth.SERVER_REPO_CACHE.update({"expires": 0.0, "servers": [], "error": ""})

    def test_catalog_validation_and_public_metadata(self):
        servers = auth.validate_server_repository(repository_document())
        self.assertEqual(
            [server["id"] for server in servers],
            ["minipc2.micstec.com", "dev-ssh.wetigu.com", "legacy.example.com"],
        )
        self.assertEqual(servers[2]["ssh_mode"], "tunnel")
        public = auth.public_server_catalog(servers)
        self.assertNotIn("ssh_hostname", public[0])
        self.assertEqual(public[1]["ssh_mode"], "direct")

    def test_protected_fetch_is_cached(self):
        payload = json.dumps(repository_document()).encode()
        fake_run = mock.Mock(
            return_value=types.SimpleNamespace(
                returncode=0,
                stdout=payload,
                stderr=b"",
            )
        )
        with mock.patch.object(
            auth,
            "server_repo_settings",
            return_value=(auth.DEFAULT_SERVER_REPO_URL, "test-passcode"),
        ), mock.patch.object(auth.subprocess, "run", fake_run):
            first, error, configured = auth.load_server_catalog()
            second, second_error, _configured = auth.load_server_catalog()

        self.assertTrue(configured)
        self.assertFalse(error)
        self.assertFalse(second_error)
        self.assertEqual(first, second)
        fake_run.assert_called_once()
        command = fake_run.call_args.args[0]
        self.assertIn("@-", command)
        self.assertNotIn("test-passcode", " ".join(command))
        self.assertEqual(
            fake_run.call_args.kwargs["input"],
            b"X-Droppy-Share-Passcode: test-passcode\n",
        )

    def test_settings_file_supplies_passcode_without_hardcoding(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = os.path.join(temp_dir, "server-repo.conf")
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("https://files.example.com/s/servers\nsecret-value\n")
            with mock.patch.object(auth, "SERVER_REPO_CONFIG", config), mock.patch.dict(
                os.environ,
                {
                    "WEBTERMINAL_SERVER_REPO_URL": "",
                    "WEBTERMINAL_SERVER_REPO_PASSCODE": "",
                },
            ):
                url, passcode = auth.server_repo_settings()
        self.assertEqual(url, "https://files.example.com/s/servers/serverlist.json")
        self.assertEqual(passcode, "secret-value")

    def test_remote_window_scripts_preserve_host_key_checks(self):
        servers = auth.validate_server_repository(repository_document())
        tunnel_script = auth.build_remote_window_script(servers[0], 4)
        direct_script = auth.build_remote_window_script(servers[1], 5)
        self.assertIn("ProxyCommand=", tunnel_script)
        self.assertIn("ssh-minipc2.micstec.com", tunnel_script)
        self.assertNotIn("ProxyCommand=", direct_script)
        self.assertIn("dev.wetigu.com", direct_script)
        self.assertNotIn("StrictHostKeyChecking=no", tunnel_script)
        self.assertNotIn("StrictHostKeyChecking=no", direct_script)

    def test_nginx_exposes_remote_tab_api(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        for relative_path in ("nginx/ttyd.conf", "cf_tunnel_install.sh"):
            content = (root / relative_path).read_text(encoding="utf-8")
            self.assertIn("location = /api/servers", content)
            self.assertIn("location = /api/remote-tab", content)

    def test_spa_contains_remote_picker_and_safe_saved_state(self):
        self.assertIn('id="remoteTabMenu"', auth.APP_HTML)
        self.assertIn("/api/servers", auth.APP_HTML)
        self.assertIn("/api/remote-tab", auth.APP_HTML)
        self.assertIn("serverId: t.serverId", auth.APP_HTML)
        self.assertNotIn("sshHostname: t.sshHostname", auth.APP_HTML)


if __name__ == "__main__":
    unittest.main()
