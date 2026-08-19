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
                "gpu": False,
                "enabled": True,
            },
            {
                "id": "dev-ssh.wetigu.com",
                "name": "dev-ssh",
                "web_hostname": "dev-ssh.wetigu.com",
                "ssh_mode": "direct",
                "ssh_hostname": "dev.wetigu.com",
                "gpu": True,
                "enabled": True,
            },
            {
                "id": "legacy.example.com",
                "web_hostname": "legacy.example.com/path",
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
        auth.SSH_CONFIG_SYNC_SIGNATURE = ""
        with auth.SERVER_REPO_LOCK:
            auth.SERVER_REPO_CACHE.update({"expires": 0.0, "servers": [], "error": ""})

    def test_catalog_validation_and_public_metadata(self):
        servers = auth.validate_server_repository(repository_document())
        self.assertEqual(
            [server["id"] for server in servers],
            ["minipc2.micstec.com", "dev-ssh.wetigu.com", "legacy.example.com"],
        )
        self.assertEqual(servers[2]["ssh_mode"], "tunnel")
        self.assertEqual(servers[2]["web_hostname"], "")
        public = auth.public_server_catalog(servers)
        self.assertEqual(public[0]["ssh_hostname"], "ssh-minipc2.micstec.com")
        self.assertEqual(public[0]["web_hostname"], "minipc2.micstec.com")
        self.assertEqual(public[1]["ssh_mode"], "direct")
        self.assertEqual(public[1]["ssh_hostname"], "dev.wetigu.com")
        self.assertFalse(public[0]["gpu"])
        self.assertTrue(public[1]["gpu"])
        self.assertFalse(public[2]["gpu"])

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
        ), mock.patch.object(auth, "SERVER_REPO_CONFIG", __file__), mock.patch.object(auth.subprocess, "run", fake_run):
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

    def test_missing_config_hides_servers_even_with_environment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = os.path.join(temp_dir, "missing.conf")
            with mock.patch.object(auth, "SERVER_REPO_CONFIG", missing), mock.patch.object(
                auth,
                "server_repo_settings",
                return_value=(auth.DEFAULT_SERVER_REPO_URL, "test-passcode"),
            ), mock.patch.dict(
                os.environ,
                {"WEBTERMINAL_SERVER_REPO_PASSCODE": "test-passcode"},
            ):
                with auth.SERVER_REPO_LOCK:
                    auth.SERVER_REPO_CACHE.update({"expires": 9999999999, "servers": [{"id": "cached"}], "error": ""})
                servers, error, configured = auth.load_server_catalog()
        self.assertEqual(servers, [])
        self.assertIn("remote setup", error)
        self.assertFalse(configured)

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

    def test_commands_repository_url_is_a_sibling_and_preserves_query(self):
        with mock.patch.dict(os.environ, {"WEBTERMINAL_COMMANDS_REPO_URL": ""}):
            self.assertEqual(
                auth._commands_repo_url(
                    "https://files.example.com/s/servers/serverlist.json?token=abc"
                ),
                "https://files.example.com/s/servers/commands.json?token=abc",
            )
        with mock.patch.dict(
            os.environ,
            {"WEBTERMINAL_COMMANDS_REPO_URL": "https://other.example/s/shared"},
        ):
            self.assertEqual(
                auth._commands_repo_url("https://ignored.example/serverlist.json"),
                "https://other.example/s/shared/commands.json",
            )

    def test_quick_commands_sync_merges_and_writes_both_sides(self):
        remote_document = {
            "kind": "micsapp-webterminal-commands",
            "schema_version": 1,
            "revision": 3,
            "updated_at": "2026-08-12T00:00:00Z",
            "commands": [{
                "id": "aaaaaaaaaaaa",
                "name": "Status",
                "command": "old",
                "tags": "",
                "created": 1,
                "updated": 1,
            }],
        }
        local_commands = [{
            "id": "bbbbbbbbbbbb",
            "name": " status ",
            "command": "new",
            "tags": ["ops"],
            "created": 2,
            "updated": 2,
        }]
        uploaded = {}
        local_written = {}

        def fake_get(_url, _passcode, body_path, headers_path):
            pathlib.Path(body_path).write_text(json.dumps(remote_document), encoding="utf-8")
            pathlib.Path(headers_path).write_text('ETag: "rev-3"\n', encoding="utf-8")
            return '"rev-3"'

        def fake_put(_url, _passcode, etag, body_path):
            self.assertEqual(etag, '"rev-3"')
            uploaded.update(json.loads(pathlib.Path(body_path).read_text(encoding="utf-8")))
            return 204

        with mock.patch.object(auth, "commands_repo_settings", return_value=("https://example/commands.json", "pass")), mock.patch.object(
            auth, "_read_user_quick_commands", return_value=local_commands
        ), mock.patch.object(
            auth, "_write_user_quick_commands", side_effect=lambda _user, value: local_written.update({"commands": value})
        ), mock.patch.object(
            auth, "_curl_commands_get", side_effect=fake_get
        ), mock.patch.object(
            auth, "_curl_commands_put", side_effect=fake_put
        ):
            result = auth.sync_quick_commands("tester")

        self.assertEqual(result["deduplicated"], 1)
        self.assertEqual(result["revision"], 4)
        self.assertEqual(len(uploaded["commands"]), 1)
        self.assertEqual(uploaded["commands"][0]["id"], "aaaaaaaaaaaa")
        self.assertEqual(uploaded["commands"][0]["command"], "new")
        self.assertEqual(local_written["commands"], uploaded["commands"])

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

    def test_remote_window_uses_and_returns_the_browser_tab_name(self):
        server = auth.validate_server_repository(repository_document())[0]
        script = auth.build_remote_window_script(server, 4, name="Custom Shell 4")
        self.assertIn("Custom Shell 4", script)
        self.assertIn('"display-message", "-p", "-t", target', script)
        self.assertIn('"name": window_name', script)
        self.assertIn('"name": cfg["name"]', script)

    def test_ttyd_launcher_keeps_name_sync_out_of_terminal_startup(self):
        process = mock.Mock()
        popen = mock.Mock(return_value=process)
        username = "session-name-sync-test"
        auth.user_instances.pop(username, None)
        try:
            with mock.patch.object(auth, "allocate_port", return_value=7799), mock.patch.object(
                auth, "wait_for_ttyd_ready", return_value=True
            ), mock.patch.object(auth.subprocess, "Popen", popen):
                self.assertEqual(auth.spawn_user_ttyd(username, "password"), 7799)
        finally:
            auth.user_instances.pop(username, None)

        launcher = popen.call_args.args[0][-1]
        self.assertIn('RAW="$1"; case "$RAW"', launcher)
        self.assertIn("|| exec tmux new-session", launcher)
        self.assertNotIn('NAME="$2"', launcher)
        self.assertNotIn("rename-window", launcher)

    def test_catalog_sync_passes_only_tunnel_hosts_once(self):
        servers = auth.validate_server_repository(repository_document())
        fake_run = mock.Mock(
            return_value=types.SimpleNamespace(
                returncode=0,
                stdout=b"added 1: ssh-new.example.com\n",
                stderr=b"",
            )
        )
        with mock.patch.object(auth, "SERVER_REPO_HELPER", __file__), mock.patch.object(
            auth, "SSH_CONFIG_FILE", "/tmp/test-ssh-config"
        ), mock.patch.object(auth, "REMOTE_SSH_USER", "mli"), mock.patch.object(
            auth.subprocess, "run", fake_run
        ):
            self.assertEqual(auth.append_new_tunnel_ssh_hosts(servers), "")
            self.assertEqual(auth.append_new_tunnel_ssh_hosts(servers), "")

        fake_run.assert_called_once()
        payload = json.loads(fake_run.call_args.kwargs["input"])
        self.assertEqual(
            [server["ssh_hostname"] for server in payload["servers"]],
            ["ssh-minipc2.micstec.com", "ssh-legacy.example.com"],
        )

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
        self.assertIn("'Web Terminal'", auth.APP_HTML)
        self.assertIn("'SSH Session'", auth.APP_HTML)
        self.assertIn("function addRemoteWebTab(serverId)", auth.APP_HTML)
        self.assertIn("type: 'web'", auth.APP_HTML)
        self.assertIn("'https://' + server.web_hostname + '/'", auth.APP_HTML)
        self.assertIn("server.ssh_hostname", auth.APP_HTML)
        self.assertIn("function remoteServerLabel(server)", auth.APP_HTML)
        self.assertIn("' (gpu)'", auth.APP_HTML)
        self.assertIn("tabs.filter(isTerminalTab)", auth.APP_HTML)
        self.assertIn("serverId: t.serverId", auth.APP_HTML)
        self.assertNotIn("sshHostname: t.sshHostname", auth.APP_HTML)
        self.assertNotIn("webHostname: t.webHostname", auth.APP_HTML)

    def test_spa_reconciles_tab_names_with_tmux(self):
        self.assertNotIn("params.append('arg', (tab && tab.name) ? tab.name : '')", auth.APP_HTML)
        self.assertIn("#{automatic-rename}", auth.APP_HTML)
        self.assertIn("function reconcileSessionNames(sessions)", auth.APP_HTML)
        self.assertIn("if (live && !live.autoRename && live.name) tabObj.name = live.name", auth.APP_HTML)
        self.assertIn("reconcileSessionNames(sessions);\n  sessLast = sessions;", auth.APP_HTML)
        self.assertIn("data.exit_code !== 0", auth.APP_HTML)

    def test_installer_contains_session_name_sync_contract(self):
        installer = pathlib.Path(auth.__file__).with_name("cf_tunnel_install.sh").read_text(encoding="utf-8")
        for fragment in (
            "function reconcileSessionNames(sessions)",
            'RAW="$1"; case "$RAW"',
            "|| exec tmux new-session",
            "def build_remote_window_script(server, slot, name=None):",
        ):
            self.assertIn(fragment, installer)
        self.assertNotIn('NAME="$2"', installer)

    def test_trusted_origins_can_embed_web_terminal_html(self):
        headers = auth.HTML_ONLY_SECURITY_HEADERS
        self.assertNotIn("X-Frame-Options", headers)
        csp = headers["Content-Security-Policy"]
        self.assertIn("frame-src 'self' https://*.micstec.com https://*.wetigu.com", csp)
        self.assertIn("frame-ancestors 'self' https://*.micstec.com https://*.wetigu.com", csp)


if __name__ == "__main__":
    unittest.main()
