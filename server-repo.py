#!/usr/bin/env python3
"""Validate, display, and update the shared web-terminal server list."""

from __future__ import annotations

import argparse
import fcntl
import getpass
import json
import os
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn


REPOSITORY_KIND = "micsapp-webterminal-server-list"
SSH_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
SSH_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def fail(message: str) -> NoReturn:
    raise SystemExit(f"server-repo: {message}")


def load_repository(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path}: {exc}")

    if not isinstance(document, dict):
        fail("repository root must be a JSON object")
    if document.get("kind") != REPOSITORY_KIND:
        fail(f"unexpected repository kind (expected {REPOSITORY_KIND})")
    if not isinstance(document.get("servers"), list):
        fail("repository 'servers' must be an array")
    if "schema_version" in document and not isinstance(document["schema_version"], int):
        fail("repository 'schema_version' must be an integer")
    if any(not isinstance(server, dict) for server in document["servers"]):
        fail("every repository server entry must be a JSON object")
    if not isinstance(document.get("revision", 0), int):
        fail("repository 'revision' must be an integer")
    return document


def server_web_hostname(server: dict[str, Any]) -> str:
    value = server.get("web_hostname") or server.get("hostname") or ""
    return value if isinstance(value, str) else ""


def existing_exact_ssh_hosts(config: str) -> set[str]:
    """Return literal Host tokens; wildcard patterns are deliberately ignored."""
    hosts: set[str] = set()
    for raw_line in config.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if not parts or parts[0].lower() != "host":
            continue
        for token in parts[1:]:
            if not any(char in token for char in "*!?") and SSH_HOST_RE.fullmatch(token):
                hosts.add(token.lower())
    return hosts


def tunnel_ssh_hostnames(document: dict[str, Any]) -> list[str]:
    """Return unique enabled Cloudflare SSH hostnames in repository order."""
    hostnames: list[str] = []
    seen: set[str] = set()
    for server in document["servers"]:
        if not server.get("enabled", True):
            continue
        hostname = server.get("ssh_hostname")
        hostname = hostname.strip() if isinstance(hostname, str) else ""
        mode = server.get("ssh_mode")
        if not mode:
            mode = "tunnel" if hostname else "none"
        key = hostname.lower()
        if mode == "tunnel" and SSH_HOST_RE.fullmatch(hostname) and key not in seen:
            hostnames.append(hostname)
            seen.add(key)
    return hostnames


def command_sync_ssh_config(args: argparse.Namespace) -> None:
    """Append stanzas only for new tunnel hostnames; never rewrite existing config."""
    document = load_repository(args.input)
    if not SSH_USER_RE.fullmatch(args.user):
        fail(f"invalid SSH user: {args.user!r}")

    config_path: Path = args.config.expanduser()
    additions: list[str] = []
    try:
        config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(config_path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as config_file:
            fcntl.flock(config_file.fileno(), fcntl.LOCK_EX)
            existing = config_file.read()
            known = existing_exact_ssh_hosts(existing)
            additions = [
                hostname
                for hostname in tunnel_ssh_hostnames(document)
                if hostname.lower() not in known
            ]
            if additions:
                prefix = ""
                if existing and not existing.endswith("\n"):
                    prefix += "\n"
                if existing and not (existing + prefix).endswith("\n\n"):
                    prefix += "\n"
                proxy = shlex.quote(args.cloudflared)
                stanzas = []
                for hostname in additions:
                    stanzas.append(
                        f"Host {hostname}\n"
                        f"    HostName {hostname}\n"
                        f"    User {args.user}\n"
                        f"    ProxyCommand {proxy} access ssh --hostname %h"
                    )
                config_file.seek(0, os.SEEK_END)
                config_file.write(prefix + "\n\n".join(stanzas) + "\n")
                config_file.flush()
                os.fsync(config_file.fileno())
    except OSError as exc:
        fail(f"cannot append to {config_path}: {exc}")

    if additions:
        print(f"added {len(additions)}: {', '.join(additions)}")
    else:
        print("unchanged")


def command_show(args: argparse.Namespace) -> None:
    document = load_repository(args.input)
    servers = document["servers"]

    print(f"Kind:      {document['kind']}")
    print(f"Schema:    {document.get('schema_version', 'unknown')}")
    print(f"Revision:  {document.get('revision', 0)}")
    print(f"Servers:   {len(servers)}")
    print()
    print(f"  {'WEB HOSTNAME':<32} {'SSH HOSTNAME / DNS':<34} {'SSH MODE':<8} {'STATE':<8} NAME")
    print(f"  {'-' * 32} {'-' * 34} {'-' * 8} {'-' * 8} {'-' * 20}")
    for raw_server in servers:
        if not isinstance(raw_server, dict):
            continue
        web = server_web_hostname(raw_server) or "-"
        ssh = raw_server.get("ssh_hostname") or "-"
        ssh_mode = raw_server.get("ssh_mode")
        if ssh_mode not in {"direct", "tunnel", "none"}:
            ssh_mode = "tunnel" if ssh != "-" else "none"
        state = "enabled" if raw_server.get("enabled", True) else "disabled"
        name = raw_server.get("name") or raw_server.get("id") or "-"
        marker = "*" if args.current and web == args.current else " "
        print(f"{marker} {web:<32} {str(ssh):<34} {ssh_mode:<8} {state:<8} {name}")

    if args.current:
        print()
        print(f"* current server ({args.current})")


def command_merge(args: argparse.Namespace) -> None:
    document = load_repository(args.input)
    servers = document["servers"]
    match: dict[str, Any] | None = None

    for raw_server in servers:
        if not isinstance(raw_server, dict):
            continue
        if args.web_hostname in {
            raw_server.get("id"),
            raw_server.get("hostname"),
            raw_server.get("web_hostname"),
        }:
            match = raw_server
            break

    created = match is None
    if created:
        match = {}
        servers.append(match)

    before = json.dumps(match, sort_keys=True, separators=(",", ":"))
    match["id"] = match.get("id") or args.web_hostname
    match["name"] = match.get("name") or args.name or args.web_hostname.split(".", 1)[0]
    match["hostname"] = args.web_hostname
    match["web_hostname"] = args.web_hostname
    match["enabled"] = True
    match["ssh_mode"] = args.ssh_mode
    if args.ssh_mode in {"direct", "tunnel"}:
        if not args.ssh_hostname:
            fail(f"--ssh-hostname is required for SSH mode '{args.ssh_mode}'")
        match["ssh_hostname"] = args.ssh_hostname
    else:
        match.pop("ssh_hostname", None)

    after = json.dumps(match, sort_keys=True, separators=(",", ":"))
    changed = created or before != after
    status = "created" if created else "updated" if changed else "unchanged"

    if changed:
        document["schema_version"] = max(2, document.get("schema_version", 0))
        document["revision"] = document.get("revision", 0) + 1
        if "updated_at" in document:
            document["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    try:
        args.output.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        fail(f"cannot write {args.output}: {exc}")

    print(status)
    print(document.get("revision", 0))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    show_parser = subparsers.add_parser("show", help="display a repository")
    show_parser.add_argument("input", type=Path)
    show_parser.add_argument("--current", default="", help="mark this web hostname")
    show_parser.set_defaults(handler=command_show)

    sync_parser = subparsers.add_parser(
        "sync-ssh-config", help="append missing Cloudflare SSH host stanzas"
    )
    sync_parser.add_argument("input", type=Path)
    sync_parser.add_argument(
        "--config", type=Path, default=Path("~/.ssh/config"), help="SSH config path"
    )
    sync_parser.add_argument("--user", default=getpass.getuser(), help="SSH login user")
    sync_parser.add_argument(
        "--cloudflared", default="cloudflared", help="cloudflared executable path"
    )
    sync_parser.set_defaults(handler=command_sync_ssh_config)

    merge_parser = subparsers.add_parser("merge", help="register or update one server")
    merge_parser.add_argument("input", type=Path)
    merge_parser.add_argument("output", type=Path)
    merge_parser.add_argument("--web-hostname", required=True)
    merge_parser.add_argument("--ssh-hostname", default="")
    merge_parser.add_argument(
        "--ssh-mode", required=True, choices=("tunnel", "direct", "none")
    )
    merge_parser.add_argument("--name", default="")
    merge_parser.set_defaults(handler=command_merge)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
