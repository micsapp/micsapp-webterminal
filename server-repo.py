#!/usr/bin/env python3
"""Validate, display, and update the shared web-terminal server list."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn


REPOSITORY_KIND = "micsapp-webterminal-server-list"


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
