#!/usr/bin/env python3
"""Validate, display, initialize, and merge the shared quick-command repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn


REPOSITORY_KIND = "micsapp-webterminal-commands"
COMMAND_ID_RE = re.compile(r"^[a-f0-9]{12}$")
MAX_COMMANDS = 10_000


def fail(message: str) -> NoReturn:
    raise SystemExit(f"commands-repo: {message}")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalized_name(value: str) -> str:
    return " ".join(value.strip().casefold().split())


def normalize_tags(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(tag).strip() for tag in value if str(tag).strip())
    if value is None:
        return ""
    return str(value).strip()


def valid_timestamp(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def generated_id(command: dict[str, Any], used: set[str]) -> str:
    seed = canonical_json({
        "name": normalized_name(command["name"]),
        "command": command["command"],
        "tags": command["tags"],
    })
    attempt = 0
    while True:
        suffix = "" if attempt == 0 else f"\0{attempt}"
        candidate = hashlib.sha256((seed + suffix).encode("utf-8")).hexdigest()[:12]
        if candidate not in used:
            return candidate
        attempt += 1


def normalize_command(raw: Any, *, used_ids: set[str], require_valid_id: bool) -> dict[str, Any]:
    if not isinstance(raw, dict):
        fail("every command must be a JSON object")
    name = raw.get("name")
    command_text = raw.get("command")
    if not isinstance(name, str) or not name.strip():
        fail("every command must have a non-empty string name")
    if not isinstance(command_text, str) or not command_text.strip():
        fail("every command must have a non-empty string command")

    result = dict(raw)
    result["name"] = name.strip()
    result["command"] = command_text
    result["tags"] = normalize_tags(raw.get("tags", ""))
    result["created"] = valid_timestamp(raw.get("created"))
    result["updated"] = valid_timestamp(raw.get("updated"))

    command_id = raw.get("id")
    command_id = command_id.strip().lower() if isinstance(command_id, str) else ""
    if require_valid_id and not COMMAND_ID_RE.fullmatch(command_id):
        fail(f"invalid command id for {result['name']!r}")
    if not COMMAND_ID_RE.fullmatch(command_id) or command_id in used_ids:
        if require_valid_id and command_id in used_ids:
            fail(f"duplicate command id: {command_id}")
        command_id = generated_id(result, used_ids)
    result["id"] = command_id
    used_ids.add(command_id)
    return result


def normalize_commands(raw_commands: Any, *, remote: bool) -> list[dict[str, Any]]:
    if not isinstance(raw_commands, list):
        fail("commands must be a JSON array")
    if len(raw_commands) > MAX_COMMANDS:
        fail(f"repository exceeds the {MAX_COMMANDS} command limit")
    used_ids: set[str] = set()
    return [
        normalize_command(raw, used_ids=used_ids, require_valid_id=remote)
        for raw in raw_commands
    ]


def load_repository(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path}: {exc}")
    if not isinstance(document, dict):
        fail("repository root must be a JSON object")
    if document.get("kind") != REPOSITORY_KIND:
        fail(f"unexpected repository kind (expected {REPOSITORY_KIND})")
    schema_version = document.get("schema_version")
    revision = document.get("revision")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version < 1:
        fail("repository schema_version must be a positive integer")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        fail("repository revision must be a non-negative integer")
    normalized = dict(document)
    normalized["commands"] = normalize_commands(document.get("commands"), remote=True)
    return normalized


def load_local(path: Path) -> list[dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read local commands {path}: {exc}")
    return normalize_commands(raw, remote=False)


def editable_signature(command: dict[str, Any]) -> str:
    return canonical_json({key: command.get(key) for key in ("name", "command", "tags")})


def merge_entry(shared: dict[str, Any], incoming: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    shared_updated = shared.get("updated", 0)
    incoming_updated = incoming.get("updated", 0)
    if incoming_updated > shared_updated:
        winner, loser = incoming, shared
    elif incoming_updated < shared_updated:
        winner, loser = shared, incoming
    elif editable_signature(incoming) > editable_signature(shared):
        winner, loser = incoming, shared
    else:
        winner, loser = shared, incoming

    merged = dict(loser)
    merged.update(winner)
    merged["id"] = shared["id"]
    created_values = [value for value in (shared.get("created", 0), incoming.get("created", 0)) if value > 0]
    merged["created"] = min(created_values) if created_values else 0
    merged["updated"] = max(shared_updated, incoming_updated)
    return merged, editable_signature(shared) != editable_signature(incoming)


def merge_collections(
    remote_commands: list[dict[str, Any]], local_commands: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    stats = {"added_local": 0, "added_remote": 0, "updated": 0, "deduplicated": 0}
    merged: list[dict[str, Any]] = []
    by_id: dict[str, int] = {}
    by_name: dict[str, int] = {}
    for command in remote_commands:
        name_key = normalized_name(command["name"])
        index = by_name.get(name_key)
        if index is None:
            index = len(merged)
            merged.append(dict(command))
            by_id[command["id"]] = index
            by_name[name_key] = index
            continue
        shared = merged[index]
        combined, fields_differ = merge_entry(shared, command)
        merged[index] = combined
        by_id[combined["id"]] = index
        by_name[normalized_name(combined["name"])] = index
        stats["deduplicated"] += 1
        if fields_differ:
            stats["updated"] += 1

    remote_ids = set(by_id)
    local_match_ids: set[str] = set()

    for incoming in local_commands:
        name_key = normalized_name(incoming["name"])
        index = by_id.get(incoming["id"])
        name_matched = False
        if index is None:
            index = by_name.get(name_key)
            name_matched = index is not None
        if index is None:
            command = dict(incoming)
            if command["id"] in by_id:
                command["id"] = generated_id(command, set(by_id))
            index = len(merged)
            merged.append(command)
            by_id[command["id"]] = index
            by_name[name_key] = index
            stats["added_remote"] += 1
            local_match_ids.add(command["id"])
            continue

        shared = merged[index]
        if name_matched and shared["id"] != incoming["id"]:
            stats["deduplicated"] += 1
        combined, fields_differ = merge_entry(shared, incoming)
        old_name_key = normalized_name(shared["name"])
        merged[index] = combined
        by_id[combined["id"]] = index
        if by_name.get(old_name_key) == index and old_name_key != normalized_name(combined["name"]):
            del by_name[old_name_key]
        by_name[normalized_name(combined["name"])] = index
        local_match_ids.add(combined["id"])
        if fields_differ:
            stats["updated"] += 1

    stats["added_local"] = len(remote_ids - local_match_ids)
    unique: list[dict[str, Any]] = []
    unique_by_name: dict[str, int] = {}
    for command in merged:
        name_key = normalized_name(command["name"])
        index = unique_by_name.get(name_key)
        if index is None:
            unique_by_name[name_key] = len(unique)
            unique.append(command)
            continue
        combined, fields_differ = merge_entry(unique[index], command)
        unique[index] = combined
        stats["deduplicated"] += 1
        if fields_differ:
            stats["updated"] += 1

    merged = unique
    merged.sort(key=lambda command: (normalized_name(command["name"]), command["id"]))
    return merged, stats


def write_json(path: Path, value: Any) -> None:
    try:
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        fail(f"cannot write {path}: {exc}")


def command_init(args: argparse.Namespace) -> None:
    document = {
        "kind": REPOSITORY_KIND,
        "schema_version": 1,
        "revision": 0,
        "updated_at": utc_now(),
        "commands": [],
    }
    write_json(args.output, document)
    print(canonical_json({"ok": True, "revision": 0, "total": 0}))


def command_show(args: argparse.Namespace) -> None:
    document = load_repository(args.input)
    print(f"Kind:      {document['kind']}")
    print(f"Schema:    {document['schema_version']}")
    print(f"Revision:  {document['revision']}")
    print(f"Commands:  {len(document['commands'])}")
    if document["commands"]:
        print()
        print(f"  {'ID':<12}  {'NAME':<32} TAGS")
        print(f"  {'-' * 12}  {'-' * 32} {'-' * 24}")
        for command in document["commands"]:
            print(f"  {command['id']:<12}  {command['name'][:32]:<32} {command['tags']}")


def command_merge(args: argparse.Namespace) -> None:
    document = load_repository(args.remote)
    local_commands = load_local(args.local)
    merged, stats = merge_collections(document["commands"], local_commands)

    remote_changed = canonical_json(merged) != canonical_json(document["commands"])
    local_changed = canonical_json(merged) != canonical_json(local_commands)
    output_document = dict(document)
    output_document["commands"] = merged
    if remote_changed:
        output_document["schema_version"] = max(1, document["schema_version"])
        output_document["revision"] = document["revision"] + 1
        output_document["updated_at"] = utc_now()

    write_json(args.remote_output, output_document)
    write_json(args.local_output, merged)
    metadata = {
        "ok": True,
        "mode": "merge",
        **stats,
        "total": len(merged),
        "revision": output_document["revision"],
        "remote_changed": remote_changed,
        "local_changed": local_changed,
        "changed": remote_changed or local_changed,
    }
    print(canonical_json(metadata))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create an empty commands repository")
    init_parser.add_argument("output", type=Path)
    init_parser.set_defaults(handler=command_init)

    show_parser = subparsers.add_parser("show", help="display a commands repository")
    show_parser.add_argument("input", type=Path)
    show_parser.set_defaults(handler=command_show)

    merge_parser = subparsers.add_parser("merge", help="merge remote and local commands")
    merge_parser.add_argument("remote", type=Path)
    merge_parser.add_argument("local", type=Path)
    merge_parser.add_argument("remote_output", type=Path)
    merge_parser.add_argument("local_output", type=Path)
    merge_parser.set_defaults(handler=command_merge)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
