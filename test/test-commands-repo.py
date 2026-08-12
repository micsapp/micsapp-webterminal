#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("commands_repo", ROOT / "commands-repo.py")
commands_repo = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(commands_repo)


def command(command_id, name, text, updated=1, created=1, **extra):
    return {
        "id": command_id,
        "name": name,
        "command": text,
        "tags": extra.pop("tags", "test"),
        "created": created,
        "updated": updated,
        **extra,
    }


class CommandsRepositoryTests(unittest.TestCase):
    def test_merge_union_and_idempotence(self):
        remote = [command("aaaaaaaaaaaa", "Remote", "echo remote")]
        local = [command("bbbbbbbbbbbb", "Local", "echo local")]
        merged, stats = commands_repo.merge_collections(remote, local)
        self.assertEqual([item["name"] for item in merged], ["Local", "Remote"])
        self.assertEqual(stats["added_local"], 1)
        self.assertEqual(stats["added_remote"], 1)

        second, second_stats = commands_repo.merge_collections(merged, merged)
        self.assertEqual(commands_repo.canonical_json(second), commands_repo.canonical_json(merged))
        self.assertEqual(second_stats["added_local"], 0)
        self.assertEqual(second_stats["added_remote"], 0)
        self.assertEqual(second_stats["deduplicated"], 0)

    def test_same_normalized_name_deduplicates_and_keeps_remote_id(self):
        remote = [command("aaaaaaaaaaaa", "Docker   Status", "docker ps", updated=1)]
        local = [command("bbbbbbbbbbbb", " docker status ", "docker ps -a", updated=2)]
        merged, stats = commands_repo.merge_collections(remote, local)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["id"], "aaaaaaaaaaaa")
        self.assertEqual(merged[0]["command"], "docker ps -a")
        self.assertEqual(stats["deduplicated"], 1)

    def test_newer_remote_wins_and_earliest_created_is_preserved(self):
        remote = [command("aaaaaaaaaaaa", "Status", "new", updated=5, created=3, owner="remote")]
        local = [command("aaaaaaaaaaaa", "Status", "old", updated=4, created=2, local=True)]
        merged, stats = commands_repo.merge_collections(remote, local)
        self.assertEqual(merged[0]["command"], "new")
        self.assertEqual(merged[0]["created"], 2)
        self.assertEqual(merged[0]["owner"], "remote")
        self.assertTrue(merged[0]["local"])
        self.assertEqual(stats["updated"], 1)

    def test_equal_timestamp_conflict_is_deterministic(self):
        first = command("aaaaaaaaaaaa", "Status", "aaa", updated=2)
        second = command("aaaaaaaaaaaa", "Status", "zzz", updated=2)
        left, _ = commands_repo.merge_collections([first], [second])
        right, _ = commands_repo.merge_collections([second], [first])
        self.assertEqual(left[0]["command"], "zzz")
        self.assertEqual(commands_repo.canonical_json(left), commands_repo.canonical_json(right))

    def test_local_invalid_and_duplicate_ids_are_repaired_deterministically(self):
        used = set()
        raw = [
            {"id": "bad", "name": "One", "command": "echo 1"},
            {"id": "bad", "name": "Two", "command": "echo 2"},
        ]
        normalized = commands_repo.normalize_commands(raw, remote=False)
        self.assertEqual(len({item["id"] for item in normalized}), 2)
        self.assertTrue(all(commands_repo.COMMAND_ID_RE.fullmatch(item["id"]) for item in normalized))
        self.assertEqual(normalized, commands_repo.normalize_commands(raw, remote=False))

    def test_repository_validation_rejects_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "commands.json"
            path.write_text(json.dumps({
                "kind": commands_repo.REPOSITORY_KIND,
                "schema_version": 1,
                "revision": 0,
                "commands": [
                    command("aaaaaaaaaaaa", "One", "echo 1"),
                    command("aaaaaaaaaaaa", "Two", "echo 2"),
                ],
            }), encoding="utf-8")
            with self.assertRaises(SystemExit):
                commands_repo.load_repository(path)

    def test_malformed_local_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "local.json"
            path.write_text("not-json", encoding="utf-8")
            with self.assertRaises(SystemExit):
                commands_repo.load_local(path)


if __name__ == "__main__":
    unittest.main()
