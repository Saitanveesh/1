"""No deletion may occur without all branch-retirement safety gates."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prune_merged_branches import classify  # noqa: E402


class BranchRetirementPolicyTests(unittest.TestCase):
    def setUp(self):
        self.record = {
            "name": "build/previously-merged-change",
            "sha": "a" * 40,
            "category": "merged_pr",
        }
        self.live_sha = "a" * 40

    def evaluate(
        self,
        record=None,
        live_sha=None,
        open_refs=None,
        ancestor=True,
        referenced=False,
    ):
        return classify(
            record or self.record,
            self.live_sha if live_sha is None else live_sha,
            set() if open_refs is None else open_refs,
            ancestor,
            referenced,
        )

    def test_clean_integrated_branch_is_eligible(self):
        self.assertEqual(self.evaluate(), "eligible")

    def test_open_pr_head_or_base_is_preserved(self):
        self.assertEqual(
            self.evaluate(open_refs={"build/previously-merged-change"}),
            "used by open PR",
        )

    def test_divergent_branch_is_preserved(self):
        self.assertIn("not already", self.evaluate(ancestor=False))

    def test_changed_tip_is_preserved(self):
        self.assertEqual(
            self.evaluate(live_sha="b" * 40),
            "head changed since inventory",
        )

    def test_reference_in_repository_prevents_deletion(self):
        self.assertEqual(
            self.evaluate(referenced=True),
            "referenced by tracked project files",
        )

    def test_unmerged_branch_is_preserved(self):
        row = {**self.record, "category": "other"}
        self.assertEqual(
            self.evaluate(record=row), "not a completed PR branch"
        )

    def test_any_open_pr_category_is_preserved(self):
        row = {**self.record, "category": "open_pr"}
        self.assertEqual(
            self.evaluate(record=row), "not a completed PR branch"
        )

    def test_release_and_backups_are_preserved(self):
        for name in (
            "release/mon-batch4-rc1",
            "backup/postgres-logical-restore",
            "ops/mon-three-lab-docker-migration-20261028",
            "lab/test-day-readiness",
            "feature/mon-final-console-20261023",
            "main",
        ):
            with self.subTest(name=name):
                row = {**self.record, "name": name}
                self.assertEqual(
                    self.evaluate(record=row), "protected branch"
                )


if __name__ == "__main__":
    unittest.main()
