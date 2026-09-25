#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_repository_security", ROOT / "scripts/validate_repository_security.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RepositorySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sync_source = (ROOT / ".github/workflows/upstream-source-sync.yml").read_text()
        self.sync_document = yaml.safe_load(self.sync_source)

    def test_current_repository_security_contract(self) -> None:
        VALIDATOR.validate_repository(
            allow_exact_pin_bootstrap=(
                os.environ.get("CADVISOR_PENDING_SYNC") == "1"
            )
        )

    def test_mutable_upstream_ref_is_rejected(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "main"
        with self.assertRaisesRegex(ValueError, "upstream_ref_must_be_exact_commit"):
            VALIDATOR.validate_upstream(source, lock)

    def test_exact_pin_bootstrap_allows_only_source_authority_drift(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "upstream_lock_not_bound"):
            VALIDATOR.validate_upstream(source, lock)
        VALIDATOR.validate_upstream(
            source, lock, allow_exact_pin_bootstrap=True
        )
        lock["upstream_commit"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "upstream_lock_not_bound"):
            VALIDATOR.validate_upstream(
                source, lock, allow_exact_pin_bootstrap=True
            )

    def test_sync_uses_reviewed_retry_safe_pull_request(self) -> None:
        VALIDATOR.validate_sync(self.sync_source, self.sync_document)
        unsafe = self.sync_source.replace(
            'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
            "git push origin HEAD:main",
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync(unsafe, self.sync_document)
        for token in (
            '[[ "$(git rev-parse "$remote_ref")" == "$REMOTE_SHA" ]]',
            'git rev-parse "${remote_ref}:upstream"',
            'git rev-parse "${remote_ref}:CODESTRA_UPSTREAM_LOCK.json"',
            '[[ "${remote_parent_values[0]}" == "$GITHUB_SHA" ]]',
            'git diff --name-only "${remote_parent_values[0]}" "$remote_ref"',
            'LOCAL_SHA="$REMOTE_SHA"',
            "if (( ${#OPEN_PRS[@]} > 1 )); then",
            'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
        ):
            self.assertIn(token, self.sync_source)
        self.assertNotIn('[[ "$REMOTE_SHA" == "$LOCAL_SHA" ]]', self.sync_source)

    def test_retry_reuses_equivalent_existing_branch_after_main_advances(self) -> None:
        required = 'LOCAL_SHA="$REMOTE_SHA"'
        unsafe = self.sync_source.replace(required, "true")
        with self.assertRaisesRegex(ValueError, "reviewed_sync_boundary_missing"):
            VALIDATOR.validate_sync(unsafe, yaml.safe_load(unsafe))

    def test_sync_rejects_quoted_and_obscured_protected_refspecs(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        for command in (
            'git push origin "HEAD:refs/heads/main"',
            '(git push origin HEAD:refs/heads/staging)',
            '/usr/bin/git -c protocol.version=2 push origin HEAD:refs/heads/production>/dev/null',
        ):
            with self.subTest(command=command):
                unsafe = self.sync_source.replace(safe, command)
                with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
                    VALIDATOR.validate_sync(unsafe, yaml.safe_load(unsafe))

    def test_brace_expansion_and_indirect_destinations_fail_closed(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        for command in (
            "git push origin HEAD:refs/heads/{main,topic}",
            "git -c remote.origin.push=HEAD:refs/heads/main push origin",
            "git push origin 2>/dev/null HEAD:refs/heads/main",
            "bash -c 'git push origin HEAD:refs/heads/main'",
        ):
            with self.subTest(command=command):
                unsafe = self.sync_source.replace(safe, command)
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden:push_not_exact"
                ):
                    VALIDATOR.validate_sync(unsafe, yaml.safe_load(unsafe))

    def test_quoted_fragments_and_missing_approved_push_fail_closed(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        quoted = self.sync_source.replace(
            safe, safe + "\n          g''it p''ush origin HEAD:refs/heads/main"
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync(quoted, yaml.safe_load(quoted))
        missing = self.sync_source.replace(safe, "true")
        with self.assertRaisesRegex(ValueError, "approved_sync_push_count_invalid"):
            VALIDATOR.validate_sync(missing, yaml.safe_load(missing))

    def test_dynamic_command_words_and_subcommands_fail_closed(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        for command in (
            safe + '\n          G=git; "$G" push origin HEAD:refs/heads/main',
            safe + '\n          verb=push; git "$verb" origin HEAD:refs/heads/main',
            safe + '\n          suffix=; git p${suffix}ush origin HEAD:refs/heads/main',
            safe
            + '\n          G=/usr/bin/git; P=pu; P+=sh; { "$G" "$P" origin HEAD:refs/heads/main; }',
            safe
            + '\n          git -c alias.x=push x origin HEAD:refs/heads/main',
            safe
            + '\n          git -calias.x=push x origin HEAD:refs/heads/main',
            safe
            + '\n          git config alias.x push; git x origin HEAD:refs/heads/main',
        ):
            with self.subTest(command=command):
                unsafe = self.sync_source.replace(safe, command)
                with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
                    VALIDATOR.validate_sync(unsafe, yaml.safe_load(unsafe))

    def test_heredoc_body_cannot_satisfy_approved_push_count(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        body_only = self.sync_source.replace(
            safe,
            "cat <<'PUSH_EVIDENCE'\n          " + safe + "\n          PUSH_EVIDENCE",
        )
        with self.assertRaisesRegex(ValueError, "approved_sync_push_count_invalid"):
            VALIDATOR.validate_sync(body_only, yaml.safe_load(body_only))

    def test_manual_sync_is_restricted_to_main(self) -> None:
        gate = "github.ref == 'refs/heads/main'"
        self.assertIn(gate, self.sync_source)
        unsafe = self.sync_source.replace(gate, "true")
        with self.assertRaisesRegex(ValueError, "reviewed_sync_boundary_missing"):
            VALIDATOR.validate_sync(unsafe, yaml.safe_load(unsafe))

    def test_bot_created_pr_dispatches_exact_branch_validation(self) -> None:
        assignment = (
            'readonly SYNC_BRANCH="sync/cadvisor-upstream-'
            '${UPSTREAM_SHA}-${GITHUB_SHA}"'
        )
        self.assertIn(assignment, self.sync_source)
        without_epoch = self.sync_source.replace(
            assignment, assignment.replace("-${GITHUB_SHA}", "")
        )
        with self.assertRaisesRegex(ValueError, "sync_branch_authority_invalid"):
            VALIDATOR.validate_sync(without_epoch, yaml.safe_load(without_epoch))
        self.assertEqual(
            self.sync_document["permissions"],
            {"actions": "write", "contents": "write", "pull-requests": "write"},
        )
        self.assertIn(
            'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
            self.sync_source,
        )

    def test_existing_sync_pr_identity_is_exact(self) -> None:
        for token in (
            'gh api --method GET "repos/${GITHUB_REPOSITORY}/pulls"',
            '-f head="${GITHUB_REPOSITORY_OWNER}:${SYNC_BRANCH}"',
            '.head.repo.full_name',
            '[[ "$pr_head_sha" == "$LOCAL_SHA" ]]',
            '[[ "$pr_repository" == "$GITHUB_REPOSITORY" ]]',
        ):
            self.assertIn(token, self.sync_source)
        for token in (
            '[[ "$pr_head_sha" == "$LOCAL_SHA" ]]',
            '[[ "$pr_repository" == "$GITHUB_REPOSITORY" ]]',
        ):
            with self.subTest(token=token):
                unsafe = self.sync_source.replace(token, "true")
                with self.assertRaisesRegex(
                    ValueError, "reviewed_sync_boundary_missing"
                ):
                    VALIDATOR.validate_sync(unsafe, yaml.safe_load(unsafe))

    def test_vendored_tree_is_bound_to_fresh_official_commit(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn('fetch --depth 1 --no-tags origin "$upstream_ref"', source)
        self.assertIn("rev-parse 'HEAD^{tree}'", source)
        self.assertIn("git rev-parse 'HEAD:upstream'", source)
        self.assertIn('[[ "$vendored_tree" == "$official_tree" ]]', source)

    def test_validation_classifies_only_exact_upstream_pin_bootstrap(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        for token in (
            "Classify an exact upstream-pin bootstrap",
            '(( ${#changed[@]} == 1 ))',
            '[[ "${changed[0]}" == CODESTRA_UPSTREAM.json ]]',
            "validator_args+=(--allow-exact-pin-bootstrap)",
            'validation_ref="$locked_upstream_ref"',
            'base_sha="$CADVISOR_VALIDATION_BASE_SHA"',
            'os.environ.get("CADVISOR_PENDING_SYNC") == "1"',
        ):
            self.assertIn(
                token,
                source if "os.environ" not in token else Path(__file__).read_text(),
            )

    def test_actions_are_pinned_and_validation_is_unconditional(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        VALIDATOR.validate_workflow(source)
        unsafe = source.replace("pull_request:\n", "pull_request:\n    paths:\n      - scripts/**\n")
        with self.assertRaisesRegex(ValueError, "pull_request_validation_must_be_unconditional"):
            VALIDATOR.validate_workflow(unsafe)

    def test_whitespace_gate_checks_the_committed_base_to_head_range(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("fetch-depth: 0", source)
        self.assertIn('base_sha="${{ github.event.pull_request.base.sha }}"', source)
        self.assertIn(
            'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
            source,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
