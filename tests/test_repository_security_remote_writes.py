"""Synthetic policy regressions; never execute the supplied shell commands."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "remote_write_policy", ROOT / "scripts/validate_repository_security.py"
)
assert SPEC is not None and SPEC.loader is not None
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
APPROVED = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"\n'


class RemoteWritePolicyTests(unittest.TestCase):
    def test_approved_write(self) -> None:
        policy.reject_protected_pushes(APPROVED)

    def test_checked_in_sync_remains_valid(self) -> None:
        policy.reject_protected_pushes(
            (ROOT / ".github/workflows/upstream-source-sync.yml").read_text()
        )

    def test_local_preparation_commands(self) -> None:
        for command in (
            'git init repo', 'git -C repo fetch origin SHA',
            'git read-tree --prefix=upstream/ SHA', 'git add file',
            'git rm --cached file', 'git diff --cached --quiet',
            'git config user.name codestra', 'git commit -m reviewed',
            'git rev-parse HEAD', 'git rev-list --parents -n 1 HEAD',
            'git merge-base --is-ancestor base HEAD',
            'git ls-remote --heads origin ref', 'git remote add origin repo',
            'git show HEAD', 'git checkout --detach SHA', 'git switch branch',
        ):
            with self.subTest(command=command):
                policy.reject_protected_pushes(APPROVED + command)

    def test_alias_and_remote_write_rejection(self) -> None:
        for command in (
            "printf '[alias]\\n x = push\\n' > ~/.gitconfig\ngit x origin HEAD:refs/heads/main",
            "cp aliases .git/config\ngit x origin HEAD:refs/heads/main",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.x GIT_CONFIG_VALUE_0=push git x origin HEAD:refs/heads/main",
            'git send-pack origin HEAD:refs/heads/main',
            'git http-push origin HEAD:refs/heads/main',
            'git receive-pack remote',
            '/usr/lib/git-core/git-send-pack origin HEAD:refs/heads/main',
            'git-http-push origin HEAD:refs/heads/main',
            "sh -c 'git send-pack origin HEAD:refs/heads/main'",
            'git external-helper origin HEAD:refs/heads/main',
            'git -c alias.x=push x origin HEAD:refs/heads/main',
            'GIT=git; "$GIT" push origin HEAD:refs/heads/main',
            'suffix=; git p${suffix}ush origin HEAD:refs/heads/main',
            'git push origin HEAD:refs/heads/main',
            "g''it p''ush origin HEAD:refs/heads/main",
        ):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    policy.reject_protected_pushes(APPROVED + command)

    def test_exactly_one_write(self) -> None:
        for source in ('', APPROVED * 2, "cat <<'EOF'\n" + APPROVED + 'EOF\n'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                policy.reject_protected_pushes(source)


if __name__ == '__main__':
    unittest.main()
