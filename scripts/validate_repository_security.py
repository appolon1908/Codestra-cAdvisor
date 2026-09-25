#!/usr/bin/env python3
"""Validate Codestra cAdvisor protected source authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SYNC_WORKFLOW_SHA256 = "1fe7195de00578b3d1bba61caf8b6928df59656bb01f5e7fdb3b3f236d78d436"


def logical_shell_lines(source: str) -> tuple[str, ...]:
    result: list[str] = []
    pending = ""
    heredocs: list[str] = []
    for raw in source.splitlines():
        if heredocs:
            if raw.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending += line
        trailing = len(pending) - len(pending.rstrip("\\"))
        if trailing % 2 == 1:
            pending = pending[:-1]
            continue
        result.append(pending)
        for match in re.finditer(
            r"(?<!<)<<-?(?!<)\s*(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z_][A-Za-z0-9_]*))",
            pending,
        ):
            heredocs.append(next(value for value in match.groups() if value))
        pending = ""
    if pending:
        result.append(pending)
    return tuple(result)


def reject_protected_pushes(source: str) -> None:
    approved = ["git", "push", "origin", "HEAD:refs/heads/${SYNC_BRANCH}"]
    # Only Git built-ins used by the pinned sync workflow are allowed. Unknown
    # commands may resolve to aliases or git-* helpers regardless of how their
    # configuration was written. This guard supplements, not replaces, the
    # reviewed workflow digest and GitHub branch protections.
    local_commands = {
        "add", "checkout", "commit", "config", "diff", "fetch", "init",
        "ls-remote", "merge-base", "read-tree", "remote", "rev-list",
        "rev-parse", "rm", "show", "switch",
    }
    remote_writers = {"git-send-pack", "git-http-push", "git-receive-pack"}
    approved_count = 0
    for line in logical_shell_lines(source):
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars="();&|<>")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            words = list(lexer)
        except ValueError as error:
            raise ValueError("sync_shell_parse_failed") from error
        if words == approved:
            approved_count += 1
            continue
        for word in words:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=(?:git|push)", word):
                raise ValueError("protected_branch_sync_forbidden:dynamic_command")
        segments: list[list[str]] = [[]]
        for word in words:
            if word in {"{", "}"} or (word and set(word) <= set("();&|")):
                segments.append([])
            else:
                segments[-1].append(word)
        if re.match(r"^(?:(?:elif|if|while)\s+)?(?:\(\(|\[\[)", line) is None:
            for segment in segments:
                while segment and (
                    segment[0] in {"!", "do", "elif", "if", "then", "until", "while"}
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", segment[0])
                ):
                    segment = segment[1:]
                if segment and ("$" in segment[0] or "`" in segment[0]):
                    raise ValueError("protected_branch_sync_forbidden:dynamic_command")
        git_push = False
        for index, word in enumerate(words):
            if Path(word).name in remote_writers:
                raise ValueError("protected_branch_sync_forbidden:remote_transport")
            if Path(word).name != "git":
                continue
            command_index = index + 1
            while command_index < len(words) and words[command_index].startswith("-"):
                option = words[command_index]
                if option == "-c":
                    if command_index + 1 >= len(words):
                        raise ValueError("sync_shell_parse_failed")
                    config = words[command_index + 1]
                    if (
                        config.lower().startswith("alias.")
                        or "$" in config
                    ):
                        raise ValueError(
                            "protected_branch_sync_forbidden:dynamic_command"
                        )
                if option.lower().startswith(("-calias.", "--config-env=alias.")):
                    raise ValueError(
                        "protected_branch_sync_forbidden:dynamic_command"
                    )
                command_index += 2 if option in {
                    "-c", "-C", "--git-dir", "--work-tree"
                } else 1
            if (
                command_index < len(words)
                and words[command_index] == "config"
                and any(
                    "alias." in argument.lower()
                    or "$" in argument
                    or "`" in argument
                    for argument in words[command_index + 1 :]
                )
            ):
                raise ValueError("protected_branch_sync_forbidden:dynamic_command")
            if command_index < len(words) and (
                "$" in words[command_index] or "`" in words[command_index]
            ):
                raise ValueError("protected_branch_sync_forbidden:dynamic_command")
            if command_index >= len(words):
                raise ValueError("sync_shell_parse_failed")
            if words[command_index] not in local_commands | {"push"}:
                raise ValueError("protected_branch_sync_forbidden:unreviewed_git_command")
            if command_index < len(words) and words[command_index] == "push":
                git_push = True
                break
        nested_push = any(
            re.search(r"\bgit(?:\s+(?:push|send-pack|http-push|receive-pack)|-(?:send-pack|http-push|receive-pack))\b", re.sub(r"\\([^\n])", r"\1", word))
            for word in words
        )
        dynamic_push = any(
            word == "push" and index > 0
            and ("$" in words[index - 1] or "`" in words[index - 1])
            for index, word in enumerate(words)
        )
        if git_push or nested_push or dynamic_push:
            raise ValueError("protected_branch_sync_forbidden:push_not_exact")
    if approved_count != 1:
        raise ValueError("approved_sync_push_count_invalid")


def validate_sync_branch_authority(source: str) -> None:
    expected = 'readonly SYNC_BRANCH="sync/cadvisor-upstream-${UPSTREAM_SHA}-${GITHUB_SHA}"'
    lines = logical_shell_lines(source)
    if lines.count(expected) != 1:
        raise ValueError("sync_branch_authority_invalid")
    for line in lines:
        if line == expected:
            continue
        probe = re.sub(r"\\([^\n])", r"\1", line)
        if re.search(r"(?:^|[();&|<>\s])SYNC_BRANCH\s*=", probe):
            raise ValueError("sync_branch_authority_invalid")
        if re.search(r"\b(?:unset|read|mapfile|declare|typeset|local|export|readonly|printf)\b[^\n]*\bSYNC_BRANCH\b", probe):
            raise ValueError("sync_branch_authority_invalid")


def validate_upstream(
    source: dict, lock: dict, *, allow_exact_pin_bootstrap: bool = False
) -> None:
    expected = {
        "component": "cAdvisor",
        "codestra_repository": "appolon1908-hue/Codestra-cAdvisor",
        "upstream_repository": "google/cadvisor",
        "upstream_clone_url": "https://github.com/google/cadvisor.git",
        "import_path": "upstream",
        "deployment_enabled": False,
        "secret_material_allowed_in_git": False,
    }
    for key, value in expected.items():
        if source.get(key) != value:
            raise ValueError(f"upstream_authority_drift:{key}")
    ref = source.get("upstream_ref")
    if not isinstance(ref, str) or re.fullmatch(r"[0-9a-f]{40}", ref) is None:
        raise ValueError("upstream_ref_must_be_exact_commit")
    for key in (
        "upstream_clone_url",
        "import_path",
        "deployment_enabled",
        "secret_material_allowed_in_git",
    ):
        if lock.get(key) != expected[key]:
            raise ValueError(f"upstream_lock_drift:{key}")
    locked_ref = lock.get("upstream_ref")
    locked_commit = lock.get("upstream_commit")
    if (
        not isinstance(locked_ref, str)
        or re.fullmatch(r"[0-9a-f]{40}", locked_ref) is None
        or locked_commit != locked_ref
    ):
        raise ValueError("upstream_lock_not_bound_to_exact_ref")
    if locked_ref != ref and not allow_exact_pin_bootstrap:
        raise ValueError("upstream_lock_not_bound_to_exact_ref")


def validate_sync(source: str, document: dict) -> None:
    if (document.get("permissions") or {}) != {
        "actions": "write",
        "contents": "write",
        "pull-requests": "write",
    }:
        raise ValueError("sync_permissions_drift")
    validate_sync_branch_authority(source)
    reject_protected_pushes(source)
    required = (
        "github.ref == 'refs/heads/main'",
        "[[ \"$UPSTREAM_REF\" =~ ^[0-9a-f]{40}$ ]]",
        "[[ \"$UPSTREAM_SHA\" == \"$UPSTREAM_REF\" ]]",
        'readonly SYNC_BRANCH="sync/cadvisor-upstream-${UPSTREAM_SHA}-${GITHUB_SHA}"',
        'git read-tree --prefix=upstream/ "${UPSTREAM_SHA}^{tree}"',
        '[[ "$(git rev-parse "$remote_ref")" == "$REMOTE_SHA" ]]',
        'git rev-parse "${remote_ref}:upstream"',
        'git rev-parse "${remote_ref}:CODESTRA_UPSTREAM_LOCK.json"',
        '[[ "${remote_parent_values[0]}" == "$GITHUB_SHA" ]]',
        'git diff --name-only "${remote_parent_values[0]}" "$remote_ref"',
        'LOCAL_SHA="$REMOTE_SHA"',
        "gh api --method GET",
        '-f base="main"',
        '-f head="${GITHUB_REPOSITORY_OWNER}:${SYNC_BRANCH}"',
        ".head.repo.full_name",
        '[[ "$pr_head_sha" == "$LOCAL_SHA" ]]',
        '[[ "$pr_repository" == "$GITHUB_REPOSITORY" ]]',
        "Multiple open synchronization pull requests found.",
        "gh pr create",
        "--base main",
        'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
        "'synchronized_at': os.environ['UPSTREAM_TIMESTAMP']",
        'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
        'export GIT_COMMITTER_DATE="$UPSTREAM_TIMESTAMP"',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"reviewed_sync_boundary_missing:{token}")
    if hashlib.sha256(source.encode()).hexdigest() != SYNC_WORKFLOW_SHA256:
        raise ValueError("sync_workflow_digest_mismatch")


def validate_workflow(source: str) -> None:
    required = (
        "pull_request:",
        "workflow_dispatch:",
        "validate-source:",
        "name: validate-source",
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "persist-credentials: false",
        "fetch-depth: 0",
        "Bind vendored Git tree to exact official commit",
        "Classify an exact upstream-pin bootstrap",
        '(( ${#changed[@]} == 1 ))',
        '[[ "${changed[0]}" == CODESTRA_UPSTREAM.json ]]',
        "validator_args+=(--allow-exact-pin-bootstrap)",
        'validation_ref="$locked_upstream_ref"',
        'base_sha="$CADVISOR_VALIDATION_BASE_SHA"',
        "git rev-parse 'HEAD:upstream'",
        '[[ "$vendored_tree" == "$official_tree" ]]',
        'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"validation_boundary_missing:{token}")
    if re.search(r"uses:\s+actions/(?:checkout|setup-python)@v\d+", source):
        raise ValueError("mutable_action_reference")
    if re.search(r"pull_request:\s*\n\s+paths:", source):
        raise ValueError("pull_request_validation_must_be_unconditional")
    if re.search(r"^\s*git diff --check\s*$", source, re.MULTILINE):
        raise ValueError("whitespace_check_must_use_committed_range")


def validate_repository(*, allow_exact_pin_bootstrap: bool = False) -> None:
    paths = {
        "source": ROOT / "CODESTRA_UPSTREAM.json",
        "lock": ROOT / "CODESTRA_UPSTREAM_LOCK.json",
        "sync": ROOT / ".github/workflows/upstream-source-sync.yml",
        "validate": ROOT / ".github/workflows/validate.yml",
    }
    for path in paths.values():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required_regular_file_missing:{path.relative_to(ROOT)}")
    source = json.loads(paths["source"].read_text())
    lock = json.loads(paths["lock"].read_text())
    sync_source = paths["sync"].read_text()
    validate_source = paths["validate"].read_text()
    validate_upstream(
        source, lock, allow_exact_pin_bootstrap=allow_exact_pin_bootstrap
    )
    validate_sync(sync_source, yaml.safe_load(sync_source))
    yaml.safe_load(validate_source)
    validate_workflow(validate_source)
    if (ROOT / "upstream/.git").exists():
        raise ValueError("nested_upstream_git_metadata_forbidden")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-exact-pin-bootstrap", action="store_true")
    arguments = parser.parse_args()
    try:
        validate_repository(
            allow_exact_pin_bootstrap=arguments.allow_exact_pin_bootstrap
        )
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"CADVISOR_SOURCE_SECURITY=FAIL ERROR={error}") from error
    print("CADVISOR_SOURCE_SECURITY=PASS")
    print("UPSTREAM_COMMIT_PINNED=YES")
    print("SYNC_THROUGH_REVIEWED_PR=YES")
    print("DEPLOYMENT_ENABLED=NO")
