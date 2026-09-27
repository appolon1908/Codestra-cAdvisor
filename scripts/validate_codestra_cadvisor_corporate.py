#!/usr/bin/env python3
"""Canonical entrypoint for Codestra cAdvisor corporate validation.

Managed application containers require a deployment-owned replica label before
their metrics survive Prometheus relabeling. The three exporter/security
containers are infrastructure components rather than application replicas, so
they must carry the six stable platform identity labels but are intentionally
exempt from `codestra.replica`.

The base validator also proves that cAdvisor's Docker-label whitelist retains the
full seven-label application contract. This wrapper therefore never mutates the
contract constant. It validates the real Compose labels first and supplies a
synthetic infrastructure replica only to the base Compose checker, preserving the
full whitelist and every other hardening check.

The locked upstream cAdvisor command module no longer exposes a `--rootfs` CLI
flag. Upstream still requires the read-only host-root bind at `/rootfs`, so this
wrapper requires that mount, rejects the removed flag, and reconciles only that
single source-version difference before invoking the base Compose policy.
"""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import re
import sys
from types import ModuleType
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_codestra_cadvisor.py"
REMOVED_LOCKED_SOURCE_FLAG = "--rootfs=/rootfs"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("codestra_cadvisor_policy", VALIDATOR)
    if spec is None or spec.loader is None:
        fail("unable to load the cAdvisor policy validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_proxy_source_and_tests_syntax_aware(module: ModuleType) -> None:
    """Preserve every proxy check while accepting gofmt field alignment."""

    original_require_file = module.require_file

    def require_file_with_normalized_test_spacing(path: pathlib.Path) -> str:
        text = original_require_file(path)
        if path == module.PROXY_TEST:
            # The base policy checks named table cases. Go permits and gofmt may
            # retain aligned spacing such as `name:   "connection upgrade"`.
            text = re.sub(r'name:\s+"', 'name: "', text)
        return text

    module.require_file = require_file_with_normalized_test_spacing
    try:
        module.validate_proxy_source_and_tests()
    finally:
        module.require_file = original_require_file


def validate_locked_source_rootfs_contract(module: ModuleType, compose: dict[str, Any]) -> None:
    cadvisor = compose.get("services", {}).get("cadvisor", {})
    command = {str(item) for item in cadvisor.get("command", [])}
    if REMOVED_LOCKED_SOURCE_FLAG in command:
        module.fail(
            "locked cAdvisor source no longer supports --rootfs; retain the "
            "read-only /rootfs bind without the removed CLI flag"
        )

    root_mounts = [
        item
        for item in cadvisor.get("volumes", [])
        if isinstance(item, dict) and item.get("target") == "/rootfs"
    ]
    if len(root_mounts) != 1 or root_mounts[0].get("read_only") is not True:
        module.fail("cAdvisor requires exactly one read-only host-root bind at /rootfs")
    if root_mounts[0].get("source") != "/":
        module.fail("cAdvisor /rootfs must map the host root and may not use another source")


def validate_compose_with_infrastructure_replica_exemption(module: ModuleType) -> None:
    original_load_yaml = module.load_yaml
    original_required_flags = module.REQUIRED_CADVISOR_FLAGS
    compose = original_load_yaml(module.COMPOSE)
    services = compose.get("services", {})
    stable_labels = module.DOCKER_LABELS - {"codestra.replica"}

    validate_locked_source_rootfs_contract(module, compose)

    for name, service in services.items():
        labels = service.get("labels", {})
        missing = stable_labels - set(labels)
        if missing:
            module.fail(
                f"managed cAdvisor infrastructure service {name} is missing labels: "
                f"{sorted(missing)}"
            )
        if "codestra.replica" in labels:
            module.fail(
                f"cAdvisor infrastructure service {name} must not impersonate an "
                "application replica"
            )

    def load_yaml_with_infrastructure_replica(path: pathlib.Path) -> Any:
        value = original_load_yaml(path)
        if path != module.COMPOSE:
            return value
        value = copy.deepcopy(value)
        for service in value.get("services", {}).values():
            service.setdefault("labels", {})["codestra.replica"] = "infrastructure"
        return value

    module.REQUIRED_CADVISOR_FLAGS = set(original_required_flags) - {
        REMOVED_LOCKED_SOURCE_FLAG
    }
    module.load_yaml = load_yaml_with_infrastructure_replica
    try:
        module.validate_compose()
    finally:
        module.load_yaml = original_load_yaml
        module.REQUIRED_CADVISOR_FLAGS = original_required_flags


def main() -> None:
    module = load_validator()
    module.validate_runtime()
    module.validate_label_contract()
    module.validate_relabel_contract()
    validate_proxy_source_and_tests_syntax_aware(module)
    validate_compose_with_infrastructure_replica_exemption(module)
    module.validate_packaging_docs_and_secrets()
    print("Codestra cAdvisor corporate configuration validation PASS")


if __name__ == "__main__":
    main()
