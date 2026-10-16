#!/usr/bin/env python3
"""Fail-closed validation of this exporter's place in the monitoring platform.

Reads ``codestra/monitoring-platform.v1.json`` and proves from source that the
exporter listens only on the private observability network (no host port,
no internet ingress), that it either holds no credential by design or reads
every credential from a runtime file declared as an OpenBao secret reference
(never a value in Git), and, for the Blackbox Exporter, that every probe
module is read-only (GET/HEAD, TCP, DNS, ICMP) and that the OpenBao health
module never unseals.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CODESTRA = ROOT / "codestra"
PLATFORM = CODESTRA / "monitoring-platform.v1.json"
SECRET_REFERENCES = CODESTRA / "secret-references.v1.json"
SECRET_SCHEMA = CODESTRA / "contracts" / "secret-reference.v1.schema.json"
SECRET_SCHEMA_PIN = CODESTRA / "contracts" / "secret-reference.v1.schema.sha256"
FORBIDDEN_REFERENCE_KEYS = {
    "value", "password", "token", "private_key", "client_secret", "secret",
    "secret_value", "unseal_key", "recovery_key", "root_token",
}
CREDENTIAL_KEY = re.compile(r"(?im)^\s*(?:-\s*)?([A-Z][A-Z0-9_]*(?:PASSWORD|PASS|SECRET|TOKEN|API_KEY))\s*[:=]\s*['\"]?([^'\"\s]+)")


def inline_credential(text: str) -> str | None:
    """A key that names a credential and carries a value that is not a file path, a variable, or a Docker secret name."""
    for match in CREDENTIAL_KEY.finditer(text):
        key, value = match.group(1), match.group(2)
        if key.endswith("_FILE") or value.startswith(("/", "$", "codestra-")):
            continue
        if len(value) >= 12 and re.search(r"[0-9]", value) and re.search(r"[A-Za-z]", value):
            return f"{key}"
    return None
PORT_LINE = re.compile(r'^\s*-\s*"?([0-9A-Za-z.:${}_-]+:\d+(?:/(?:tcp|udp))?)"?\s*$', re.MULTILINE)


def fail(message: str) -> None:
    print(f"MONITORING_PLATFORM_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def load_yaml(path: Path) -> Any:
    import yaml

    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")


def compose_files(platform: dict[str, Any]) -> list[Path]:
    candidates = [
        ROOT / "deploy" / "compose.yaml",
        CODESTRA / "deploy" / "compose.candidate.yaml",
        CODESTRA / "runtime-v1" / "compose.yaml",
        CODESTRA / "runtime-v1" / "compose-codestra.yaml",
    ]
    files = [path for path in candidates if path.is_file()]
    if not files:
        fail("no compose file found to validate listeners")
    return files


def validate_platform() -> dict[str, Any]:
    platform = load_json(PLATFORM)
    if platform.get("schemaVersion") != 1 or platform.get("plane") != "telemetry-data-plane":
        fail("monitoring platform declaration drifted")
    if platform.get("runtimeApplyAuthorized") is not False:
        fail("runtime apply must not be authorized from source")
    listener = platform.get("listener", {})
    if listener.get("hostPortPublished") is not False or listener.get("internetIngress") is not False:
        fail("exporter listeners must stay private")
    policy = platform.get("credentialPolicy", {})
    if policy.get("secretMaterialInGit") is not False:
        fail("secret material in Git must be declared false")
    if policy.get("credentialFree") is False and (not policy.get("openbaoWorkloadIdentity") or not policy.get("secretReferences")):
        fail("a credentialed exporter must name its OpenBao identity and secret references")
    if policy.get("credentialFree") is True and policy.get("openbaoWorkloadIdentity"):
        fail("a credential-free exporter must not claim an OpenBao identity")
    effects = platform.get("businessEffects", {})
    if effects.get("providerWrites") is not False or effects.get("businessApiCalls") is not False:
        fail("exporters never produce business effects")
    return platform


def validate_listeners(platform: dict[str, Any]) -> None:
    for path in compose_files(platform):
        text = path.read_text(encoding="utf-8")
        ports_block = re.search(r"(?ms)^\s*ports\s*:\s*\n((?:\s*-.*\n)+)", text)
        if ports_block:
            for match in PORT_LINE.finditer(ports_block.group(1)):
                binding = match.group(1)
                if not binding.startswith("127.0.0.1:"):
                    fail(f"{path.relative_to(ROOT)} publishes a non-loopback host port: {binding}")
        leaked = inline_credential(text)
        if leaked:
            fail(f"{path.relative_to(ROOT)} carries an inline credential for {leaked}")
        if "network_mode: host" in text and platform["service"] not in {"node-exporter", "cadvisor"}:
            fail(f"{path.relative_to(ROOT)} must not use host networking")
    env_example = ROOT / ".env.example"
    if env_example.is_file() and inline_credential(env_example.read_text(encoding="utf-8")):
        fail(".env.example carries an inline credential")


def reject_secret_material(value: Any, trail: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_REFERENCE_KEYS or str(key).lower().endswith(("_password", "_token", "_secret")):
                fail(f"secret reference carries a value-bearing key at {trail}.{key}")
            reject_secret_material(item, f"{trail}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_secret_material(item, f"{trail}[{index}]")
    elif isinstance(value, str) and (value.startswith("hvs.") or ("PRIVATE " + "KEY") in value):
        fail(f"secret-shaped value at {trail}")


def validate_secret_references(platform: dict[str, Any]) -> None:
    policy = platform["credentialPolicy"]
    if policy.get("credentialFree"):
        if SECRET_REFERENCES.exists():
            fail("a credential-free exporter must not declare secret references")
        return
    schema = load_json(SECRET_SCHEMA)
    pin = SECRET_SCHEMA_PIN.read_text(encoding="utf-8").strip()
    if hashlib.sha256(json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() != pin:
        fail("vendored secret-reference schema does not match its pin")
    document = load_json(SECRET_REFERENCES)
    identity = policy["openbaoWorkloadIdentity"]
    prefix = policy["openbaoPathPrefix"]
    if document.get("secretValuesIncluded") is not False or document.get("schemaSha256") != pin:
        fail("secret references must declare no values and bind the pinned schema")
    if document.get("authority", {}).get("workloadIdentity") != identity:
        fail(f"secret references must belong to the {identity} identity")
    reject_secret_material(document, "secret-references")
    covered: set[str] = set()
    environments: set[str] = set()
    for index, reference in enumerate(document.get("references", [])):
        trail = f"references[{index}]"
        for required in schema["required"]:
            if required not in reference:
                fail(f"{trail} missing {required}")
        env = reference["environment"]
        expected_prefix = prefix.replace("<environment>", env)
        if reference["provider"] != "openbao" or reference["workload_identity"] != identity:
            fail(f"{trail} must be an openbao reference readable by {identity}")
        if not reference["secret_ref"].startswith(expected_prefix):
            fail(f"{trail} must lie beneath {expected_prefix}")
        if reference.get("reference_uri") != "openbao://" + reference["secret_ref"]:
            fail(f"{trail} reference_uri must equal openbao:// + secret_ref")
        if reference["secret_class"] not in schema["properties"]["secret_class"]["enum"]:
            fail(f"{trail} has an unknown secret_class")
        environments.add(env)
        covered.update(reference.get("runtime_files", []))
    if environments != {"staging", "production"}:
        fail("secret references must cover exactly staging and production")
    for path in compose_files(platform):
        text = path.read_text(encoding="utf-8")
        for secret_file in sorted(set(re.findall(r"/run/secrets/[A-Za-z0-9_.-]+", text))):
            if secret_file not in covered:
                fail(f"{path.relative_to(ROOT)} reads {secret_file} without an OpenBao secret reference")


def validate_probe_policy(platform: dict[str, Any]) -> None:
    policy = platform.get("probePolicy")
    if not policy:
        return
    modules = load_yaml(ROOT / "config" / "blackbox.yml").get("modules", {})
    allowed_methods = set(policy["allowedHttpMethods"])
    for name, module in modules.items():
        prober = module.get("prober")
        if prober not in policy["allowedProbers"]:
            fail(f"blackbox module {name} uses an unreviewed prober {prober}")
        if prober == "http":
            method = str(module.get("http", {}).get("method", "GET")).upper()
            if method not in allowed_methods:
                fail(f"blackbox module {name} uses forbidden method {method}")
            if module.get("http", {}).get("body") or module.get("http", {}).get("body_file"):
                fail(f"blackbox module {name} must not send a body")
            if module.get("http", {}).get("tls_config", {}).get("insecure_skip_verify") is True:
                fail(f"blackbox module {name} must verify TLS")
    health = modules.get(policy["openbaoHealthModule"])
    if not health:
        fail("the OpenBao health module is missing")
    http = health.get("http", {})
    if http.get("method", "GET") != "GET" or http.get("valid_status_codes") != [200, 429]:
        fail("the OpenBao health module must be GET-only and accept only active (200) and standby (429)")
    checks = http.get("fail_if_body_not_matches_regexp", [])
    if not any("initialized" in c for c in checks) or not any("sealed" in c for c in checks):
        fail("the OpenBao health module must require initialized=true and sealed=false")


def main() -> None:
    platform = validate_platform()
    validate_listeners(platform)
    validate_secret_references(platform)
    validate_probe_policy(platform)
    print("MONITORING_PLATFORM=PASS")
    print(f"MONITORING_PLATFORM_SERVICE={platform['service']}")
    print(f"MONITORING_PLATFORM_CREDENTIAL_FREE={'YES' if platform['credentialPolicy']['credentialFree'] else 'NO'}")
    print("MONITORING_PLATFORM_PUBLIC_LISTENER=NONE")
    print("MONITORING_PLATFORM_SECRET_VALUES_IN_SOURCE=NONE")


if __name__ == "__main__":
    main()
