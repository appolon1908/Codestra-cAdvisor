#!/usr/bin/env python3
"""Fail-closed validation for the Codestra cAdvisor corporate overlay."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
CODESTRA = ROOT / "codestra"
RUNTIME = CODESTRA / "runtime.v1.json"
LABEL_CONTRACT = CODESTRA / "container-label-contract.v1.json"
RELABEL = CODESTRA / "prometheus-metric-relabel.yml"
COMPOSE = CODESTRA / "deploy" / "compose.candidate.yaml"
PROXY_SOURCE = CODESTRA / "deploy" / "proxy.go"
PROXY_TEST = CODESTRA / "deploy" / "proxy_test.go"
HEALTHCHECK = CODESTRA / "deploy" / "healthcheck.go"
PROXY_DOCKERFILE = CODESTRA / "deploy" / "Dockerfile.proxy"
CADVISOR_DOCKERFILE = CODESTRA / "deploy" / "Dockerfile.cadvisor"
ENV_EXAMPLE = CODESTRA / "deploy" / "runtime.env.example"
OPERATING_MODEL = CODESTRA / "docs" / "OPERATING-MODEL.md"
RUNTIME_FEATURES = CODESTRA / "docs" / "RUNTIME-FEATURES.md"
RUNTIME_IMAGE_VALIDATOR = ROOT / "scripts" / "validate_runtime_images.py"
IMAGE_TEMPLATE = re.compile(
    r"^\$\{([A-Z][A-Z0-9_]*_IMAGE):\?[^}\r\n]+\}$"
)

BUSINESSES = {
    "platform",
    "codestra",
    "moneybee",
    "beyvra",
    "breero",
    "larim-a",
    "transportation",
    "booked4seasons",
    "social",
    "klyrow",
    "telnexa",
    "kyqra",
    "restaurant",
    "provisioning",
}
DOCKER_LABELS = {
    "codestra.business",
    "codestra.application",
    "codestra.service",
    "codestra.environment",
    "codestra.region",
    "codestra.deployment",
    "codestra.replica",
}
PROMETHEUS_LABELS = {
    "codestra_business",
    "application",
    "service",
    "environment",
    "region",
    "deployment",
    "replica",
    "server",
}
DISABLED_METRICS = {
    "advtcp",
    "cpu_topology",
    "cpuset",
    "hugetlb",
    "memory_numa",
    "perf_event",
    "process",
    "referenced_memory",
    "resctrl",
    "sched",
    "tcp",
    "udp",
}
REQUIRED_CADVISOR_FLAGS = {
    "--docker=tcp://docker-api-proxy:2375",
    "--docker_only=true",
    "--docker_root=/var/lib/docker",
    "--rootfs=/rootfs",
    "--listen_ip=0.0.0.0",
    "--port=8080",
    "--prometheus_endpoint=/metrics",
    "--housekeeping_interval=15s",
    "--max_housekeeping_interval=60s",
    "--allow_dynamic_housekeeping=true",
    "--global_housekeeping_interval=60s",
    "--storage_duration=2m",
    "--disable_root_cgroup_stats=true",
    "--store_container_labels=false",
    "--profiling=false",
    "--event_storage_event_limit=default=0",
    "--event_storage_age_limit=default=0",
}
REQUIRED_PROXY_TEST_CASES = {
    "ping",
    "versioned info",
    "container list",
    "container inspect",
    "container stats",
    "events",
    "image inspect",
    "network list",
    "network inspect",
    "head version",
    "create container",
    "delete container",
    "container archive",
    "unapproved query",
    "volume list",
    "exec list",
    "plugin list",
    "service list",
    "build endpoint",
    "request body",
    "connection upgrade",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_file(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(require_file(path))
    except Exception as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def load_yaml(path: pathlib.Path) -> Any:
    try:
        return yaml.safe_load(require_file(path))
    except Exception as exc:
        fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")


def validate_runtime() -> None:
    runtime = load_json(RUNTIME)
    if runtime.get("schemaVersion") != "1.0":
        fail("cAdvisor runtime schemaVersion must be 1.0")
    if runtime.get("component") != "cadvisor":
        fail("cAdvisor runtime component mismatch")
    if runtime.get("canonicalHostname") != "cadv.codestra.media":
        fail("canonical cAdvisor hostname mismatch")
    if runtime.get("exposure") != "internal_private":
        fail("cAdvisor exposure must remain internal_private")
    if runtime.get("status") != "CONFIG_PREPARED_NOT_DEPLOYED":
        fail("cAdvisor runtime must remain CONFIG_PREPARED_NOT_DEPLOYED")
    if set(runtime.get("businessScope", [])) != BUSINESSES:
        fail("cAdvisor runtime must exactly represent the approved business portfolio")

    topology = runtime.get("topology", {})
    if set(topology.get("services", [])) != {
        "docker-api-proxy",
        "cadvisor",
        "cadvisor-metrics-proxy",
    }:
        fail("cAdvisor three-service topology is incomplete")
    for field in (
        "cadvisorDirectDockerSocket",
        "cadvisorOnObservabilityNetwork",
        "dockerApiProxyOnObservabilityNetwork",
        "nativeHostPortsPublished",
    ):
        if topology.get(field) is not False:
            fail(f"cAdvisor topology boundary must remain false: {field}")
    for field in (
        "metricsProxyOnObservabilityNetwork",
        "internalDockerApiNetwork",
        "internalMetricsNetwork",
    ):
        if topology.get(field) is not True:
            fail(f"cAdvisor topology feature must remain true: {field}")

    docker_boundary = runtime.get("dockerApiBoundary", {})
    if set(docker_boundary.get("methods", [])) != {"GET", "HEAD"}:
        fail("Docker API proxy may allow only GET and HEAD")
    for field in (
        "containerCreate",
        "containerStartStopRestart",
        "containerExec",
        "containerArchive",
        "imageBuildPullPushRemove",
        "volumeMutation",
        "networkMutation",
        "swarmServiceMutation",
        "pluginMutation",
        "connectionUpgrade",
        "requestBodies",
    ):
        if docker_boundary.get(field) is not False:
            fail(f"Docker API mutation boundary must remain false: {field}")
    for field in ("concurrencyBounded", "queryKeysBounded"):
        if docker_boundary.get(field) is not True:
            fail(f"Docker API boundary must remain bounded: {field}")

    metrics_boundary = runtime.get("metricsBoundary", {})
    if metrics_boundary.get("tlsMinimumVersion") != "TLS13":
        fail("metrics proxy must require TLS 1.3")
    for field in (
        "prometheusClientCertificateRequired",
        "otherPathsDenied",
        "queryStringsDenied",
        "writeMethodsDenied",
        "rawCadvisorPortPrivate",
    ):
        if metrics_boundary.get(field) is not True:
            fail(f"metrics proxy boundary must remain true: {field}")

    identity = runtime.get("containerIdentity", {})
    if set(identity.get("whitelistedDockerLabels", [])) != DOCKER_LABELS:
        fail("runtime Docker-label allowlist mismatch")
    for field in (
        "storeAllDockerLabels",
        "containerIdsRetainedAfterRelabel",
        "containerNamesRetainedAfterRelabel",
        "imageReferencesRetainedAfterRelabel",
        "arbitraryDockerLabelsRetainedAfterRelabel",
    ):
        if identity.get(field) is not False:
            fail(f"container identity/cardinality boundary must remain false: {field}")
    if identity.get("unknownOrIncompleteContainersDroppedByPrometheus") is not True:
        fail("unknown/incomplete containers must be dropped")

    disabled = set(runtime.get("metricFamilies", {}).get("disabled", []))
    if disabled != DISABLED_METRICS:
        fail("disabled cAdvisor metric-family list mismatch")
    host_access = runtime.get("hostAccess", {})
    for field in ("devKmsg", "hostNetwork", "hostPidNamespace", "privilegedMode"):
        if host_access.get(field) is not False:
            fail(f"cAdvisor host-access boundary must remain false: {field}")
    if host_access.get("cadvisorRunsAsContainerRoot") is not True:
        fail("runtime must honestly record cAdvisor's container-root compatibility requirement")
    if host_access.get("cadvisorLinuxCapabilities") != []:
        fail("cAdvisor must run with no Linux capabilities")

    activation = runtime.get("activation", {})
    if not activation or any(value is not False for value in activation.values()):
        fail("all cAdvisor activation gates must remain false before evidence exists")


def validate_label_contract() -> None:
    contract = load_json(LABEL_CONTRACT)
    if contract.get("schemaVersion") != "1.0":
        fail("container-label contract schemaVersion must be 1.0")
    if contract.get("status") != "CONTRACT_PREPARED_NOT_ENFORCED":
        fail("container-label contract must remain prepared, not enforced")
    if set(contract.get("businessScope", [])) != BUSINESSES:
        fail("container-label contract business catalogue mismatch")
    if set(contract.get("requiredDockerLabels", [])) != DOCKER_LABELS:
        fail("required Docker labels do not match the corporate contract")
    if set(contract.get("prometheusLabels", [])) != PROMETHEUS_LABELS:
        fail("Prometheus labels do not match the corporate contract")

    rules = contract.get("valueRules", {})
    if set(rules) != DOCKER_LABELS:
        fail("container-label value rules are incomplete")
    if rules["codestra.business"].get("allowedValuesFrom") != "businessScope":
        fail("business label must be constrained to the business catalogue")
    if set(rules["codestra.environment"].get("allowedValues", [])) != {
        "development",
        "test",
        "staging",
        "production",
    }:
        fail("environment label allowlist mismatch")
    for label in DOCKER_LABELS - {"codestra.business", "codestra.environment"}:
        expression = rules[label].get("regex")
        if not expression or not expression.startswith("^") or not expression.endswith("$"):
            fail(f"container-label rule must be anchored: {label}")

    ownership = contract.get("ownership", {})
    for field in (
        "labelsSetByDeploymentAuthority",
        "applicationMayNotOverrideBusiness",
        "unknownOrIncompleteContainersDroppedFromCorporateMetrics",
    ):
        if ownership.get(field) is not True:
            fail(f"container-label ownership rule must remain true: {field}")
    if ownership.get("customerOrUserInputAllowed") is not False:
        fail("customer/user input may not set container identity labels")

    cardinality = contract.get("cardinality", {})
    for field in (
        "containerIdsRetained",
        "containerNamesRetained",
        "imageReferencesRetained",
        "arbitraryDockerLabelsRetained",
    ):
        if cardinality.get(field) is not False:
            fail(f"container-cardinality boundary must remain false: {field}")
    for field in (
        "maximumApplicationsPerBusinessPerEnvironment",
        "maximumServicesPerApplicationPerEnvironment",
        "maximumReplicasPerServicePerEnvironment",
    ):
        value = cardinality.get(field)
        if not isinstance(value, int) or value <= 0 or value > 1000:
            fail(f"invalid cardinality budget: {field}")


def validate_relabel_contract() -> None:
    actions = load_yaml(RELABEL)
    if not isinstance(actions, list) or len(actions) < 10:
        fail("Prometheus metric relabel contract is incomplete")
    for item in actions:
        if not isinstance(item, dict) or not item.get("action"):
            fail("invalid Prometheus metric relabel action")

    keep_actions = [item for item in actions if item.get("action") == "keep"]
    if len(keep_actions) != 2:
        fail("metric relabel contract must have exactly two keep gates")
    if keep_actions[0].get("source_labels") != ["container_label_codestra_business"]:
        fail("first relabel keep gate must validate business")
    for business in BUSINESSES:
        if business not in keep_actions[0].get("regex", ""):
            fail(f"business missing from cAdvisor relabel allowlist: {business}")

    required_sources = [
        "container_label_codestra_application",
        "container_label_codestra_service",
        "container_label_codestra_environment",
        "container_label_codestra_region",
        "container_label_codestra_deployment",
        "container_label_codestra_replica",
    ]
    if keep_actions[1].get("source_labels") != required_sources:
        fail("second relabel keep gate must validate every required container label")

    replacements = {
        item.get("target_label"): item.get("source_labels")
        for item in actions
        if item.get("action") == "replace"
    }
    expected_replacements = {
        "codestra_business": ["container_label_codestra_business"],
        "application": ["container_label_codestra_application"],
        "service": ["container_label_codestra_service"],
        "environment": ["container_label_codestra_environment"],
        "region": ["container_label_codestra_region"],
        "deployment": ["container_label_codestra_deployment"],
        "replica": ["container_label_codestra_replica"],
    }
    if replacements != expected_replacements:
        fail("cAdvisor relabel replacements do not match the corporate label contract")

    labeldrops = [item.get("regex", "") for item in actions if item.get("action") == "labeldrop"]
    for required in ("container_label_.*", "container_env_.*"):
        if required not in labeldrops:
            fail(f"cAdvisor relabel contract must drop {required}")
    if not any("id|name|image" in expression for expression in labeldrops):
        fail("cAdvisor relabel contract must drop runtime identity labels")


def validate_proxy_source_and_tests() -> None:
    source = require_file(PROXY_SOURCE)
    required_source_fragments = (
        'modeDockerAPI = "docker-api"',
        'modeMetrics   = "metrics-mtls"',
        "request.Method != http.MethodGet && request.Method != http.MethodHead",
        'request.Header.Get("Upgrade")',
        'path == "/containers/json"',
        'path == "/events"',
        "containerInspect.MatchString(path)",
        "containerStats.MatchString(path)",
        "imageInspect.MatchString(path)",
        "networkInspect.MatchString(path)",
        'http.Error(w, "Docker API operation denied", http.StatusForbidden)',
        "tls.VersionTLS13",
        "tls.RequireAndVerifyClientCert",
        'r.URL.Path != "/metrics" && r.URL.Path != "/healthz"',
        "withConcurrencyLimit",
        "MaxHeaderBytes",
    )
    for fragment in required_source_fragments:
        if fragment not in source:
            fail(f"cAdvisor proxy source is missing security behavior: {fragment}")
    for forbidden in (
        "InsecureSkipVerify: true",
        "tls.NoClientCert",
        "http.MethodPost",
        "http.MethodPut",
        "http.MethodDelete",
        "http.MethodPatch",
        "os/exec",
        "exec.Command",
    ):
        if forbidden in source:
            fail(f"cAdvisor proxy source contains forbidden behavior: {forbidden}")

    tests = require_file(PROXY_TEST)
    for name in REQUIRED_PROXY_TEST_CASES:
        if f'name: "{name}"' not in tests:
            fail(f"cAdvisor proxy tests omit case: {name}")
    if "allowedDockerRequest" not in tests:
        fail("cAdvisor proxy tests do not exercise the allowlist function")


def validate_compose() -> None:
    compose = load_yaml(COMPOSE)
    services = compose.get("services", {})
    if set(services) != {
        "docker-api-proxy",
        "cadvisor",
        "cadvisor-metrics-proxy",
    }:
        fail("Compose candidate must define the three-service cAdvisor topology")

    networks = compose.get("networks", {})
    if networks.get("cadvisor-docker-api", {}).get("internal") is not True:
        fail("Docker API network must be internal")
    if networks.get("cadvisor-metrics", {}).get("internal") is not True:
        fail("cAdvisor metrics network must be internal")
    if networks.get("codestra-observability", {}).get("external") is not True:
        fail("observability network must be external")

    for name, service in services.items():
        if service.get("read_only") is not True:
            fail(f"service root filesystem must be read-only: {name}")
        if service.get("privileged") is True or service.get("network_mode") == "host":
            fail(f"service may not use privileged or host-network mode: {name}")
        if service.get("pid") == "host":
            fail(f"service may not use host PID namespace: {name}")
        if service.get("ports"):
            fail(f"service may not publish host ports: {name}")
        if "ALL" not in service.get("cap_drop", []):
            fail(f"service must drop all Linux capabilities: {name}")
        if "no-new-privileges:true" not in service.get("security_opt", []):
            fail(f"service must set no-new-privileges: {name}")
        if not service.get("healthcheck"):
            fail(f"service requires a healthcheck: {name}")
        limits = service.get("deploy", {}).get("resources", {}).get("limits", {})
        for field in ("cpus", "memory", "pids"):
            if field not in limits:
                fail(f"service {name} is missing resource limit {field}")
        labels = service.get("labels", {})
        for label in DOCKER_LABELS:
            if label not in labels:
                fail(f"managed cAdvisor service {name} is missing label {label}")

    docker_proxy = services["docker-api-proxy"]
    if set(docker_proxy.get("networks", [])) != {"cadvisor-docker-api"}:
        fail("Docker API proxy must attach only to its internal network")
    if docker_proxy.get("environment", {}).get("CODESTRA_PROXY_MODE") != "docker-api":
        fail("Docker API proxy mode mismatch")
    if docker_proxy.get("user", "").split(":", 1)[0] != "65532":
        fail("Docker API proxy must run as the non-root proxy UID")
    if not docker_proxy.get("group_add"):
        fail("Docker API proxy requires the explicit Docker socket group")
    docker_proxy_targets = {
        item.get("target")
        for item in docker_proxy.get("volumes", [])
        if isinstance(item, dict)
    }
    if docker_proxy_targets != {"/var/run/docker.sock"}:
        fail("Docker API proxy must mount only the Docker socket")
    for item in docker_proxy.get("volumes", []):
        if item.get("read_only") is not True:
            fail("Docker socket bind must be read-only")

    cadvisor = services["cadvisor"]
    if set(cadvisor.get("networks", [])) != {"cadvisor-docker-api", "cadvisor-metrics"}:
        fail("cAdvisor must attach only to the two internal networks")
    if cadvisor.get("user") != "0:0":
        fail("cAdvisor compatibility candidate must honestly run as container root")
    if cadvisor.get("devices"):
        fail("cAdvisor may not receive host devices such as /dev/kmsg")
    command = {str(item) for item in cadvisor.get("command", [])}
    missing_flags = REQUIRED_CADVISOR_FLAGS - command
    if missing_flags:
        fail(f"cAdvisor command is missing flags: {sorted(missing_flags)}")
    whitelist_flags = [item for item in command if item.startswith("--whitelisted_container_labels=")]
    if len(whitelist_flags) != 1:
        fail("cAdvisor must define exactly one Docker-label whitelist")
    whitelisted = set(whitelist_flags[0].split("=", 1)[1].split(","))
    if whitelisted != DOCKER_LABELS:
        fail("cAdvisor Docker-label whitelist mismatch")
    disabled_flags = [item for item in command if item.startswith("--disable_metrics=")]
    if len(disabled_flags) != 1 or set(disabled_flags[0].split("=", 1)[1].split(",")) != DISABLED_METRICS:
        fail("cAdvisor disabled metric-family list mismatch")
    cadvisor_targets = {
        item.get("target")
        for item in cadvisor.get("volumes", [])
        if isinstance(item, dict)
    }
    if cadvisor_targets != {"/rootfs", "/sys", "/var/lib/docker", "/dev/disk"}:
        fail("cAdvisor read-only host-mount allowlist mismatch")
    for item in cadvisor.get("volumes", []):
        if item.get("read_only") is not True:
            fail(f"cAdvisor host bind must be read-only: {item.get('target')}")

    metrics_proxy = services["cadvisor-metrics-proxy"]
    if set(metrics_proxy.get("networks", [])) != {"cadvisor-metrics", "codestra-observability"}:
        fail("metrics proxy network boundary mismatch")
    if metrics_proxy.get("environment", {}).get("CODESTRA_PROXY_MODE") != "metrics-mtls":
        fail("metrics proxy mode mismatch")
    if metrics_proxy.get("user") != "65532:65532":
        fail("metrics proxy must run as the non-root proxy UID/GID")
    if set(metrics_proxy.get("secrets", [])) != {
        "cadvisor_proxy_server_cert",
        "cadvisor_proxy_server_key",
        "prometheus_client_ca",
    }:
        fail("metrics proxy mTLS secret-file contract is incomplete")

    socket_consumers = []
    for name, service in services.items():
        for item in service.get("volumes", []):
            if isinstance(item, dict) and item.get("target") == "/var/run/docker.sock":
                socket_consumers.append(name)
    if socket_consumers != ["docker-api-proxy"]:
        fail(f"Docker socket consumer mismatch: {socket_consumers}")

    expected_service_images = {
        "docker-api-proxy": "CODESTRA_CADVISOR_PROXY_IMAGE",
        "cadvisor": "CODESTRA_CADVISOR_IMAGE",
        "cadvisor-metrics-proxy": "CODESTRA_CADVISOR_PROXY_IMAGE",
    }
    for name, service in services.items():
        image = str(service.get("image", ""))
        match = IMAGE_TEMPLATE.fullmatch(image)
        if not match or match.group(1) != expected_service_images[name]:
            fail(f"service image must use its fail-closed image variable: {name}")
    if set(docker_proxy.get("build", {}).get("args", {})) != {
        "GO_BUILDER_IMAGE",
        "PROXY_RUNTIME_IMAGE",
    }:
        fail("proxy build must pin builder and runtime images")
    if set(cadvisor.get("build", {}).get("args", {})) != {
        "GO_BUILDER_IMAGE",
        "CADVISOR_BASE_IMAGE",
    }:
        fail("cAdvisor build must pin builder and upstream images")
    for service_name in ("docker-api-proxy", "cadvisor"):
        for variable, expression in services[service_name]["build"]["args"].items():
            match = IMAGE_TEMPLATE.fullmatch(str(expression))
            if not match or match.group(1) != variable:
                fail(f"build image argument must fail closed: {service_name}/{variable}")

    serialized = COMPOSE.read_text(encoding="utf-8")
    for forbidden in (
        ":latest",
        "privileged: true",
        "network_mode: host",
        "pid: host",
        "/dev/kmsg",
        "0.0.0.0:8080:8080",
        "0.0.0.0:9443:9443",
    ):
        if forbidden in serialized:
            fail(f"cAdvisor runtime contains forbidden content: {forbidden}")


def validate_packaging_docs_and_secrets() -> None:
    proxy_dockerfile = require_file(PROXY_DOCKERFILE)
    for fragment in (
        "ARG GO_BUILDER_IMAGE",
        "ARG PROXY_RUNTIME_IMAGE",
        "CGO_ENABLED=0",
        "-trimpath",
        "/codestra-cadvisor-proxy",
        "/codestra-healthcheck",
        "USER 65532:65532",
    ):
        if fragment not in proxy_dockerfile:
            fail(f"proxy Dockerfile is missing {fragment}")

    cadvisor_dockerfile = require_file(CADVISOR_DOCKERFILE)
    for fragment in (
        "ARG GO_BUILDER_IMAGE",
        "ARG CADVISOR_BASE_IMAGE",
        "CGO_ENABLED=0",
        "-trimpath",
        "/codestra-healthcheck",
        "COPY upstream/ ./",
        "/out/cadvisor /usr/bin/cadvisor",
        "Revision=6a0c4f2",
        "USER 0:0",
    ):
        if fragment not in cadvisor_dockerfile:
            fail(f"cAdvisor Dockerfile is missing {fragment}")
    if ":latest" in proxy_dockerfile or ":latest" in cadvisor_dockerfile:
        fail("cAdvisor Dockerfiles may not use latest tags")

    healthcheck = require_file(HEALTHCHECK)
    for fragment in (
        "CODESTRA_HEALTHCHECK_URL",
        "checkHTTP(endpoint)",
        "response.StatusCode < 200 || response.StatusCode >= 300",
        "http.ErrUseLastResponse",
        "net.DialTimeout",
    ):
        if fragment not in healthcheck:
            fail(f"cAdvisor healthcheck omits fail-closed readiness: {fragment}")
    if "os/exec" in healthcheck or "exec.Command" in healthcheck:
        fail("cAdvisor healthcheck may not invoke a shell")

    require_file(RUNTIME_IMAGE_VALIDATOR)

    env_text = require_file(ENV_EXAMPLE)
    for fragment in (
        "CODESTRA_CADVISOR_DEPLOYMENT_ID=",
        "GO_BUILDER_IMAGE=",
        "PROXY_RUNTIME_IMAGE=",
        "CADVISOR_BASE_IMAGE=",
        "CODESTRA_CADVISOR_PROXY_IMAGE=",
        "CODESTRA_CADVISOR_IMAGE=",
        "DOCKER_SOCKET_GID=",
        "CADVISOR_DOCKER_ROOT_PATH=",
        "CADVISOR_PROXY_SERVER_CERT_SECRET_NAME=",
        "CADVISOR_PROXY_SERVER_KEY_SECRET_NAME=",
        "PROMETHEUS_CLIENT_CA_SECRET_NAME=",
    ):
        if fragment not in env_text:
            fail(f"cAdvisor runtime example omits {fragment}")

    require_file(OPERATING_MODEL)
    require_file(RUNTIME_FEATURES)

    dash = chr(45) * 5
    signatures = (
        dash + "BEGIN " + "PRIVATE" + chr(32) + "KEY" + dash,
        dash + "BEGIN " + "OPENSSH" + chr(32) + "PRIVATE" + chr(32) + "KEY" + dash,
        "A" + "K" + "I" + "A",
    )
    for path in CODESTRA.rglob("*"):
        if not path.is_file() or path.suffix == ".pyc" or "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for signature in signatures:
            if signature in text:
                fail(f"secret-shaped material found in {path.relative_to(ROOT)}")


def main() -> None:
    validate_runtime()
    validate_label_contract()
    validate_relabel_contract()
    validate_proxy_source_and_tests()
    validate_compose()
    validate_packaging_docs_and_secrets()
    print("Codestra cAdvisor corporate configuration validation PASS")


if __name__ == "__main__":
    main()
