# Codestra cAdvisor Production Server and Native API Contract

## Authority

- Repository: `appolon1908-hue/Codestra-cAdvisor`
- Role: container resource-metrics authority
- Canonical hostname: `cadv.codestra.media`
- Central production host: `37.27.128.39`
- Core host `65.109.65.169`: separate approved exporter installation after central certification
- Status: `SOURCE_CONTRACT_PREPARED_NOT_DEPLOYED`

cAdvisor owns container CPU, memory, I/O, network, OOM, restart, and throttling metrics; controlled container-label policy; image/release evidence; and rollback. It does not own Docker mutation, host metrics, application telemetry, or business actions.

## Native API surface

| Methods | Path | Purpose | Boundary |
|---|---|---|---|
| `GET`, `HEAD` | `/healthz` | external proxy health | private mTLS client required |
| `GET`, `HEAD` | `/metrics` | container resource metrics | private mTLS Prometheus scrape |

The in-container health check may call the cAdvisor upstream on loopback without a client certificate. Any external caller reaches the source-controlled metrics proxy, which requires and verifies a client certificate for both `/healthz` and `/metrics`.

Unexpected `404`, `5xx`, public port `8080`, privileged mutation access, writable Docker socket access, missing HEAD support, or sensitive/high-cardinality data retained after Prometheus relabeling blocks production.

## Runtime and label policy

- Native ports remain private.
- Required host mounts are read-only and explicitly reviewed.
- Direct writable Docker socket access is forbidden. A constrained read-only metadata proxy may be used only when source-controlled and tested.
- Privileged mode, host PID, and host network are prohibited unless separately justified and approved; the normal profile uses none of them.
- Arbitrary Docker labels are disabled; only the reviewed Codestra labels—business, application, service, environment, region, deployment, and bounded replica identity—may be copied from container metadata.
- cAdvisor still emits native base container identity labels such as `id`, `name`, and `image`. These values are protected as private mTLS-only operational metadata and are not claimed absent from the native response.
- The source-controlled Prometheus `metric_relabel_configs` boundary must remove `id`, `name`, `image`, container IDs, image IDs, pod UIDs, and other forbidden identity/cardinality labels before authoritative metric storage.
- Customer IDs, users, emails, phones, requests, traces, messages, orders, payments, and transaction IDs must appear neither on the native endpoint nor after relabeling.

## Production gates

```text
PROTECTED_PRODUCTION_SHA=PASS
READ_ONLY_HOST_MOUNTS=PASS
DOCKER_METADATA_BOUNDARY=PASS
DOCKER_WRITE_AUTHORITY=NO
PRIVILEGED_MODE=NO
HOST_NETWORK=NO
HOST_PID=NO
METHOD_ALLOWLIST_GET_HEAD=PASS
HEALTHZ_EXTERNAL_MTLS=PASS
METRICS_EXTERNAL_MTLS=PASS
DOCKER_LABEL_ALLOWLIST=PASS
NATIVE_BASE_IDENTITY_LABELS_PRIVATE=PASS
PROMETHEUS_METRIC_RELABEL=PASS
POST_RELABEL_CARDINALITY_LIMITS=PASS
IMMUTABLE_IMAGE_DIGEST=PASS
IMAGE_SIGNATURE=PASS
SBOM=PASS
PROVENANCE=PASS
SECRET_SCAN=PASS
ROLLBACK_MANIFEST=PASS
```

## Runtime certification

```text
GET_/healthz=PASS
HEAD_/healthz=PASS
GET_/metrics=PASS
HEAD_/metrics=PASS
UNAUTHENTICATED_HEALTHZ_DENIED=PASS
UNAUTHENTICATED_SCRAPE_DENIED=PASS
MTLS_CLIENT_VERIFY_HEALTHZ=PASS
MTLS_CLIENT_VERIFY_METRICS=PASS
CONTAINER_CPU_MEMORY_IO_NETWORK=PASS
OOM_AND_THROTTLING_METRICS=PASS
NATIVE_ID_NAME_IMAGE_LABELS_PRIVATE=PASS
POST_PROMETHEUS_RELABEL_SENSITIVE_IDENTITY_LABELS=0
POST_PROMETHEUS_RELABEL_HIGH_CARDINALITY_LABELS=0
DOCKER_WRITE_TEST=DENIED
UNEXPECTED_404=0
UNEXPECTED_5XX=0
SOURCE_RUNTIME_DRIFT=0
```

Certification must inspect both the private native response and the Prometheus-stored series. It must not falsely report native `id`, `name`, or `image` labels as absent when the privacy control is actually implemented at the reviewed Prometheus relabel boundary.

## Repository-first remediation

Stop the affected wave and preserve the prior healthy cAdvisor runtime on failure. Fix source/configuration here, add regression tests, commit/push, obtain exact-head CI/review, merge normally, build/sign an immutable image, update the BOM, and retry. Do not patch Compose or mounts only on the server. Changes to Prometheus-owned metric relabeling must be made and reviewed in `appolon1908-hue/Codestra-Prometheus`.

## Safety

This document does not deploy cAdvisor or activate scrapes. SSH changes, business writes, communications delivery, provider effects, lending, payments, and trading remain outside scope and disabled.