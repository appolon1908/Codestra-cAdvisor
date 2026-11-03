# Codestra cAdvisor

This repository is the service authority for container CPU, memory, filesystem, network, I/O, throttling, restart, OOM, lifecycle, and resource-limit telemetry. `appolon1908-hue/Codestra-Prometheus` owns scraping, canonical labels, recording rules, alerts, SLO evaluation, and retention.

## Privilege boundary

cAdvisor requires broad read access to host cgroups, Docker state, devices, and
runtime metadata. The reviewed topology does not grant privileged mode, host
networking, the host PID namespace, `/dev/kmsg`, or the Docker socket to
cAdvisor. A separate non-root proxy alone receives the read-only socket bind
and permits only the Docker metadata requests cAdvisor requires. Root filesystems
and host mounts are read-only, capabilities are dropped, and high-cost
process/TCP/scheduler metrics are disabled. This service is host infrastructure
and must never share a trust boundary with untrusted workloads.

The runtime suppresses all container labels by default and permits only the
seven deployment-owned `codestra.*` container labels in the repository contract.
Prometheus relabeling drops incomplete workloads plus raw container IDs, names,
image references, environment variables, credentials, and business payload
data.

No host port is published. The native cAdvisor listener is isolated on the
internal metrics network; only the mTLS metrics proxy joins the approved
observability network. `cadv.codestra.media` is an ownership/DNS identifier and
does not authorize a public Caddy/Kong route.

## Corporate metric contract

The source-controlled profile covers CPU, memory, network, filesystem, I/O, throttling, OOM, restart, and lifecycle indicators with normalized `codestra_business`, `application`, `service`, `environment`, `deployment`, `region`, and `server` dimensions. Noisy and ephemeral labels are dropped before storage.

See `codestra/enterprise-profile.v1.json` and `codestra/docs/CORPORATE-FEATURES.md` for the corporate feature model.

## Validation

Repository CI renders and inspects `codestra/deploy/compose.candidate.yaml`, proves immutable-image enforcement, read-only Docker API access, mTLS-only metrics exposure, read-only host mounts, label suppression, disabled profiling/high-cost metrics, and the absence of host or public port publication.

The cAdvisor image replaces the binary inherited from the locked upstream
runtime base with a binary compiled from the exact `upstream/` tree recorded in
`CODESTRA_UPSTREAM_LOCK.json`. Its version readback is
`v0.60.5-codestra.1 (6a0c4f2)`. Any upstream Go source change triggers the source
build and flag-compatibility gate.

A future approved deployment may use:

```bash
cp codestra/deploy/runtime.env.example .env
# Set accepted image digests, deployment identity, Docker socket GID, and
# external Docker secrets for the proxy certificate, key, and Prometheus CA.
set -a; . ./.env; set +a
python3 scripts/validate_runtime_images.py
docker compose --env-file .env -f codestra/deploy/compose.candidate.yaml config
docker compose --env-file .env -f codestra/deploy/compose.candidate.yaml up -d
docker compose --env-file .env -f codestra/deploy/compose.candidate.yaml ps
```

The Docker API proxy healthcheck performs `GET /healthz`, which succeeds only
after the proxy can complete Docker `/_ping`; a listening socket alone is not
readiness. The native cAdvisor listener is internal-only. Metrics must be tested
through `cadvisor-metrics-proxy:9443` from the observability network with the
approved Prometheus client certificate; plaintext or unauthenticated `curl` is
not a valid smoke test. These commands are documentation only during the
repository-first phase. Before Prometheus target activation, later deployment
evidence must prove private-only reachability, expected Docker workloads,
absence of environment/tenant labels, bounded sample cardinality, required
labels, mTLS scrape success, and rollback.

## Promotion and safety

Promotion is `feature/* -> development -> test -> staging -> production -> main`. Merging changes source authority only and does not deploy. `DEPLOYMENT_ENABLED=NO` remains binding until the 14-repository release manifest is accepted.

Automated upstream synchronization requires the repository Actions secret `CODESTRA_AUTOMATION_TOKEN`, backed by an approved GitHub App or fine-grained token with contents and pull-request permissions. The non-default token is required so generated review PRs trigger normal validation; absence of the secret fails the sync closed.
