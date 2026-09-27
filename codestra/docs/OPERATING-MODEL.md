# Codestra cAdvisor Operating Model

## Corporate role

cAdvisor is the authoritative container resource-metrics source for Codestra servers. It exposes CPU, memory, filesystem, block-I/O, network, OOM and lifecycle evidence for containers and supplies bounded deployment-owned labels so Prometheus, Grafana and Alertmanager can attribute a condition to the correct Codestra business, application, service, environment, region, deployment and replica.

cAdvisor does not own:

- host metrics, which belong to Node Exporter;
- application metrics or traces, which belong to OpenTelemetry;
- logs, which belong to Alloy and Loki;
- synthetic endpoint checks, which belong to Blackbox Exporter;
- recording rules, SLOs or alerts, which belong to Prometheus;
- incident routing, which belongs to Alertmanager;
- business or container mutation.

## Three-service security topology

The runtime separates Docker control-plane access, container metric collection and Prometheus exposure:

```text
Docker socket
    ↓
read-only Docker API proxy
    ↓ private internal network
cAdvisor
    ↓ private internal network
TLS 1.3 client-auth metrics proxy
    ↓ private observability network
Prometheus
```

### Docker API proxy

Only the proxy mounts `/var/run/docker.sock`. The proxy:

- accepts only `GET` and `HEAD`;
- permits a narrow metadata/statistics allowlist;
- rejects request bodies, connection upgrades and unapproved query keys;
- denies container create, start, stop, restart, remove, exec, archive and attach operations;
- denies image build, pull, push and removal;
- denies volume, network, service, plugin and swarm mutation;
- bounds request concurrency, headers, query values and upstream timeouts;
- exposes no host or observability-network port.

The socket bind is read-only, but the HTTP allowlist is the actual mutation boundary. A read-only socket bind alone is not considered protection.

### cAdvisor

cAdvisor receives Docker metadata through the proxy and never mounts the Docker socket. It is connected only to the private Docker-API and private metrics networks. It is not connected directly to Prometheus or the public edge.

cAdvisor requires broad read-only views of:

- host root filesystem at `/rootfs`;
- `/sys`, including cgroups;
- Docker data root;
- `/dev/disk` metadata.

Because these paths are commonly root-readable, cAdvisor runs as UID 0 **inside** a non-privileged container with all Linux capabilities dropped, `no-new-privileges`, read-only root filesystem, no host network, no host PID namespace and no `/dev/kmsg`. This is a constrained compatibility candidate, not a claim that root inside a container is harmless. Production is blocked until host-access and denial tests prove the boundary on every server class.

### Metrics proxy

Only the metrics proxy joins the shared observability network. It:

- requires TLS 1.3;
- requires a Prometheus client certificate signed by the configured CA;
- permits only `GET` and `HEAD` for `/metrics` and `/healthz`;
- rejects query strings, write methods and other paths;
- strips cookies and sets no-store/security headers;
- reaches cAdvisor only on the private metrics network.

The cAdvisor native port remains private and is never a public DNS or host listener.

## Container identity and business isolation

Every managed container must carry:

- `codestra.business`
- `codestra.application`
- `codestra.service`
- `codestra.environment`
- `codestra.region`
- `codestra.deployment`
- `codestra.replica`

These labels are set by deployment authority, never by customer or user input. `codestra.business` must be one approved portfolio ID.

cAdvisor stores only the seven whitelisted Docker labels. Prometheus metric relabeling:

1. drops containers whose business is unknown;
2. drops containers missing any required label;
3. validates bounded label syntax;
4. maps the Docker labels to the canonical corporate metric labels;
5. removes every raw `container_label_*` and `container_env_*` label;
6. removes container IDs, names, image references, pod/namespace identity and other runtime identifiers.

`replica` is required so IDs can be removed without merging multiple replicas into the same time series. Cross-business and duplicate-series tests are production gates.

## Metric scope and cardinality

The runtime keeps core resource families needed for operational decisions:

- CPU and per-CPU usage;
- load where supported;
- memory, working set, failures and OOM evidence;
- filesystem and disk I/O;
- network traffic, errors and drops;
- container lifecycle/last-seen evidence.

Expensive or high-cardinality families are disabled unless a future evidence-backed release changes the policy: advanced TCP, CPU topology, cpuset, huge pages, NUMA memory, perf events, per-process metrics, referenced memory, resctrl, scheduler, TCP and UDP detail.

Event storage and profiling are disabled. Root-cgroup stats are disabled because Node Exporter owns host metrics.

Prometheus recording rules should derive bounded service/replica views for:

- CPU saturation and throttling;
- memory pressure and OOM activity;
- filesystem usage and write pressure;
- block-I/O latency/throughput;
- network errors, drops and traffic;
- missing/restarted containers;
- container metric scrape health and cardinality.

## Secrets and certificates

The metrics-proxy server certificate, private key and Prometheus client CA are external runtime secret files. The proxy image contains no secret values. Certificate issuance, rotation and revocation belong to the approved PKI authority.

The Docker API proxy does not receive application credentials. Docker metadata can still reveal image names, labels and topology, so its internal network and logs are treated as sensitive platform data.

## Initial engineering objectives

Subject to staging calibration:

- private scrape availability at least 99.9%;
- scrape p95 below 10 seconds;
- collection-to-Prometheus freshness below 30 seconds;
- zero public or host-published cAdvisor/proxy ports;
- zero direct cAdvisor Docker-socket access;
- zero accepted Docker mutation requests;
- zero no-certificate or plaintext metric scrapes;
- zero unapproved or incomplete containers in corporate metrics;
- zero duplicate series after container identity removal;
- cAdvisor CPU below 20% of one core and memory below the approved limit at expected container count;
- cardinality within the Prometheus target budget;
- metric proxy and Docker proxy error rates visible in logs and self-monitoring.

These are engineering objectives, not production SLOs until load, isolation and failure evidence exists.

## Required staging evidence

1. Build immutable proxy and cAdvisor images and record all digests.
2. Build the cAdvisor binary from the repository's locked upstream source.
3. Prove every configured cAdvisor flag exists in that exact source.
4. Unit-test all Docker API allow and deny cases.
5. Start the Docker proxy against a disposable Docker-compatible socket and prove allowed reads and denied mutations.
6. Start cAdvisor without privileged mode, host network, host PID namespace or `/dev/kmsg`.
7. Prove the native cAdvisor port is unreachable from the observability network.
8. Prove the metrics proxy accepts a valid Prometheus certificate and rejects no-cert, wrong-CA and plaintext requests.
9. Validate required labels for every managed container class.
10. Prove unknown/incomplete containers are dropped.
11. Prove IDs, names, images and arbitrary Docker labels are absent after metric relabeling.
12. Run duplicate-series, cardinality and peak-container load tests.
13. Verify Prometheus recording rules, Grafana dashboards and Alertmanager ownership metadata.
14. Record rollback instructions and previous immutable image digests.

## Release boundary

Promotion is:

```text
feature/* -> development -> test -> staging -> production -> main
```

`CONFIG_PREPARED_NOT_DEPLOYED` remains the source state. Merge or CI success does not mount the Docker socket or host filesystems, issue certificates, create networks, start any service, expose a port, activate Prometheus scraping or authorize any container/business mutation.
