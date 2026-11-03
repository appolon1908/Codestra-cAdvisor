# Codestra cAdvisor Runtime Features

## Corporate container monitoring

- CPU, throttling, memory, OOM, filesystem, block-I/O and network metrics;
- one canonical business, application, service, environment, region, deployment and replica identity per managed container;
- bounded Prometheus metric relabeling that drops unknown/incomplete containers;
- removal of container IDs, names, images and arbitrary Docker labels after attribution;
- disabled high-cardinality process, TCP/UDP, scheduler, perf, NUMA and topology families;
- no root-cgroup duplication of Node Exporter host metrics;
- no profiling or in-memory event history;
- private health and metrics paths only.

## Docker access protection

- cAdvisor never mounts the Docker socket;
- a dedicated proxy is the only socket consumer;
- only GET/HEAD metadata and statistics paths are allowed;
- request bodies, connection upgrades and unapproved query keys are denied;
- all container/image/network/volume/service/plugin mutations are denied;
- the proxy has no public or observability-network access;
- exact allow and deny behavior is covered by Go unit tests.

## Prometheus access protection

- cAdvisor has no direct observability-network access;
- a dedicated metrics proxy exposes only `/metrics` and `/healthz`;
- TLS 1.3 and Prometheus client-certificate authentication are required;
- plaintext, no-certificate, wrong-CA, write-method, query-string and unapproved-path requests are denied;
- server certificate, private key and client CA are external secret files.

## Runtime hardening

- immutable builder, proxy runtime, cAdvisor base and final image references;
- optional private-registry ports validated as integers in the TCP range
  `1..65535` before Compose rendering or image access;
- read-only root filesystems;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- no privileged mode;
- no host network;
- no host PID namespace;
- no `/dev/kmsg` device;
- read-only host root, `/sys`, Docker data-root and device-metadata mounts;
- internal-only Docker API and metrics networks;
- native static health probes;
- CPU, memory and PID limits;
- all activation gates false until staging evidence exists.

## Codestra portfolio representation

The container-label contract supports shared platform services and all managed businesses: Codestra, MoneyBee, Beyvra Trading, Breero, LARIM-A, Transportation and Freight, Booked4Seasons, Codestra Social, Klyrow Email, Telnexa Messaging, Kyqra, Restaurant Platform and Codestra Provisioning.

## Deliberate non-features

cAdvisor does not:

- expose a public dashboard or host port;
- control containers or Docker resources;
- keep all Docker labels;
- retain customer, user, request, trace or message identifiers as metric labels;
- replace Node Exporter host metrics;
- replace OpenTelemetry application metrics/traces;
- replace Alloy/Loki logging;
- evaluate SLOs or route alerts;
- send communications or run workflows;
- write Odoo or provider state;
- expose broker/exchange credentials or authoritative financial state;
- place, modify, cancel or approve a trade.
