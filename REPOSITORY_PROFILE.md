# Repository Profile — `Codestra-cAdvisor`

## Identity

- **Repository:** `appolon1908-hue/Codestra-cAdvisor`
- **Category:** Observability exporter — container metrics
- **Visibility:** `public`
- **Default branch:** `main`
- **Canonical hostname:** `cadv.codestra.media`
- **Exposure:** Internal/private only; no public native metrics endpoint
- **Authority:** Primary container CPU, memory, filesystem, network, I/O, throttling, OOM, and lifecycle metrics authority

## Purpose

Exports bounded container-resource metrics to Prometheus while minimizing Docker-socket risk and dropping unsafe/high-cardinality runtime identity data.

## Owns

- cAdvisor runtime and approved container metric families
- Read-only Docker metadata boundary and isolated metrics proxy design
- Deployment-owned business/application/service/environment labels and Prometheus relabeling policy

## Does not own

- Docker mutation or container control
- Host-level Node Exporter metrics
- Arbitrary Docker labels, environment values, image references, customer data, or business payloads

## Key integrations

- Prometheus
- Grafana container-health dashboards
- Docker runtime through a constrained read-only proxy
- Infrastructure-managed mTLS and private networks

## Current priorities

1. Clear every exact-head build and corporate validation gate
2. Maintain the three-service Docker-proxy/cAdvisor/mTLS-proxy boundary
3. Bound metric families, labels, query keys, concurrency, and host mounts
4. Prove immutable packaging, scrape behavior, upgrade, and rollback

## Governance and safety

- Promotion model: `feature/docs/fix/security/upgrade -> development -> test -> staging -> production -> main`.
- Native port `8080` and diagnostics must remain private; `cadv.codestra.media` must not expose cAdvisor publicly.
- Never commit certificates, private keys, Docker credentials, customer data, or secret-bearing fixtures.
- cAdvisor must never receive Docker mutation authority or broad public access.
- Merge does not mount the Docker socket/host filesystems, start cAdvisor, issue certificates, activate scraping, or expose ports.

## Account-wide catalog

See `appolon1908-hue/documentaions/REPOSITORY_CATALOG.md`.
