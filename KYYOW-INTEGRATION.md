# Kyyow integration

This repository is the source authority for **cadvisor** in the Kyyow platform. Its Kyyow boundary is machine-readable in [kyyow-integration.v1.json](kyyow-integration.v1.json).

The component is **private** and its native ports are not made public by this contract. Keycloak owns identity, OpenBao owns secret delivery, and Middleware remains the sole writer to Odoo. Grafana and Superset consume read-only data paths.

This contract is source-complete but deliberately does not claim a live deployment. Production activation requires an immutable image/configuration digest, private-network verification, restore and rollback evidence, and a separately approved cutover.

## Source topology and limits

`codestra/deploy/compose.candidate.yaml` routes Prometheus through `cadvisor-metrics-proxy:9443` with a Prometheus client CA to `cadvisor:8080`. The separate Docker API proxy listens on 2375 on its isolated network. There is no Alloy metrics hop.

All listed ports are private or loopback. This correction does not authorize runtime activation.
