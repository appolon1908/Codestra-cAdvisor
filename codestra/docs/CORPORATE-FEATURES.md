# Codestra cAdvisor Corporate Features

## Mission

cAdvisor is the standard container-resource telemetry source for Codestra-managed Docker/container workloads. It complements Node Exporter by showing which individual service/container is consuming host capacity.

## Required coverage

Track per-container CPU, memory, network, filesystem/I/O, CPU throttling, OOM signals and lifecycle/restart behavior.

## Corporate label model

Prometheus relabeling should normalize container metadata into `codestra_business`, application, service, environment, server, deployment and container role. Ephemeral container IDs/hashes and dynamic path labels should be dropped where they create unnecessary cardinality.

## Corporate features

- container saturation and capacity views;
- OOM and restart correlation;
- CPU throttling visibility;
- per-service network and I/O trends;
- noisy-container detection;
- deployment/version correlation;
- business/service rollups in Grafana;
- alerts for runaway containers and repeated restarts.

## Security

cAdvisor is read-only operational telemetry. Its native listener remains private, and access to the container runtime/filesystem should be the minimum required for monitoring. It must not become a container-management or deployment control plane.

## Release rule

`cadv.codestra.media` remains internal/private. Codestra-specific configuration stays outside imported upstream source, and merge does not authorize port publication or deployment.
