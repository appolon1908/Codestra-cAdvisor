# Repository profile

- Authority: `appolon1908-hue/Codestra-cAdvisor`
- Component: `cadvisor`
- Artifact model: two repository-built, signed immutable images (`cadvisor` and `cadvisor-proxy`)
- Runtime topology: read-only Docker API proxy, cAdvisor, and mTLS metrics proxy
- Native exposure: private networks only; no published host port
- Privileged mode: prohibited by the canonical candidate
- Direct Docker socket consumer: proxy only, read-only mount, allowlisted API methods and paths
- Promotion path: `development -> test -> staging -> production -> main`
- Production activation from this source: `NO`
- Source hygiene: whitespace enforcement applies to Codestra-owned files; `upstream/` is byte-preserved and exempt through `.gitattributes`

The canonical deployment source is `codestra/deploy/compose.candidate.yaml`. Legacy privileged, host-network, device-mounted manifests were removed because they conflicted with this enforced boundary.
