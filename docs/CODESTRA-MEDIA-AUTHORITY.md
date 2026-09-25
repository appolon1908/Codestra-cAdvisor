# Codestra cAdvisor Authority

Principal repository: `ingtrader21-spec/Codestra-cAdvisor`
Canonical service host: `cadv.codestra.media`
Canonical DNS target: `37.27.128.39`
TTL: `600`

DNS has been externally verified. No alternate authoritative hostname is permitted.

## Ownership
Own cAdvisor deployment/configuration, container metrics exposure policy, validation and upgrade runbooks. Do not own Prometheus scrape policy, Docker platform administration outside metrics requirements, Grafana dashboards or Caddy.

## Exposure
Private/internal only. DNS may exist, but cAdvisor ports must be restricted to Prometheus/private monitoring networks.

## Integration
Upstream: local container runtime metrics. Downstream: Prometheus scrapes.

## Branch policy
Persistent: `main`, `development`, `test`, `staging`, `production`.
Temporary: `feature/*`, `fix/*`, `upgrade/*`, `security/*`, `docs/*`, `hotfix/*`, optional `release/*`, `rollback/*`.
Promotion: work -> development -> test -> staging -> production -> main.
