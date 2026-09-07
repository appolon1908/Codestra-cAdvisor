# Private cAdvisor proxy request contract

This change follows the host-cgroup repair in PR #35. It changes source validation and request handling only; it does not deploy an exporter, access a production Docker socket, or activate scraping.

## Scrape and health interface

The private mTLS metrics proxy serves GET/HEAD `/metrics` and `/healthz` only. Other methods return 405; other paths, query strings, request bodies, upgrades and malformed envelopes are rejected before forwarding. Its TLS 1.3 client-certificate requirement is unchanged. This is not a public operator or business API.

The isolated Docker metadata proxy keeps the existing explicit GET/HEAD operation and query-key allowlist. No create, delete, exec, archive, build, plugin or container-control operation is added. `/healthz` now checks the request before contacting the socket, uses a bounded five-second ping context, returns 503 for unsuccessful upstream status, and emits no body on HEAD.

## Request validation

Reject nonzero or unknown Content-Length, transfer encoding, trailers, body streams, upgrade tokens in any Connection/Upgrade header value, noncanonical/dot-segment paths, backslash/NUL/CR/LF/percent ambiguity, inconsistent RawPath, and raw queries over 8192 bytes. Legitimate escaped image-ID colons remain valid. Docker query parsing must succeed completely; malformed entries may not disappear during authorization. Existing per-key limits remain eight values of at most 4096 bytes.

## Ownership and evidence

Node Exporter owns host metrics; cAdvisor owns bounded container metrics. Prometheus scrapes these private interfaces. Agent usernames, campaigns, tenant identity and business mutations do not belong in exporter endpoints or high-cardinality metric labels.

Deployment still requires reviewed network isolation, trusted upstream configuration, mTLS material, exact image/configuration identity, container-discovery/readback, rollback evidence and protected promotion. HTTP unit tests do not certify those runtime conditions.

`codestra/deploy/proxy_request_test.go` includes nine cases that failed against the original proxy and now pass. It also covers valid reads, health/metrics denial before upstream access, bounded health context, HEAD behavior and failed-health status. Tests use in-memory handlers and a fake transport, never a live socket. The new read-only workflow executes existing and added tests with the race detector on both source and merge-result trees; existing corporate CI remains required.
