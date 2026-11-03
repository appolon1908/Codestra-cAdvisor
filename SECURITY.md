# Security policy

Report vulnerabilities privately through GitHub Security Advisories. Never place Docker credentials, mTLS keys, tokens, socket data, or exploit details in public issues.

Only the Docker API proxy may mount the socket, read-only. It permits the bounded read-only API contract tested in `proxy_test.go`; cAdvisor itself receives no socket, host PID namespace, host network, privileged mode, or host device. Metrics leave through the mTLS proxy. Both repository-built images must be released from an exact protected production SHA with digest-pinned build inputs, redacted secret scanning, vulnerability gates, SBOMs, signatures, and provenance.
