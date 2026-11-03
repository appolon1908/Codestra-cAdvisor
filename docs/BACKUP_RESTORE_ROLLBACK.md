# Backup, restore, and rollback

cAdvisor and its proxies are stateless. Preserve the reviewed Compose source, runtime-base lock, both immutable image digests, configuration checksum, Docker socket group mapping, mounted secret-file paths, and release evidence. Do not copy secret values.

Before installation or rollback, validate every recorded image through
`scripts/validate_runtime_images.py`. A registry port outside `1..65535` is not
a usable immutable identity and blocks the operation before Compose rendering
or any pull attempt.
Only a numeric field in the registry authority before `/` is interpreted as a
port; a numeric image tag remains a valid immutable rollback identity.

Rollback both images as one topology change: validate the previous proxy,
cAdvisor, builder, and base identities with
`scripts/validate_runtime_images.py`; verify the previous release digests are
pullable and that the cAdvisor OCI revision names the protected source that
compiled the locked vendored tree; render the previous Compose manifest; apply
the three services without rebuilding or deleting volumes; then prove Docker
`/_ping` readiness through the proxy health route, proxy denial tests, cAdvisor
health, mTLS metrics, Prometheus target recovery, and absence of public or
native exposure.
