# Upgrade procedure

Update cAdvisor only on a feature branch. Resolve the official runtime-base
image to an OCI digest, import the reviewed upstream source and record its exact
commit/tree, update the cAdvisor build manifest and runtime-base lock together,
and rebuild both repository images with the same protected source SHA. The
packaged cAdvisor binary must be compiled from the locked `upstream/` tree and
its revision readback must equal that tree's source commit; the base image's
prebuilt binary is never the release authority.

Promote the certified lineage through development, test, staging, production, and main. Staging must prove read-only Docker API behavior, denied mutations and upgrades, bounded labels, private mTLS metrics, restart recovery, and a two-image rollback rehearsal before production authorization.

The parent-repository whitespace gate excludes the byte-preserved `upstream/`
snapshot because official documentation contains literal conflict-marker examples.
That exclusion is bounded by an independent `HEAD:upstream` Git-tree comparison
against `CODESTRA_UPSTREAM_LOCK.json#imported_tree_sha`. A mismatch blocks release;
rollback restores the last protected source and lock together.

Before any later installation, source the reviewed non-secret runtime environment
and run `python3 scripts/validate_runtime_images.py`. It rejects mutable tags,
malformed digests, and incomplete builder/runtime image identities before
Compose rendering or image pulls.
