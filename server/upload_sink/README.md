# HTTPS upload sink

This is a test-owned Render image. Render terminates HTTPS at its edge and
passes HTTP to the container's injected `PORT`.

The image runs as unprivileged UID `65532` in group `1000`. Render's
`/etc/secrets` runtime mount uses that group for secret-file access; the sink
needs it only to read the single generated upload path file. Render may expose
that fixed path through a provider-managed symlink; the sink follows the fixed
path and validates the opened descriptor as a small regular file before
reading it.

The immutable-image workflow builds and exercises the container as
`linux/amd64`, mounts a representative `/etc/secrets/upload-path`, performs
the `/healthz` check, and sends an exact 1 MiB upload as UID `65532`/GID `1000`.
It then logs out of GHCR and verifies that the exact digest can be pulled,
inspected, and run anonymously with the same non-root, secret-file, health,
and exact 1 MiB upload checks. A successful workflow prints the exact digest
and image reference needed for the protected Render variables:

```text
RENDER_SINK_IMAGE_OWNER_ID=<Render workspace owner ID>
RENDER_SINK_IMAGE_PATH=ghcr.io/dobbyvpn/torturer-upload-sink@sha256:<workflow digest>
RENDER_SINK_IMAGE_DIGEST=sha256:<workflow digest>
```

The container requires:

- `PORT`: a decimal TCP port in the range 1–65535;
- either `UPLOAD_PATH` containing `/upload/` followed by at least 32 lowercase
  hexadecimal characters (local runs), or the default image argument
  `--path-file=/etc/secrets/upload-path` (the secret file contains that path).

The default argument is part of the immutable image configuration. The Render
service request deliberately sends no separate `dockerCommand` override, so
the published image and the provider use one startup contract.

Operational gates for using the published image with Render:

- Before the first publication, an owner must make the
  `dobbyvpn/torturer-upload-sink` GHCR package public. GitHub creates a new
  package as private by default; this workflow deliberately does not change
  package visibility or request broader permissions. The anonymous digest
  pull is a hard check of this gate.
- After each publication, an owner must copy the emitted immutable image
  reference and digest into the protected `RENDER_SINK_IMAGE_PATH` and
  `RENDER_SINK_IMAGE_DIGEST` repository variables. The trusted Render lease
  workflow reads those variables and rejects missing or stale identities; the
  publish workflow does not modify protected configuration.

`GET /healthz` returns `204`. The configured upload path accepts only a
positive, explicit `Content-Length` no larger than 2 MiB. The body is read and
discarded. The handler does not add request logging; Go's complete unmodified
server diagnostics remain on stderr in the private Render service logs.
