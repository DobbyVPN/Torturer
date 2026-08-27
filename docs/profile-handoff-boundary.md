# Disposable profile handoff boundary

The functional workflows use short-lived encrypted transport artifacts to
move one disposable VPN profile from the trusted Render lease job to the
trusted client job. Every hosted platform additionally receives `upload.cms`,
an encrypted handoff for its per-run upload-sink URL; it is not a functional
result, is not evidence, and neither handoff is consumed by the canonical
result contract.

The allowed boundary is:

- The lease job receives the provider credential only through its protected
  workflow environment. The plaintext profile, provider endpoint, and Render
  API response remain in its owner-only workspace and are never printed or
  uploaded.
- The client job creates a fresh recipient key and certificate. The private key
  stays in the client workspace; it is never uploaded, cached, passed to the
  lease job, or written to a result/evidence file. Only the public certificate
  and an opaque request cross into the lease workflow.
- The lease job encrypts the profile with that certificate using CMS
  AES-256-GCM. The only profile-derived artifact permitted to cross the hosted
  artifact boundary is the ciphertext, retained for one day. The separately
  generated sink URL crosses on every hosted platform only as the equally
  short-lived `upload.cms` ciphertext; its plaintext and random path never
  enter the safe lease record. The request must
  carry the full, lowercase, non-zero 40-character DobbyVPN `source_sha`; the
  provider rejects omission, short/invalid/all-zero values, or a mismatch
  before any ciphertext is decrypted. The lease/artifact correlation ID is a
  deterministic hash of run, platform, and `source_sha`, so two source
  revisions cannot address the same replay identity. The lease record contains
  only safe service identity/provenance fields.
- The client decrypts the ciphertext locally, uses the plaintext only from
  owner-only storage, and removes the plaintext and private key unconditionally.
  Raw command and service diagnostics remain private; the public functional
  result contains canonical outcomes, safe metrics, stable codes, and opaque
  evidence references only.

The ciphertext is confidential only because the fresh private key remains in
the client job. GitHub documents that anyone with read access to a repository
can download workflow artifacts, and public resources may be downloaded without
authentication ([artifact API](https://docs.github.com/en/rest/actions/artifacts),
[artifact downloads](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts)).
Therefore ciphertext is not treated as secret storage: it must contain no
plaintext or provider credential outside encryption, must have one-day
retention, and must never be uploaded as a result or evidence artifact.

Every request must be checked against the originating workflow run, attempt,
platform, exact Torturer revision, candidate source revision, immutable server
image digest, and fresh recipient certificate. A request, lease, ciphertext, or
completion marker from another run, platform, source revision, image, or stale
certificate must fail closed before client use. A tampered CMS object must fail
decryption. Cleanup is unconditional and must preserve complete private
diagnostics before removing disposable plaintext/workspace material.
