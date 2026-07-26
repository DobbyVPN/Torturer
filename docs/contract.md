# Torturer v1 contract

## Caller

DobbyVPN will invoke a reusable Torturer workflow from a protected workflow
definition. The Torturer revision is pinned by full commit SHA.

The call accepts only:

| Input | Meaning |
|---|---|
| `source_repository` | Public candidate repository, including a pull-request fork |
| `commit_sha` | Exact full 40-character candidate commit |
| `pr_number` | Diagnostic pull-request identity |

No secrets are accepted. The effective workflow token has `contents: read` and
no write permission. The caller passes data strings only; it does not execute
candidate code in a privileged pre-test job.

Before checkout, the called workflow validates the repository form and full
hexadecimal SHA. It checks out only that repository/SHA pair and records the
resolved commit.

## Stable required checks

The intended v1 required checks are:

- `Torturer / artifact contract (Linux)`
- `Torturer / artifact contract (Windows)`
- `Torturer / artifact contract (macOS arm64)`
- `Torturer / artifact contract (macOS Intel)`
- `Torturer / Android service contract`

Names become a compatibility surface once configured in DobbyVPN branch
protection.

## Diagnostic manifest

Each job emits a JSON manifest with:

```json
{
  "schema": 1,
  "source": {
    "repository": "DobbyVPN/DobbyVPN",
    "commit": "FULL_40_CHARACTER_SHA",
    "pr": 123
  },
  "runner": {
    "os": "ubuntu",
    "arch": "x86_64"
  },
  "artifact": {
    "platform": "linux",
    "format": "package",
    "file": "candidate-file",
    "sha256": "SHA256",
    "size_bytes": 123
  },
  "components": [],
  "build": {
    "workflow_revision": "FULL_TORTURER_COMMIT_SHA",
    "started_at": "RFC3339_UTC"
  }
}
```

The schema records immutable source identity, runner identity, file format,
size, SHA-256, component hashes, and Torturer revision. It is test evidence,
not authority to sign or publish the artefact.

## Public/private boundary

Public synthetic tests may verify package layout, process and service
lifecycle, public CLI behaviour, malformed inputs, cleanup, file permissions,
network-denial behaviour, and absence of obvious embedded credentials.

Actual provider profiles, external-IP expectations, throughput, protocol
performance, real failover, soak runs, private VM definitions/state, rich
failure artefacts, and physical iOS testing remain in Harness.

## Rollout gate

The DobbyVPN caller is not added and no check is made required until the first
Torturer vertical slice is implemented and proven. The existing protected
real-profile workflow remains in DobbyVPN until its private Harness replacement
also passes.
