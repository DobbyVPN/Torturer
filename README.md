# DobbyVPN Torturer

Independent public black-box verification for
[`DobbyVPN/DobbyVPN`](https://github.com/DobbyVPN/DobbyVPN).

Torturer is being built to exercise exact candidate commits and their packaged
applications on GitHub-hosted Linux, Windows, macOS, and Android runners. Its
tests use only public synthetic inputs and product-facing interfaces. It
contains no private profiles, credentials, signing material, or release
secrets.

## Why this is separate

Application pull requests cannot change the independent test logic that judges
them. DobbyVPN calls a reviewed Torturer reusable workflow pinned to an
immutable commit, and branch protection requires the resulting stable checks.

This repository is not a build dependency and does not replace DobbyVPN's
co-located unit, package-private, source-set, or seam tests.

## Initial coverage roadmap

- Linux packaged CLI/service lifecycle and cleanup;
- Windows packaged CLI/service lifecycle and cleanup;
- macOS ARM and Intel bundle/CLI/service contracts;
- Android APK installation and package-facing service lifecycle;
- artefact identity, layout, digest, permission, telemetry-absence, and
  obvious-secret checks.

Real VPN endpoints, external-IP assertions, speed tests, prolonged soak tests,
local VMs, and physical-device tests belong to the private Harness.

## Security promises

- Candidate code runs with no secrets and minimum read-only permissions.
- The exact source repository and full 40-character commit SHA are recorded.
- Workflow and third-party action references are pinned to immutable commits.
- Candidate-controlled values are passed through environment variables and
  validated, never interpolated directly into shell programs.
- Fork pull requests receive the same public synthetic tests but no privileged
  context.
- Generated manifests are diagnostic evidence, not signing attestations.

See `docs/contract.md` for the planned caller and result contracts.
