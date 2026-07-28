# DobbyVPN Torturer

Independent public black-box verification for
[`DobbyVPN/DobbyVPN`](https://github.com/DobbyVPN/DobbyVPN).

Torturer exercises exact candidate commits and their source-built
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

## Public coverage

- Linux, Windows, macOS ARM, and macOS Intel source-build/CLI/service contracts;
- Android dual-ABI APK layout, installation, package-facing behavior, and
  candidate-owned lifecycle instrumentation;
- portable Windows/macOS ZIP identity, layout, architecture, digest, and
  obvious-credential-marker inspection helpers.

The repository also contains an unpinned H1 iOS Simulator evidence helper. It
is not a required check and does not run in GitHub Actions until DobbyVPN has a
fixed, public Simulator build/test contract and a later H2 workflow revision
pins the H1 helper commit. It validates simulator app/result evidence; it does
not claim NetworkExtension, routing, DNS, or physical-device coverage.

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

See `docs/contract.md` for the caller and result contracts.

Licensed under the Apache License, Version 2.0.
