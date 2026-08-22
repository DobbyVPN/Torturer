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

The repository contains a pinned public iOS Simulator core lane. It proves the
exact clean candidate identity, verifies the H1 evidence helper, runs tests
against the candidate's exact production Swift lifecycle sources, and links
and tests shared KMP code on an Apple-silicon Simulator. It also source-builds,
inspects, installs, launches, and terminates the fixed unsigned Simulator app
without credentials. The named app XCTest evidence remains a separate later
stage until DobbyVPN exposes that target. None of these checks claims
NetworkExtension, routing, DNS, or physical-device coverage.

Real VPN endpoints, external-IP assertions, speed tests, prolonged soak tests,
and physical-device tests are outside Torturer's public test contract.

The provider package also contains a pure, secret-safe Outline WSS input
contract (`torturer_provider.outline`). It creates one run-scoped shared path
prefix and key, emits both canonical `websocket-stream` (`/tcp`) and
`websocket-packet` (`/udp`) listener definitions for the pinned image, and
builds the in-memory DobbyVPN profile only after a trusted service URL is
known. The key and generated config are provider handoff data; they are never
public result data. This contract is tested locally and does not claim that a
live Render service has been provisioned.

The trusted-runner package `torturer_checks.hosted` now provides one narrow
CLI adapter for Linux, Windows, macOS, and Android entry points. It drives only
DobbyVPN's existing public CLI, records complete command bytes in a private
runner-local directory, translates independently observed connection facts, and
leaves scenario assertions and outcomes to the canonical engine. Capabilities
that the current adapter cannot prove (sleep/wake, process-loss recovery,
network transition, endurance, or throughput without two approved URLs) are
reported as `unavailable`; they are never inferred as passes. The protected
`python -m torturer_provider.lease_cli` boundary creates/cleans one tagged
Render lease and writes the profile only to owner-only storage for immediate
encryption. The trusted image request sets the complete Render Docker command
to `/outline-ss-server -config=/etc/secrets/config.yml`. A manual, Linux-only
trusted workflow now wires that lease boundary to the canonical hosted engine;
it fails closed when the configured immutable image digest or Render eligibility
is absent. Windows, macOS, and Android hosted functional lanes remain later
adapter phases, not silently claimed coverage.

## Security promises

- Candidate code runs with no secrets and minimum read-only permissions.
- The exact source repository and full 40-character commit SHA are recorded.
- Workflow and third-party action references are pinned to immutable commits.
- Candidate-controlled values are passed through environment variables and
  validated, never interpolated directly into shell programs.
- Fork pull requests receive the same public synthetic tests but no privileged
  context.
- The trusted profile handoff uses owner-only files and an OpenSSL CMS
  AES-256-GCM argument vector; plaintext profile material is never a command
  argument or public artifact.
- Generated manifests are diagnostic evidence, not signing attestations.

See `docs/contract.md` for the caller and result contracts.

Licensed under the Apache License, Version 2.0.
