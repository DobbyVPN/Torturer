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

The trusted-runner package `torturer_checks.hosted` provides one narrow
CLI adapter for the desktop entry points (Linux, Windows, and macOS), plus an
Android entry point that is retained only for explicit capability gating. The
CLI adapter drives only DobbyVPN's existing public CLI, records complete
command bytes in a private runner-local directory, translates independently
observed connection facts, and leaves scenario assertions and outcomes to the
canonical engine.
The Linux adapter now has real, bounded seams for network transition (an
explicit runner interface), product-service process loss (an exact service
PID/binary/socket control set), and timed endurance sampling when an approved
public download/upload URL pair is supplied. Sleep/wake remains explicitly
`unavailable` on hosted runners because suspending the runner would terminate
the job; traffic and endurance remain unavailable without the URL pair. Missing
capabilities are never inferred as passes. Every command keeps its complete raw
stdout/stderr in the private runner directory and emits only safe return-code,
size, duration, and digest metadata. The protected
`python -m torturer_provider.lease_cli` boundary creates/cleans one tagged
Render lease and writes the profile only to owner-only storage for immediate
encryption. The trusted image request sets the complete Render Docker command
to `/outline-ss-server -config=/etc/secrets/config.yml`. The manual trusted
workflow currently wires only the common Linux lane; the advanced Linux seams
are opt-in inputs until their runner-control wiring is reviewed. In particular,
network transition currently operates on the explicitly named whole runner
interface, and the process-loss controller must be given the actual candidate
PID rather than a sudo launcher PID; neither is enabled by the workflow until
that safety and cleanup proof exists. Windows, macOS, and Android hosted
functional lanes still lack their platform-specific profile/control handoff in
a trusted workflow and are not silently claimed coverage. Android's existing
public emulator test proves consented TUN and packet routing internally, but it
does not accept an Outline profile or prove an external server identity, so it
cannot be substituted for the canonical hosted VPN scenarios.

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
