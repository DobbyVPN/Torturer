# DobbyVPN Torturer

Independent public black-box verification for
[`DobbyVPN/DobbyVPN`](https://github.com/DobbyVPN/DobbyVPN).

Torturer exercises exact candidate commits and their source-built
applications on GitHub-hosted Linux, Windows, macOS, and Android runners. Its
repository contains only public synthetic inputs and product-facing
interfaces. Trusted functional jobs create a short-lived synthetic VPN profile
at runtime; no profile, provider credential, signing material, or release
secret is stored in this repository or emitted in a public result.

## Why this is separate

Application pull requests cannot change the independent test logic that judges
them. DobbyVPN calls a reviewed Torturer reusable workflow pinned to an
immutable commit, and branch protection requires the resulting stable checks.

This repository is not a build dependency and does not replace DobbyVPN's
co-located unit, package-private, source-set, or seam tests.

## Public coverage

The secretless reusable `verify.yml` workflow covers:

- Linux, Windows, macOS ARM, and macOS Intel source-build, CLI, and service
  contracts;
- Android dual-ABI APK layout, installation, package-facing behavior, and
  candidate-owned lifecycle instrumentation; and
- portable Windows/macOS ZIP identity, layout, architecture, digest, and
  obvious-credential-marker inspection.

The manually dispatched trusted functional workflows cover Linux, Windows,
macOS, and Android against one disposable Outline WebSocket server per
platform. A secretless build job produces and hashes an allow-listed candidate
closure. The client job proves that closure and its platform is ready before it
publishes an opaque lease request. A separate controller dispatches the
provider workflow, which creates the Render service and encrypts the generated
profile to the client's ephemeral certificate. Candidate execution begins only
after token-bearing GitHub operations finish; it never receives the Render
credential or a repository-control token.

Linux, Windows, and macOS use the product's public service and CLI. Android uses
a headless KVM emulator and the candidate-owned
`AndroidHostedProfileInstrumentationTest` driver. Every adapter executes the
same canonical scenario catalog and assertions, runs every scenario supported
by its proved capabilities, and reports the remainder explicitly as
unsupported. Current hosted desktop lanes prove configuration, connection,
tunnel and routing identity, traffic metrics, disconnect/cleanup, reconnect,
bounded endurance, and exact product-process recovery. Android proves the
common connection, traffic, reconnect, disconnect, and cleanup set. The Linux
hosted lane records `functional.sleep-wake` as an explicit, expected
unavailable result with reason `HOSTED_RUNNER_SUSPEND_UNSUPPORTED`: suspending
the GitHub runner would destroy the job's control path and cannot prove guest
sleep/wake. It is not silently skipped or inferred as a pass; the private
Harness Linux VM must cover it with a real guest suspend/wake boundary.

The Linux hosted result keeps all ten canonical scenario records and reports
`coverage.status` as
`supported-subset-with-expected-limitations`, never as complete coverage. The
workflow pins the exception in its command line, and the runner fails closed
for any missing, duplicate, failed, or unexpected unavailable scenario.

Each platform workflow has one total 30-minute deadline measured from the
workflow run start, including source build, client readiness, lease
coordination, scenarios, evidence, and cleanup. Android requires `/dev/kvm` and
always launches its emulator headlessly. The provider workflow cleans and
independently verifies deletion of the exact tagged Render service even when a
client fails or never publishes its completion marker.

The repository contains a pinned public iOS Simulator core lane. It proves the
exact clean candidate identity, verifies the H1 evidence helper, runs tests
against the candidate's exact production Swift lifecycle sources, and links
and tests shared KMP code on an Apple-silicon Simulator. It also source-builds,
inspects, installs, launches, and terminates the fixed unsigned Simulator app
without credentials. The named app XCTest evidence remains a separate later
stage until DobbyVPN exposes that target. None of these checks claims
NetworkExtension, routing, or DNS coverage.

The provider package contains a pure, secret-safe Outline WSS input
contract (`torturer_provider.outline`). It creates one run-scoped shared path
prefix and key, emits both canonical `websocket-stream` (`/tcp`) and
`websocket-packet` (`/udp`) listener definitions for the pinned image, and
builds the in-memory DobbyVPN profile only after a trusted service URL is
known. The key and generated config are provider handoff data; they are never
public result data. The protected `python -m torturer_provider.lease_cli`
boundary creates and cleans one tagged Render lease, writes the profile only to
owner-only storage for immediate encryption, and starts the immutable Outline
image with `/outline-ss-server -config=/etc/secrets/config.yml`.

The trusted-runner package `torturer_checks.hosted` records complete command
bytes in its private runner-local directory, converts independently observed
facts to the canonical vocabulary, and leaves every assertion and outcome to
the canonical engine. Public results contain only stable outcomes, provenance,
safe metrics, and bounded evidence metadata; they never contain a profile,
endpoint, key, URL, command argument, or observed public identity.

## Security promises

- Untrusted candidate builds receive no secrets and have read-only repository
  permissions.
- A trusted functional client receives only its short-lived synthetic VPN
  profile, after exact closure verification and after GitHub token operations
  finish; it never receives the provider credential or a write-capable token.
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
