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
provider workflow, which creates the Render bundle and encrypts the generated
profile to the client's ephemeral certificate. Candidate execution begins only
after token-bearing GitHub operations finish; it never receives the Render
credential or a repository-control token.

Hosted full qualification leases the Render account sequentially: the
unattended controller dispatches the next platform only after the previous
platform's two services have been deleted and their absence independently
verified. The fixed concurrency group in `server-lease.yml` is an account-wide
admission guard for overlapping dispatches; it is not a matrix queue and must
not be treated as the sequencing mechanism.

Linux, Windows, and macOS use the product's public service and CLI. Android uses
a headless KVM emulator and the candidate-owned
`AndroidHostedProfileInstrumentationTest` driver. Every adapter executes the
same canonical scenario catalog and assertions, runs every scenario supported
by its proved capabilities, and reports the remainder explicitly as
unsupported. Current hosted desktop lanes prove configuration, connection,
tunnel and routing identity, traffic metrics, disconnect/cleanup, reconnect,
bounded endurance, and exact product-process recovery. Linux network-transition
is unavailable in the hosted lane because the runner's physical default route
is also its control path; a separate isolated data interface is required.
Android does not advertise network-transition because airplane-mode setting
changes do not prove loss/restoration of a non-VPN uplink/default route on the
public image. Android does perform a real emulator power sleep/wake boundary
(ADB sleep/wakeup key events with `dumpsys power` proof) and force-stop
process-loss control through a token-bound rendezvous.
Process-loss recovery must then start a fresh candidate-owned session and prove
its tunnel and routed identity before it can pass. Android endurance remains
explicitly unavailable until the public instrumentation seam exposes a real
bounded-endurance operation; no shorter substitute is reported as endurance.

The hosted result records `coverage.status` as
`supported-subset-with-expected-limitations`, never as complete coverage. Each
workflow supplies an explicit scenario/reason allowlist, and the run fails
closed unless the observed unavailable pairs match that allowlist exactly.

Candidate functional execution, essential service, route, and emulator cleanup,
and provider-release marker publication share one absolute deadline: the
originating workflow run's `run_started_at` plus 30 minutes. Build elapsed time
and earlier client setup consume that same origin-run budget, reducing the time
available to the functional lane. This shared deadline does not promise that the
multi-job GitHub workflow, including GitHub-managed artifact uploads, finishes
within 30 wall-clock minutes. The provider job and each functional workflow's
controller job have independent 30-minute hard bounds; the functional client job
has its own 30-minute hard bound, while build jobs retain their separate build
bound. The functional lane is admitted only when the
Render lease leaves a common 300-second post-lane reserve plus a five-second
start margin. Essential service, route, and emulator cleanup runs after the
canonical scenarios and before the provider-release marker. Plaintext handoff
material is removed first even if timing metadata is invalid; marker preparation
and its next one-minute upload must fit inside the 180-second marker tail before
Render deletion may begin. The common 300-second reserve covers up to 120
seconds of essential cleanup plus that marker tail; Android's proved 65-second
emulator cleanup leaves 55 seconds of additional margin. The marker is published
only when those essential cleanup proofs succeed. It is a provider-release/
cleanup signal, not a functional pass result: the overall workflow result and
canonical functional result remain authoritative, including failures in later
evidence steps. Bounded safe evidence uploads and other non-semantic local
cleanup may finish afterward under their own bounded client-job steps; they do
not hold provider deletion. Android requires
`/dev/kvm` and always launches its emulator
headlessly. The provider workflow cleans and independently verifies deletion
of both exact tagged Render services even when a client fails or never publishes
its completion marker. If a client fails before a validated lease deadline is
established, marker publication is reported as unavailable and skipped while
the server's hard cleanup remains authoritative.

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
boundary uses one schema-2 bundle of the Outline lease and a separately pinned
measurement sink for Linux, Windows, macOS, and Android. It writes the profile
and the random sink URL only to owner-only storage for immediate CMS encryption,
and starts the immutable images with
`/outline-ss-server -config=/etc/secrets/config.yml` and
`/upload-sink --path-file=/etc/secrets/upload-path`.

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
  profile and token-bound measurement handoff, after exact closure verification
  and after GitHub token operations finish; it never receives the provider credential or
  a write-capable token.
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
