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

## Canonical functional result-v2 validation

The standalone `torturer_contract/functional/schema/result-v2.schema.json`
document is the shape-level wire contract. The canonical validation path must
apply the Python result model afterward through
`torturer_contract.functional.results.validate_result_payload`; schema
validation alone is not a complete result check. The model is deliberately
the owner of semantic rules that standard JSON Schema cannot express
portably, including:

- `artifact_sha256` and `artifact_manifest_sha256` must be different;
- the sum of `phase_durations_ms` values must not exceed `duration_ms`.

Both the schema and model reject a private-provider result carrying
`server_image_digest`, because that constraint is expressible at both layers.

Consumers must retain both stages when they perform an independent schema
check: first validate the JSON shape, then invoke the exact pinned Torturer
model. This keeps the public schema and the executable semantic contract
explicitly layered rather than allowing a schema-valid but semantically
invalid result to be ingested.

## Stable required checks

The intended v1 required checks are:

- `Torturer / artifact contract (Linux)`
- `Torturer / artifact contract (Windows)`
- `Torturer / artifact contract (macOS arm64)`
- `Torturer / artifact contract (macOS Intel)`
- `Torturer / iOS Simulator core contract`
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

## Desktop ZIP helper contract

`torturer_checks.artifact` is the portable v1 implementation for the Windows
and macOS artifact jobs.  A caller first proves the local checkout identity:

```python
source = source_identity_from_checkout(
    checkout, repository=source_repository, expected_commit=commit_sha
)
windows = inspect_windows_zip(artifact_zip, source=source, architecture="amd64")
macos = inspect_macos_zip(artifact_zip, source=source, architecture="arm64")
manifest_json = windows.manifest_json_v1(workflow_revision=torturer_revision)
```

The expected commit and resolved checkout `HEAD` must be identical lowercase
40-character SHAs.  No ref, abbreviated SHA, or build-time provenance claim is
accepted as a substitute.  The helper hashes the artifact and its checked main
executable, records their sizes, and emits compact sorted JSON with `schema: 1`.
It intentionally omits a timestamp, so an unchanged inspection has identical
manifest bytes.

When an artifact digest and size are supplied from a trusted download record,
pass them as `expected_sha256` and `expected_size_bytes`; any mismatch fails
the inspection.  The emitted manifest always contains the observed SHA-256 and
byte size of the ZIP and checked main executable.

The Windows default layout is
`dobbyVPN-windows/bin/Dobby Vpn.exe`; the macOS default layout is
`Dobby Vpn.app/Contents/Info.plist` plus
`Dobby Vpn.app/Contents/MacOS/Dobby Vpn`.  Both helpers reject archive and
input-file symlinks, unsafe/absolute/traversal paths, case-colliding ZIP names,
encrypted entries, oversized or high-ratio members, and files outside that
package root.  The PE machine type and Mach-O main executable slice must match
the requested target architecture.  The macOS bundle executable must also
match `CFBundleExecutable` in `Info.plist`.

Only a short list of unmistakable credential *markers* is scanned in member
names and bytes.  Failures identify no matched text, member, or candidate
value.  This is deliberately a coarse public safety check, not a secret
scanner or a proof that an artifact contains no credentials.

The contract proves the inspected ZIP and the checked-out source identity; it
cannot by itself prove that arbitrary build tooling produced that ZIP from that
source.  The protected workflow remains responsible for checkout provenance,
the build step, and associating its output with this manifest.

## Disposable Outline WebSocket provider input

The trusted provider-side input builder uses one random 32-byte Outline secret
and one random path prefix per platform lease. Its generated owner-only config
binds the Render-provided port and exposes exactly two listeners:

- `websocket-stream` at `<prefix>/tcp`;
- `websocket-packet` at `<prefix>/udp`.

The trusted Render service specification must reference the server image by
`image@sha256:<64 lowercase hex>` and must reject tags such as `latest`, even
when a separate digest field is present. The corresponding in-memory DobbyVPN
block uses the Render HTTPS hostname, port 443, the same prefix, and the pinned
`chacha20-ietf-poly1305` cipher. The secret is never part of public metadata,
lease journals, command arguments, or result artifacts. A plain HTTP health
path is deliberately not configured because the upstream listener returns a
non-success response to a non-WebSocket request; the first authenticated
WebSocket connection is the functional readiness check. The module's unit
contract is tested locally, but no live provider run is claimed by this public
contract until the trusted lease workflow and account eligibility are proven.

The cross-job profile and upload handoffs use an ephemeral recipient
certificate and OpenSSL CMS `-aes-256-gcm` argument vectors. The platform job
keeps its private key and plaintext values owner-only; the trusted lease job
encrypts both values to the public certificate and publishes only ciphertext
under an opaque run/platform artifact name. Command construction rejects
shell-style interpolation and file collisions. The handoff helper is a
contract boundary, not permission to publish plaintext values or to expose the
Render token.

## Hosted capability coverage contract

Every trusted platform workflow selects and emits all ten canonical scenarios.
An unavailable scenario is not a pass and is not silently removed. The workflow
passes only when failed and reset-failure counts are zero and the complete set
of `(scenario_id, reason_code)` unavailable pairs exactly matches its reviewed
allowlist:

| Platform | Expected unavailable pair(s) |
|---|---|
| Linux | `functional.network-transition=HOSTED_LINUX_INTERFACE_REQUIRED`; `functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED` |
| Windows | `functional.network-transition=HOSTED_WINDOWS_UPLINK_TOGGLE_UNSUPPORTED`; `functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED` |
| macOS | `functional.network-transition=HOSTED_MACOS_UPLINK_TOGGLE_UNSUPPORTED`; `functional.sleep-wake=HOSTED_RUNNER_SUSPEND_UNSUPPORTED` |
| Android | `functional.network-transition=ANDROID_UPLINK_TOGGLE_UNSUPPORTED`; `functional.bounded-endurance=ANDROID_ENDURANCE_SEAM_UNSUPPORTED` |

A new unavailable pair, a changed reason, or a stale pair after a capability is
implemented fails closed. The owner-only hosted envelope records
`coverage.status`, the selected/catalog counts, and declared, expected, and
observed unavailable pairs. Its status is explicitly
`supported-subset-with-expected-limitations`; it must never be described as
complete coverage.

The pre-start budget checks are derived from the current catalog and capability
sets, not from the count of scenarios that happen to be executed: Linux needs
950 seconds, Windows/macOS need 950 seconds, and Android needs 920 seconds
including ten five-second resets. These values include the reviewed
network-transition gaps. Each workflow adds a deliberate 60-second scheduling
margin, keeps the inner lane at or below 1,200 seconds, and reserves a common
300 seconds after the canonical lane for essential local cleanup and the
provider-release marker tail. The reserve covers up to 120 seconds of service,
route, or emulator cleanup, followed by a 180-second marker tail: 60 seconds
for plaintext removal/marker preparation, 60 seconds for marker upload, and a
60-second scheduling margin. Android's measured 65-second emulator cleanup
therefore leaves 55 seconds of additional margin inside the same 300 seconds.
The marker follows the essential product/resource cleanup and is only a
provider-release/cleanup signal; it is not a functional pass or release result.
Only after it is uploaded do safe evidence uploads and other non-semantic local
cleanup run. Those later operations do not hold provider deletion and are
bounded by the client hard deadline; the overall workflow result and canonical
functional result remain authoritative, including failures in later evidence
steps.

The Android sleep/wake operation is a real emulator power boundary: the adapter
sends bounded ADB `KEYCODE_SLEEP`/`KEYCODE_WAKEUP` events, proves
`dumpsys power` transitions to asleep and back to awake, and proves the VPN
state after restoration. Doze/device-idle alone is not accepted as sleep/wake.
For Android process loss, the owner-side force-stop is followed by the
candidate-owned controller starting a new session and observations of the new
tunnel and routed identity; failure to prove that recovery fails the scenario
rather than turning it into an expected runner limitation.

## Android profile-observation seam

When DobbyVPN exposes a candidate-owned Android profile test seam, its only
public result must be one JSON observation record with this fixed shape:

```json
{
  "schema": 1,
  "kind": "dobbyvpn.android.profile-observation",
  "platform": "android",
  "source_sha": "FULL_40_CHARACTER_LOWERCASE_SHA",
  "configured": true,
  "connected": true,
  "tunnel_interface": true,
  "routing_identity_changed": true,
  "stability_verified": true,
  "network_transition_verified": true,
  "sleep_wake_verified": true,
  "process_loss_verified": true,
  "latency_ms": 12.5,
  "download_mbps": 20.0,
  "upload_mbps": 10.0,
  "disconnect_clean": true,
  "restart_verified": true,
  "reconnect_bounded": true,
  "second_tunnel_interface": true,
  "second_routing_identity_changed": true,
  "final_disconnect_clean": true,
  "cleanup_verified": true,
  "error_code": "OPTIONAL_SAFE_CODE"
}
```

`error_code` is optional and must be an uppercase stable code, never an error
message containing configuration, endpoint, identity, or credential data.
The record must not contain a profile, config bytes, token, endpoint, literal
IP address, command line, or raw log. Android instrumentation emits these
observations only; the canonical Torturer engine validates the record and
decides scenario outcomes. The `source_sha` proves which candidate produced
the record but is not copied into scenario observation facts.

## Public test scope

Secretless reusable tests verify package layout, process and service lifecycle,
public CLI behaviour, malformed inputs, cleanup, file permissions,
network-denial behaviour, and absence of obvious embedded credentials. They
never receive a VPN profile or provider credential.

The separately dispatched trusted functional workflows may create one
short-lived synthetic Outline WebSocket profile and disposable two-service Render
bundle for Linux, Windows, macOS, or Android. Those workflows verify external routing
identity, bounded traffic measurements, reconnect, cleanup, and every other
canonical capability the selected adapter can actually observe. Their public
result schema excludes profiles, endpoints, URLs, keys, tokens, raw logs, and
literal observed identities.

## iOS Simulator contract

H1 provides public, standard-library Simulator evidence helpers. H2 pins the
H1 commit before adding the secretless hosted job, so a candidate cannot alter
the independent helper revision that judges it.

The initial H2 lane proves an exact clean candidate checkout; verifies the
pinned H1 helper itself; compiles and runs tests against the candidate's exact
production Swift lifecycle sources; and links and runs the shared KMP tests on
an Apple-silicon iOS Simulator. It accepts no secrets, signing inputs, profiles,
or candidate shell fragments.

Once DobbyVPN exposes a stable public Simulator project/workspace, scheme,
bundle identifier, named candidate-owned integration test, app output, and
Simulator XCFramework slice, a later workflow revision may independently
verify the exact clean
candidate checkout; build that fixed target without code signing; boot a
preinstalled iPhone Simulator; inspect/install/launch/terminate the resulting
app; inspect the XCTest result bundle; and require a non-empty failure-free
test summary. All values are passed to `xcodebuild`, `simctl`, and
`xcresulttool` as validated argument vectors rather than shell programs.

H3 fixes the Dobby public app contract to the `iosApp` Debug scheme,
`doBBYVPN.app`, `vpn.dobby.app`, and an explicit `arm64` (hosted
Apple-silicon) or `amd64` (Intel local macOS) Simulator output. The runner
passes the corresponding fixed `ARCHS` build setting and rejects any other
slice. The named app test is
`IOSSimulatorAppContractTests/IOSSimulatorAppContractTests/testAppLaunchesWithoutCredentials`.
H4 pins H3 and independently source-builds, inspects, installs, launches, and
terminates that unsigned app. The named XCTest evidence remains a separate
stage until the candidate actually exposes that target.

The helper rejects symlinked app/result bundles, unsafe executable metadata,
wrong bundle identity or Mach-O architecture, oversized trees, and a short
list of obvious credential markers without echoing candidate bytes. It uses
only synthetic configuration and a Simulator-only transport; it does not prove
NetworkExtension packet-tunnel operation, routes, DNS, traffic, entitlements,
or any physical-iPhone behaviour.

Every `verify.yml` helper checkout is pinned to the immutable H1 SHA. DobbyVPN
may update its immutable Torturer workflow pin only to a reviewed H2-or-later
commit.

## Trusted hosted adapter boundary

The hosted functional entry point is `python3 -m
torturer_checks.hosted.run`. It requires an exact allow-listed candidate
manifest, an observed target platform version, an owner-only profile file, an
immutable server-image digest, and a full source SHA. It invokes the product's existing `dobby-cli` operations (`check-config`,
`connect-profile`, `status --json`, `external-ip`, `disconnect`) as argument
vectors. The adapter's canonical `reconnect` operation composes the existing
connect-profile/status commands after the scenario-owned disconnect within one
bounded step and leaves that generation connected for independent second
tunnel/identity observations; the scenario owns the final disconnect and cleanup.
Runner controls add a bounded interface down/up transition, exact service-process
restart after a recorded loss, and timed status/identity/traffic endurance
sampling. Those controls require explicit paths and are not inferred from a
normal CLI exit. It never imports DobbyVPN source or defines product behavior.

Each command's original stdout and stderr bytes are retained under the trusted
runner's owner-only temporary evidence directory. The emitted result contains
only canonical scenario outcomes, stable failure codes, provenance, and safe
metrics; it never contains the profile, URL, key, or observed public identity.
The adapter advertises only capabilities it can actually observe.

The hosted runner currently emits functional result schema 2. Its
`artifact_sha256` is a deterministic SHA-256 over the ordered identities of
every validated member in the candidate closure; it is not the SHA-256 of
`manifest.json`. The raw manifest-file digest is emitted separately as
`artifact_manifest_sha256`, alongside the stable `artifact_kind`, target
`platform_version`, and candidate `architecture`. A missing or mismatched
manifest, platform version, architecture, or closure member fails before
candidate execution. The v2 result validator also rejects equal artifact and
manifest digests, so a manifest-file hash cannot be reused as the artifact
identity. Schema 1 remains a pinned historical contract and is
validated with its original behavior; it is not silently upgraded or filled
with `unknown` metadata.

Evidence references are finalized by the canonical engine only after the
adapter command and its owner-only evidence sink have completed and flushed.
The bounded reset after each scenario is part of that finalization, so reset
diagnostics and reset failures remain attached to the scenario result rather
than being produced after its evidence references are frozen.

`python3 -m torturer_provider.lease_cli acquire` and `cleanup` are trusted
provider operations, not public candidate steps. The request contains only an
opaque run ID, platform, full lowercase `source_sha`, and immutable image digest.
Acquisition creates one
schema-2 bundle containing a random WSS profile backed by a tagged Outline
service and a separately pinned HTTPS measurement-sink service for every hosted
platform. The bundle binds each role to its exact service ID and image digest,
and generates a fresh 128-bit path namespace. The sink accepts only its health
path, a bounded random POST path, a one-MiB download path, and an uncached
client-identity path in that namespace; it does not persist or log request
bodies or observed identities. The plaintext TOML profile and upload URL are
written only to owner-only storage; the URL crosses the trusted workflow boundary only as
encrypted `upload.cms`, while the safe lease record contains no URL or path.
Cleanup is idempotent, independently deletes and verifies both exact service
IDs, and fails closed on missing, duplicate, or conflicting role identity.
Acquisition also writes a strict, public-safe command result containing only
`completed`/`failed` and a stable uppercase code. An unconditional workflow
step validates and prints that record, so the private deadline wrapper can
retain complete raw child streams without reducing a provider failure to an
opaque digest alone. The schema-2 lease record also carries the provider's
absolute `available_until_epoch`; this is a safe timing value, not an endpoint
or credential.
Schema 1 is retained solely so old single-service journals can be cleaned up;
new acquisition never emits it. Render credentials are read only from the
protected workflow environment. Both immutable images carry their required
secret-file argument as a default image `CMD`: Outline reads
`/etc/secrets/config.yml`, and the upload sink reads
`/etc/secrets/upload-path`. The trusted request deliberately sends no Render
Docker-command override. The non-root sink permits Render's provider-managed
secret path to be a symlink, then validates the opened descriptor as a bounded
regular file before reading it. Secret files are never baked into an image or
emitted in a result.

The four manual functional workflows target Linux, Windows, macOS, and Android.
Each uses a secretless source-build job, a trusted client job with read-only
repository permissions, and a separate least-privilege controller for Render
dispatch. The controller binds the origin run ID, attempt, exact Torturer
`head_sha`, workflow path, platform, and opaque lease ID before the provider may
acquire a service. The client verifies the exact allow-listed candidate closure
and platform readiness before publishing its request. GitHub token-bearing
operations finish before untrusted candidate execution. The client receives
only the encrypted profile and measurement handoffs, never the Render credential or
a write-capable repository token. Legacy schema-1 cleanup records do not create
a new upload handoff.

Full hosted qualification dispatches the four platform leases sequentially.
The unattended controller dispatches the next platform only after the preceding
platform's two Render services have been deleted and their absence has been
independently verified. The fixed account-wide concurrency group on
`server-lease.yml` is an admission guard against overlapping leases, not a
matrix queue; sequencing remains an explicit controller responsibility.

Candidate functional execution, essential service/process, route, and emulator
cleanup, and provider-release marker publication use one absolute deadline: the
originating workflow run's `run_started_at` plus 30 minutes. Build elapsed time
and earlier client setup consume that same origin-run budget, reducing the time
available to the functional lane. This shared semantic deadline is not a promise
that the multi-job GitHub workflow, including GitHub-managed artifact uploads,
finishes within 30 wall-clock minutes. The provider job and each functional
workflow's controller job have independent 30-minute hard bounds; the functional
client job has its own 30-minute hard bound, while build jobs retain their
separate build bound. The canonical runner selects the
complete scenario catalog, partitions it by the adapter's proved capabilities, and
records every unsupported scenario explicitly. It rejects a selected set whose
declared scenario maxima plus one bounded reset per scenario exceed the active
functional budget. A final cleanup reserve remains outside the functional
subprocess but inside the same 30-minute deadline. This rule also applies to
the trusted `server-lease.yml` provider controller: its Render acquisition,
completion-marker wait, diagnostic output, encrypted handoff, deletion, exact
absence proof, and safe journal publication all share one 30-minute job bound.
The controller reserves 240 seconds for finalization and refuses to start or
continue work once that reserve is reached; it has no longer provider-job
exception or separate 40-minute allowance. The server publishes
`available_until_epoch` as its own hard deadline minus the 240-second
finalization reserve. Immediately before starting its canonical functional
subprocess, each client subtracts that same full 300-second post-lane reserve
from its own absolute `RUN_DEADLINE_EPOCH` budget and validates the provider
deadline, failing closed unless the remaining provider lifetime covers its
selected lane (capped at 1,200 seconds), the common 300-second post-lane
reserve, and a five-second start margin. If the
provider lifetime is shorter, the client caps the lane and then applies the
platform minimum; a lane that would fall below that minimum is rejected before
it starts. Before the canonical step, a separate validated post-lane deadline
step publishes the provider deadline into the job environment. Essential
service/process, route, and emulator cleanup runs before the marker. The
plaintext handoff is removed first, even if timing metadata is invalid; marker
preparation then requires the remaining 180 seconds for its bounded preparation,
upload, and scheduling margin inside that aggregate reserve. The marker is
published only after the essential cleanup steps succeed, and its following
one-minute upload is the provider-release/cleanup signal, not the functional
result. If no validated lease exists, or essential cleanup fails, marker
publication is skipped and the server's hard cleanup remains authoritative.
Safe evidence uploads and other non-semantic local cleanup run after marker
publication, each with its own one- or two-minute hard bound under the client
deadline; they may finish after the shared functional/marker deadline and do
not check or depend on provider availability or hold provider deletion. The
overall workflow result and canonical functional result remain authoritative,
and a later evidence-step failure still fails the workflow. The server waits for
the client's opaque provider-release marker until the same availability boundary.
Consequently, marker publication can never overlap provider deletion; a late or
malformed lease is rejected before the lane starts. The reserve is partitioned
into a 150-second provider cleanup budget, its 1-second termination grace, a
4-second plaintext removal budget, its 1-second termination grace, a 60-second safe
journal upload budget, and 10 seconds of bounded finalization overhead. Their
sum is 226 seconds and is enforced by workflow policy tests; the outer job
timeout is not the cleanup mechanism. The provider budget covers the bounded
worst-case two-service stale-absence repair path: eight Render API calls at
16.5 seconds each, using a cleanup-only 5-second transport timeout, two retries,
and 0.5/1-second backoff. Cleanup service discovery is limited to one API page
and no more missing-role candidates than the journal permits; exceeding either
bound fails closed instead of escaping the stated budget. Acquisition keeps its
independent readiness budget.

Linux, Windows, and macOS start the exact source-built product service and drive
the public CLI. Their workflows provide the exact service PID, binary, control
socket or address, PID file, and one encrypted query-free HTTPS measurement
namespace. Torturer derives the identity, latency, download, and upload paths
from that single handoff, so hosted qualification does not depend on unrelated
public identity or transfer providers. The sink marks GET responses `no-store`;
its identity response uses the client address supplied by Render's Cloudflare
edge, while its download response is exactly one MiB. This keeps process-loss
recovery and bounded endurance as real capabilities. When Linux process-loss
qualification deliberately starts a replacement service as a detached child,
the platform adapter verifies and stops that exact replacement before the hosted
scenario process exits. Linux treats a replacement zombie as exited only after
the process-state probe proves it, while Windows and macOS use their exact
process-tree identity mechanisms. The hosted adapter's exact replacement-tree
finalizer, together with the overall failed workflow and canonical outcome on
any finalization error, is authoritative for proving replacement cleanup. The
workflow's unconditional service/process cleanup remains an independent
safeguard for the originally launched service; it does not by itself prove that
an escaped descendant was absent. Finalization failures retain their stable
uppercase reason code in the top-level diagnostic. Connected and disconnected
route observations allow the identity to converge only within their existing
scenario deadlines; every probe remains in the runner-local raw command record.
Linux may advertise network-transition only when the workflow supplies an exact
non-control interface; Windows and macOS report an explicit uplink-toggle
limitation because interrupting the runner's control interface would destroy
the job. Sleep/wake is not advertised on hosted runners because suspending the
runner itself cannot provide the guest-level sleep/wake proof used by the
private Harness.

Android requires usable `/dev/kvm`, starts an API-35 x86_64 emulator with
`-no-window` and hardware acceleration, installs the exact staged application
and instrumentation APKs, and proves readiness before requesting its lease.
The candidate-owned `AndroidHostedProfileInstrumentationTest` accepts an
owner-only command file and profile, executes one complete canonical scenario,
and emits only the fixed safe observation schema. Torturer validates those
facts and owns the assertions and outcome. The hosted Android adapter does not
advertise network transition: airplane-mode setting changes do not prove loss
and restoration of a non-VPN uplink/default route, and the public image has no
reliable isolated root-controlled data interface while ADB remains reachable.
It uses bounded `KEYCODE_SLEEP`/`KEYCODE_WAKEUP` events with `dumpsys power`
state proof and VPN restoration for sleep/wake, and `am force-stop` for process
loss. The candidate-owned instrumentation must report process-loss recovery (a
new session with tunnel/routing facts) in `process_loss_verified`; Torturer does
not infer recovery from PID disappearance. Each action is performed outside
the APK and released through its one-use, token-bound control rendezvous; a
failure remains a failed scenario. Android does not advertise endurance
because the current public instrumentation seam has no `measure_endurance`
operation, and the adapter does not substitute a shorter or unrelated pause.
