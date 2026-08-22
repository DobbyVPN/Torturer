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

The cross-job profile handoff uses an ephemeral recipient certificate and
OpenSSL CMS `-aes-256-gcm` argument vectors. The platform job keeps its private
key and plaintext profile owner-only; the trusted lease job encrypts the
profile to the public certificate and publishes only the ciphertext under an
opaque run/platform artifact name. Command construction rejects shell-style
interpolation and file collisions. The handoff helper is a contract boundary,
not permission to publish a plaintext profile or to expose the Render token.

## Public test scope

Public synthetic tests may verify package layout, process and service
lifecycle, public CLI behaviour, malformed inputs, cleanup, file permissions,
network-denial behaviour, and absence of obvious embedded credentials.

Provider profiles, external-IP expectations, throughput, protocol performance,
real failover, soak runs, and physical iOS testing are outside this public
contract.

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
torturer_checks.hosted.run`. It requires an exact candidate artifact digest, an
owner-only profile file, an immutable server-image digest, and a full source
SHA. It invokes the product's existing `dobby-cli` operations (`check-config`,
`connect-profile`, `status --json`, `external-ip`, `disconnect`) as argument
vectors. The adapter's canonical `reconnect` operation composes the existing
disconnect/connect-profile/status commands within one bounded step and leaves the
session disconnected before the cleanup observation. On Linux, optional trusted
runner controls add a bounded interface down/up transition, exact service-process
restart after a recorded loss, and timed status/identity/traffic endurance
sampling. Those controls require explicit paths and are not inferred from a
normal CLI exit. It never imports DobbyVPN source or defines product behavior.

Each command's original stdout and stderr bytes are retained under the trusted
runner's owner-only temporary evidence directory. The emitted result contains
only canonical scenario outcomes, stable failure codes, provenance, and safe
metrics; it never contains the profile, URL, key, or observed public identity.
The adapter advertises only capabilities it can actually observe.

`python3 -m torturer_provider.lease_cli acquire` and `cleanup` are trusted
provider operations, not public candidate steps. The request contains only an
opaque run ID, platform, and immutable image digest. Acquisition creates one
random WSS profile and tagged service, writes the plaintext TOML profile only
to owner-only storage, and emits an opaque lease record. Cleanup is idempotent
and independently verifies the exact service is absent. Render credentials are
read only from the protected workflow environment. For the selected Outline
image, the trusted request sets the complete Render Docker command to
`/outline-ss-server -config=/etc/secrets/config.yml`. Render's override is a
complete start command, not additional arguments for the image ENTRYPOINT. The
secret file is never baked into the image or emitted in a result.

These entry points are unit-tested with fake adapters/provider responses. The
manual `functional.yml` workflow currently enables only the common Linux lane and
hands off one encrypted profile to the separate `server-lease.yml` workflow;
the lease wrapper binds the originating run's exact Torturer `head_sha` to its
own checkout before it can acquire a service. Both workflows are bounded and
fail closed when the immutable image variable or Render account eligibility is
absent. A hosted Linux result is not a claim that sleep/wake is covered; that
operation remains unavailable on a runner that cannot suspend and resume itself.
The optional network-transition seam currently interrupts the named whole
runner interface, so it is not enabled until endpoint-only interruption or a
runner-recovery proof is wired. The process-loss seam requires the actual Go
service PID and independently checked child cleanup; a sudo launcher PID is
not accepted. Windows and macOS still need their trusted workflow to
install/start the platform service and hand off the profile/control
credentials. Android still needs a candidate-owned automation API that accepts
a test profile and exposes consent, routing identity, and cleanup observations;
its current APK contract intentionally supplies none of those.
