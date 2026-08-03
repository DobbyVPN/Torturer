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
