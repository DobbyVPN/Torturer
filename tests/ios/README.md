# iOS Simulator public contract helper

`torturer_checks.ios_simulator` is the standard-library evidence helper used
by the active secretless iOS Simulator workflow. The helper itself does not
launch a Simulator; the pinned workflow owns that lifecycle.

It provides three independent checks:

- exact, clean 40-character candidate source identity;
- a built Simulator `.app` directory, including its `Info.plist`, declared
  executable, required Mach-O slice, bounded file tree, rejection of symlinks,
  and a narrow non-echoing obvious-credential-marker check; and
- a bounded, non-symlink `.xcresult` directory plus a failure-free XCTest
  summary check.

The helper also builds `xcodebuild`, `xcrun simctl`, and `xcresulttool`
argument vectors. Candidate values are validated and passed only as individual
arguments; no helper accepts a shell command or evaluates candidate text.

The active workflow verifies an exact candidate checkout, source-builds the Go
Simulator framework, runs the candidate's production Swift suite and shared
KMP tests, and then invokes the fixed unsigned-app contract below. Every helper
checkout is pinned to an immutable reviewed Torturer commit. The Simulator
transport uses only synthetic input and does not open a real packet tunnel.

## App-contract runner

`torturer_checks.ios_simulator_app` implements the fixed public app contract:
the unsigned `iosApp` Debug product `doBBYVPN.app`, bundle ID
`vpn.dobby.app`, and one explicit Simulator architecture: `arm64` on the
hosted Apple-silicon runner or `amd64` on an Intel local macOS host. The CLI
defaults to `arm64`; an Intel invocation must pass `--architecture amd64`.
It selects the newest available iPhone runtime
from host `simctl` JSON with deterministic tie-breaks, then builds, inspects,
installs, launches, and terminates the app. XCTest/result-bundle verification
is an independent opt-in stage and remains disabled until the named app test
target exists.

The runner uses an injected argument-vector command executor. Its full
sequencing tests run on Linux with a fake host; the active workflow supplies
the real ephemeral macOS subprocess executor for
build/install/launch/terminate evidence but does not request the optional
XCTest stage.
