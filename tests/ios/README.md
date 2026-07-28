# iOS Simulator public contract helper

`torturer_checks.ios_simulator` is the H1, standard-library implementation for
a future secretless iOS Simulator lane. It is deliberately not a workflow and
does not launch an iOS Simulator by itself.

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

H2 may use it only after DobbyVPN exposes a fixed public Simulator project or
workspace, scheme, bundle identifier, test identifier, app output and
`iosSimulatorArm64` slice. The test target remains candidate-owned because it
must exercise production iOS code; Torturer independently verifies resulting
application evidence and its package-facing launch lifecycle. The Simulator
transport must use synthetic input and must not open a real packet tunnel.

H2 must be a later Torturer commit that pins this H1 commit SHA in every
`verify.yml` helper checkout before DobbyVPN pins H2. Do not add an iOS job or
change an immutable helper pin in H1.
