# Android public contract runner

`run_contract.py` is the implementation intended for the future
`Torturer / Android service contract` reusable-workflow job.  It is
secretless and requires a candidate checkout whose `HEAD` exactly matches the
full SHA supplied by the caller.

On a GitHub-hosted Linux runner, after the job has installed JDK 17, Go,
gomobile, Android SDK command-line tools, and the candidate's normal build
prerequisites, call:

```sh
python3 tests/android/run_contract.py \
  --candidate-root "$GITHUB_WORKSPACE/candidate" \
  --commit-sha "$CANDIDATE_COMMIT" \
  --sdk-root "$ANDROID_SDK_ROOT" \
  --work-dir "$RUNNER_TEMP/torturer-android"
```

The runner uses argument-vector subprocess calls only.  It builds the exact
debug application and debug instrumentation APK paths, validates their ZIP
layout and decoded manifests, creates an API-35 Google APIs x86_64 AVD in the
job-local work directory, starts a headless emulator, installs those exact
APKs, confirms the installed package/launcher/VPN-service declaration, and
force-stops the app for cleanup.

The application APK must contain both arm64-v8a and x86_64 `libgojni.so` and
`libc++_shared.so` payloads.  The x86_64 requirement is essential: the public
emulator is x86_64 and cannot execute an arm64-only gomobile backend.

It then invokes DobbyVPN's public Gradle target
`:app:connectedDebugAndroidTest` filtered to its existing
`DobbyVpnServiceInstrumentationTest`.  That source-owned test has the only
in-process seam required to prove foreground-promotion ordering and stale
session/socket rejection; Torturer does not copy it.

This proves APK identity/layout, manifest intent, installation, launcher
process lifecycle, installed service declaration, and the candidate-owned
Android service-shell checks.  It does **not** prove a real VPN connection,
Android VPN consent, TUN creation, DNS or traffic routing, endpoint reachability,
external IP, throughput, or failover. Those are outside this public contract.
