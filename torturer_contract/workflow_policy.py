"""Immutable policy constants for the public reusable verifier.

The workflow itself is the enforcement point.  Keeping its compatibility and
trust-boundary constants here lets standard-library tests reject accidental
policy drift before a workflow revision is pinned by a caller.
"""

from __future__ import annotations

CHECKOUT_ACTION = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
SETUP_JAVA_ACTION = "actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95"
SETUP_GO_ACTION = "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16"
# All five pins below were checked against their upstream action.yml manifests:
# each runs on node24.  Keep this set intentionally small, immutable, and
# public-runner-only so the verifier cannot accidentally regain a deprecated
# Node-20/16 transitive action.
SETUP_ANDROID_ACTION = "android-actions/setup-android@40fd30fb8d7440372e1316f5d1809ec01dcd3699"
UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f"

PINNED_EXTERNAL_ACTIONS = frozenset(
    {
        CHECKOUT_ACTION,
        SETUP_JAVA_ACTION,
        SETUP_GO_ACTION,
        SETUP_ANDROID_ACTION,
        UPLOAD_ARTIFACT_ACTION,
    }
)

NODE24_EXTERNAL_ACTIONS = PINNED_EXTERNAL_ACTIONS

HOSTED_RUNNERS = frozenset(
    {
        "ubuntu-24.04",
        "windows-2022",
        "macos-15",
        "macos-15-intel",
    }
)

STABLE_CHECK_NAMES = (
    "Torturer / artifact contract (Linux)",
    "Torturer / artifact contract (Windows)",
    "Torturer / artifact contract (macOS arm64)",
    "Torturer / artifact contract (macOS Intel)",
    "Torturer / iOS Simulator core contract",
    "Torturer / Android service contract",
)

FORBIDDEN_WORKFLOW_TOKENS = (
    "pull_request_target",
    "secrets.",
    "environment:",
    "actions/cache",
)
