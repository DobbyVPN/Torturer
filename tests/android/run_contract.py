#!/usr/bin/env python3
"""Run the public Android Torturer contract against one checked-out candidate.

The intended GitHub-hosted invocation is:

    python3 tests/android/run_contract.py \
      --candidate-root "$GITHUB_WORKSPACE/candidate" \
      --commit-sha "$CANDIDATE_COMMIT" \
      --sdk-root "$ANDROID_SDK_ROOT" \
      --work-dir "$RUNNER_TEMP/torturer-android"

It builds only :app:assembleDebug and :app:assembleDebugAndroidTest, starts an
API-35 no-window emulator, installs those exact outputs, and then calls the
candidate-owned connectedDebugAndroidTest lifecycle target.  It never passes a
VPN configuration, credentials, or consent result to the app.
"""

from pathlib import Path
import sys


# Running a file makes Python put tests/android, rather than the Torturer root,
# on sys.path.  Keep this thin launcher usable without installing a package.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from torturer_checks.android import AndroidContractError, main


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AndroidContractError as error:
        print(f"Android Torturer check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
