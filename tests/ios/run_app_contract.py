"""Run the fixed public Dobby iOS Simulator app contract.

H4 may invoke this from an ephemeral GitHub-hosted macOS runner only after it
pins the H3 helper revision.  It accepts no profiles, credentials, endpoint
configuration, or shell fragments.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


if __package__ in {None, ""}:  # pragma: no cover - exercised by the H4 shell entry point
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from torturer_checks.ios_simulator_app import (  # noqa: E402
    IOSSimulatorAppContractError,
    SubprocessCommandRunner,
    public_ios_simulator_app_contract,
    run_ios_simulator_app_contract,
)


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument(
        "--architecture",
        choices=("arm64", "amd64"),
        default="arm64",
        help="required Simulator CPU slice (arm64 for hosted runners; amd64 for Intel macOS)",
    )
    parser.add_argument(
        "--with-xctest",
        action="store_true",
        help="run the fixed named app XCTest after build/install/launch/terminate evidence",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        evidence = run_ios_simulator_app_contract(
            candidate_root=args.candidate_root,
            repository=args.source_repository,
            commit_sha=args.commit_sha,
            work_dir=args.work_dir,
            runner=SubprocessCommandRunner(),
            with_xctest=args.with_xctest,
            contract=public_ios_simulator_app_contract(args.architecture),
        )
    except IOSSimulatorAppContractError as error:
        print(f"iOS Simulator Torturer check failed: {error}", file=sys.stderr)
        return 1
    print(
        "iOS Simulator Torturer app contract passed: "
        f"{evidence.simulator.name} ({evidence.simulator.runtime}), "
        f"{evidence.app.app_path.name}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
