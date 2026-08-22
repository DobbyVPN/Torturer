"""Fail-closed Android adapter until a product-facing functional seam exists."""

from torturer_contract.functional.engine import CapabilityUnavailable
from torturer_contract.functional.scenarios import ScenarioStep


class AndroidHostedAdapter:
    """Expose no canonical VPN capability without a profile/session API.

    The Android emulator instrumentation suite remains responsible for the
    product-owned consent/TUN lifecycle. It does not provide the CLI contract
    required to claim canonical profile, external-identity, or throughput
    scenarios, so the shared engine must emit unavailable for this entry
    point rather than executing shell-shaped guesses.
    """

    adapter_id = "hosted-android-app"
    adapter_version = "v2"

    def __init__(self, *, runner, **kwargs) -> None:
        del kwargs
        self.runner = runner

    @property
    def capabilities(self):
        return frozenset()

    def execute(self, step: ScenarioStep):
        del step
        raise CapabilityUnavailable()

    def reset(self, timeout_seconds: float = 30.0) -> None:
        del timeout_seconds
