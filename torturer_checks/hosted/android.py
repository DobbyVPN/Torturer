"""Fail-closed Android adapter until a test-facing profile seam exists."""

from torturer_contract.functional.engine import CapabilityUnavailable
from torturer_contract.functional.scenarios import ScenarioStep


class AndroidHostedAdapter:
    """Expose no canonical VPN capability without a profile-session driver.

    The product has an internal AndroidSessionController and the emulator
    instrumentation suite proves consent/TUN lifecycle. Torturer still has no
    stable test-facing entrypoint that supplies a profile and returns canonical
    external-identity or throughput observations, so this adapter fails closed.
    The shared engine must emit unavailable rather than executing shell-shaped
    guesses.
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
