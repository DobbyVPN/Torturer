"""macOS hosted adapter using DobbyVPN's public CLI."""
from .cli import HostedCLIAdapter


class MacOSHostedAdapter(HostedCLIAdapter):
    adapter_id = "hosted-macos-cli"
