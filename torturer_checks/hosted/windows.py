"""Windows hosted adapter using DobbyVPN's public CLI."""
from .cli import HostedCLIAdapter


class WindowsHostedAdapter(HostedCLIAdapter):
    adapter_id = "hosted-windows-cli"
