"""Linux hosted adapter using DobbyVPN's public CLI."""
from .cli import HostedCLIAdapter


class LinuxHostedAdapter(HostedCLIAdapter):
    adapter_id = "hosted-linux-cli"
