"""Android hosted adapter using the installed product-facing CLI seam."""
from .cli import HostedCLIAdapter


class AndroidHostedAdapter(HostedCLIAdapter):
    adapter_id = "hosted-android-cli"
