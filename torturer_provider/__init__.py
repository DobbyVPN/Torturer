"""Trusted hosted-test infrastructure controllers.

Provider code owns infrastructure lifecycle only.  Functional scenario
meaning and assertions remain in :mod:`torturer_contract.functional`.
"""

from .lease_request import LeaseRequestError, RenderLeaseRequest
from .render import (
    HTTPResponse,
    RenderAPI,
    RenderAPIError,
    RenderReaper,
    RenderServiceHandle,
    RenderServiceSpec,
    RenderServiceReady,
    DisposableRenderController,
)

__all__ = [
    "DisposableRenderController",
    "HTTPResponse",
    "RenderAPI",
    "RenderAPIError",
    "RenderReaper",
    "RenderServiceHandle",
    "RenderServiceReady",
    "RenderServiceSpec",
    "LeaseRequestError",
    "RenderLeaseRequest",
]
