"""Exceptions and warnings emitted by ``httpx2_kerberos``.

Authentication errors keep the original ``httpx2.Response`` on the exception so
callers can inspect the status code, headers, or request that failed.

Example:
    >>> from httpx2 import Request, Response
    >>> from httpx2_kerberos.exceptions import KerberosExchangeError
    >>> response = Response(401, request=Request("GET", "https://example.test/"))
    >>> error = KerberosExchangeError("ctx step failed", response=response)
    >>> error.response is response
    True
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from httpx2 import HTTPError, RequestError

if TYPE_CHECKING:
    from httpx2 import Response


class NegotiationStepFailedWarning(Warning):
    """Warning emitted when SPNEGO returns no negotiation token."""

    pass


class NoCertificateRetrievedWarning(Warning):
    """Warning emitted when TLS channel binding data cannot be retrieved."""

    pass


class UnknownSignatureAlgorithmOID(Warning):
    """Warning emitted when a certificate signature algorithm is unsupported."""

    pass


class MutualAuthenticationError(RequestError):
    """Unable to verify the server during mutual authentication.

    :param message: Human-readable failure detail.
    :param response: Response that could not be authenticated.
    """

    def __init__(self, message: str, *, response: "Response") -> None:
        super().__init__(message, request=response.request)
        self.response = response


class KerberosExchangeError(RequestError):
    """Kerberos token exchange failed.

    :param message: Human-readable failure detail from the Kerberos backend.
    :param response: Response that triggered the failed exchange.
    """

    def __init__(self, message: str, *, response: "Response") -> None:
        super().__init__(message, request=response.request)
        self.response = response


class KerberosUnsupported(Exception):
    """Internal signal used when a server does not advertise Negotiate auth."""
