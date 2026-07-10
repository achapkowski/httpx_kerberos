"""Public API for HTTPX2 Kerberos authentication.

The package exposes :class:`HTTPKerberosAuth` for use with ``httpx2`` request
and client calls, plus the public exception types raised by the authentication
flow.

Example:
    >>> from httpx2_kerberos import HTTPKerberosAuth, MutualAuthentication
    >>> auth = HTTPKerberosAuth(mutual_authentication=MutualAuthentication.OPTIONAL)
    >>> auth.mutual_authentication == MutualAuthentication.OPTIONAL
    True
"""

from .exceptions import KerberosExchangeError, MutualAuthenticationError
from .kerberos import HTTPKerberosAuth, MutualAuthentication


__all__ = (
    "KerberosExchangeError",
    "MutualAuthenticationError",
    "HTTPKerberosAuth",
    "MutualAuthentication",
)
