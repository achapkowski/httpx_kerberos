Usage
=====

The examples on this page are configuration examples. They do not contact a
Kerberos-protected endpoint, so they can be validated by Sphinx doctest without
requiring a ticket cache, domain account, or live server.

Basic Authentication Object
---------------------------

Create an auth object and pass it to ``httpx2`` as the ``auth`` argument when
making real requests.

.. doctest:: basic-auth

   >>> import httpx2
   >>> from httpx2_kerberos import HTTPKerberosAuth, MutualAuthentication
   >>> auth = HTTPKerberosAuth(mutual_authentication=MutualAuthentication.OPTIONAL)
   >>> isinstance(auth, httpx2.Auth)
   True
   >>> auth.mutual_authentication == MutualAuthentication.OPTIONAL
   True

Hostname Overrides
------------------

Use a string override when every request made by the auth object should use the
same Kerberos service hostname.

.. doctest:: hostname-string

   >>> from httpx2_kerberos import HTTPKerberosAuth
   >>> auth = HTTPKerberosAuth(hostname_override="internal.example.test")
   >>> auth.hostname_override
   'internal.example.test'

Use a mapping override when one auth object makes requests to multiple DNS
hostnames that need different Kerberos service hostnames.

.. doctest:: hostname-mapping

   >>> from httpx2_kerberos import HTTPKerberosAuth
   >>> auth = HTTPKerberosAuth(
   ...     hostname_override={
   ...         "external-a.example.test": "internal-a.example.test",
   ...         "external-b.example.test": "internal-b.example.test",
   ...     }
   ... )
   >>> auth.hostname_override["external-a.example.test"]
   'internal-a.example.test'

Explicit Principal
------------------

Pass ``principal`` when the default Kerberos credentials are not the credentials
that should be used for the request.

.. doctest:: principal

   >>> from httpx2_kerberos import HTTPKerberosAuth
   >>> auth = HTTPKerberosAuth(principal="user@REALM")
   >>> auth.principal
   'user@REALM'

Channel Binding
---------------

Channel binding is enabled by default for HTTPS requests. It can be disabled for
servers that cannot handle Extended Protection for Authentication.

.. doctest:: channel-binding

   >>> from httpx2_kerberos import HTTPKerberosAuth
   >>> auth = HTTPKerberosAuth(send_cbt=False)
   >>> auth.send_cbt
   False