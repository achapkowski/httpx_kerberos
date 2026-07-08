from __future__ import annotations

import os
import unittest

import httpx2

from httpx2_kerberos import HTTPKerberosAuth, MutualAuthentication


class FunctionalKerberosTests(unittest.TestCase):
    def test_successful_http_call(self) -> None:
        principal = os.environ.get("KERBEROS_PRINCIPAL")
        url = os.environ.get("KERBEROS_URL")

        if principal is None:
            self.skipTest("KERBEROS_PRINCIPAL is not set, skipping functional tests")
        if url is None:
            self.skipTest("KERBEROS_URL is not set, skipping functional tests")

        auth = HTTPKerberosAuth(
            mutual_authentication=MutualAuthentication.REQUIRED,
            principal=principal,
        )
        verify = not url.lower().startswith("https://")

        with httpx2.Client(verify=verify) as client:
            response = client.get(url, auth=auth)

        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()