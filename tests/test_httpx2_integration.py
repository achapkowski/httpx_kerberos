from __future__ import annotations

import base64
import re
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx2

from httpx2_kerberos import HTTPKerberosAuth, MutualAuthentication


class HTTPX2MigrationTests(unittest.TestCase):
    def test_package_source_uses_httpx2_imports(self) -> None:
        package_dir = Path(__file__).resolve().parents[1] / "httpx2_kerberos"
        legacy_import = re.compile(r"(?m)^\s*(from|import)\s+httpx\b")

        for path in package_dir.glob("*.py"):
            with self.subTest(path=path.name):
                self.assertIsNone(legacy_import.search(path.read_text()))

    def test_readme_examples_use_httpx2_names(self) -> None:
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()

        self.assertNotIn("import httpx\n", readme)
        self.assertNotIn("from httpx_kerberos", readme)
        self.assertNotIn("httpx.get(", readme)
        self.assertNotIn("``httpx_kerberos``", readme)


class HTTPX2ClientIntegrationTests(unittest.TestCase):
    def test_client_retries_401_with_negotiate_authorization(self) -> None:
        server_token = b"server-token"
        client_token = b"client-token"
        requests: list[httpx2.Request] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            requests.append(request)
            if len(requests) == 1:
                self.assertIsNone(request.headers.get("authorization"))
                return httpx2.Response(
                    401,
                    headers={
                        "www-authenticate": (
                            f"Negotiate {base64.b64encode(server_token).decode()}"
                        )
                    },
                    request=request,
                )

            self.assertEqual(
                request.headers["authorization"],
                f"Negotiate {base64.b64encode(client_token).decode()}",
            )
            return httpx2.Response(200, request=request)

        context = Mock()
        context.step.return_value = client_token
        auth = HTTPKerberosAuth(
            mutual_authentication=MutualAuthentication.DISABLED,
            send_cbt=False,
        )

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context) as client:
            with httpx2.Client(transport=httpx2.MockTransport(handler)) as http_client:
                response = http_client.get("https://example.test/", auth=auth)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(requests), 2)
        context.step.assert_called_once_with(in_token=server_token)
        client.assert_called_once()

    def test_client_returns_second_401_without_retry_loop(self) -> None:
        server_token = b"server-token"
        client_token = b"client-token"
        requests: list[httpx2.Request] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            requests.append(request)
            if len(requests) == 1:
                return httpx2.Response(
                    401,
                    headers={
                        "www-authenticate": (
                            f"Negotiate {base64.b64encode(server_token).decode()}"
                        )
                    },
                    request=request,
                )

            self.assertEqual(
                request.headers["authorization"],
                f"Negotiate {base64.b64encode(client_token).decode()}",
            )
            return httpx2.Response(401, request=request)

        context = Mock()
        context.step.return_value = client_token
        auth = HTTPKerberosAuth(send_cbt=False)

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context):
            with httpx2.Client(transport=httpx2.MockTransport(handler)) as http_client:
                response = http_client.get("https://example.test/", auth=auth)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(len(requests), 2)


if __name__ == "__main__":
    unittest.main()