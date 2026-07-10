from __future__ import annotations

import base64
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from importlib.metadata import version as package_version
from types import SimpleNamespace
from unittest.mock import Mock, patch

import spnego
import spnego.exceptions
from cryptography.exceptions import UnsupportedAlgorithm
from httpx2 import Request, Response

import httpx2_kerberos.__version__ as version_module
from httpx2_kerberos import HTTPKerberosAuth, MutualAuthentication
from httpx2_kerberos.exceptions import (
    KerberosExchangeError,
    KerberosUnsupported,
    MutualAuthenticationError,
    NegotiationStepFailedWarning,
    NoCertificateRetrievedWarning,
    UnknownSignatureAlgorithmOID,
)
from httpx2_kerberos.kerberos import (
    CachedCert,
    _cached_certs,
    format_auth_header,
    get_certificate_hash,
    get_channel_bindings_application_data,
    negotiate_value,
    sanitize_response,
)


def make_negotiate_response(
    url: str = "https://example.test/",
    token: bytes = b"token",
    status_code: int = 401,
) -> Response:
    return Response(
        status_code,
        headers={"www-authenticate": f"Negotiate {base64.b64encode(token).decode()}"},
        request=Request("GET", url),
    )


class KerberosHelperTests(unittest.TestCase):
    def test_version_metadata_is_importable(self) -> None:
        self.assertEqual(version_module.__title__, "httpx2_kerberos")
        self.assertEqual(
            version_module.__version__,
            package_version("httpx2_kerberos"),
        )

    def test_cached_cert_expired_compares_against_current_time(self) -> None:
        expired = CachedCert(
            SimpleNamespace(not_valid_after_utc=datetime.now(timezone.utc) - timedelta(days=1)),
            b"app-data",
        )
        current = CachedCert(
            SimpleNamespace(not_valid_after_utc=datetime.now(timezone.utc) + timedelta(days=1)),
            b"app-data",
        )

        self.assertTrue(expired.expired)
        self.assertFalse(current.expired)

    def test_format_auth_header_leaves_short_values_alone(self) -> None:
        self.assertIsNone(format_auth_header(None))
        self.assertEqual(format_auth_header("Negotiate abc"), "Negotiate abc")

    def test_format_auth_header_truncates_long_values(self) -> None:
        value = "Negotiate " + "a" * 80

        self.assertEqual(format_auth_header(value), value[:48] + "..." + value[-24:])

    def test_negotiate_value_extracts_base64_token(self) -> None:
        token = b"kerberos-token"
        response = SimpleNamespace(
            headers={
                "www-authenticate": (
                    "Basic realm=example, "
                    f"Negotiate {base64.b64encode(token).decode()}, NTLM"
                )
            }
        )

        self.assertEqual(negotiate_value(response), token)

    def test_negotiate_value_returns_none_without_negotiate_header(self) -> None:
        response = SimpleNamespace(headers={"www-authenticate": "Basic realm=example"})

        self.assertIsNone(negotiate_value(response))

    def test_get_certificate_hash_uses_sha256_for_sha1_certificates(self) -> None:
        certificate_der = b"certificate"
        cert = SimpleNamespace(signature_hash_algorithm=SimpleNamespace(name="sha1"))
        digest = Mock()
        digest.finalize.return_value = b"certificate-hash"

        with patch("httpx2_kerberos.kerberos.hashes.Hash", return_value=digest) as hash_cls:
            certificate_hash = get_certificate_hash(cert, certificate_der)

        self.assertEqual(certificate_hash, b"certificate-hash")
        self.assertEqual(hash_cls.call_args.args[0].name, "sha256")
        digest.update.assert_called_once_with(certificate_der)

    def test_get_certificate_hash_uses_certificate_signature_algorithm(self) -> None:
        certificate_der = b"certificate"
        algorithm = SimpleNamespace(name="sha512")
        cert = SimpleNamespace(signature_hash_algorithm=algorithm)
        digest = Mock()
        digest.finalize.return_value = b"certificate-hash"

        with patch("httpx2_kerberos.kerberos.hashes.Hash", return_value=digest) as hash_cls:
            certificate_hash = get_certificate_hash(cert, certificate_der)

        self.assertEqual(certificate_hash, b"certificate-hash")
        self.assertIs(hash_cls.call_args.args[0], algorithm)
        digest.update.assert_called_once_with(certificate_der)

    def test_get_certificate_hash_warns_when_signature_algorithm_is_unknown(self) -> None:
        class Cert:
            @property
            def signature_hash_algorithm(self):
                raise UnsupportedAlgorithm("unknown oid", None)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            certificate_hash = get_certificate_hash(Cert(), b"certificate")

        self.assertIsNone(certificate_hash)
        self.assertEqual(caught[0].category, UnknownSignatureAlgorithmOID)

    def test_get_channel_bindings_returns_none_for_http(self) -> None:
        response = Response(200, request=Request("GET", "http://example.test/"))

        self.assertEqual(get_channel_bindings_application_data(response), (None, None))

    def test_get_channel_bindings_warns_when_certificate_cannot_be_retrieved(self) -> None:
        response = Response(200, request=Request("GET", "https://example.test/"))

        with patch("httpx2_kerberos.kerberos.ssl.get_server_certificate", side_effect=ssl_error()), patch(
            "httpx2_kerberos.kerberos._LOGGER.warning"
        ), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = get_channel_bindings_application_data(response)

        self.assertEqual(result, (None, None))
        self.assertEqual(caught[0].category, NoCertificateRetrievedWarning)

    def test_get_channel_bindings_builds_tls_server_endpoint_data(self) -> None:
        response = Response(200, request=Request("GET", "https://example.test/"))
        cert = object()

        with patch("httpx2_kerberos.kerberos.ssl.get_server_certificate", return_value="pem"), patch(
            "httpx2_kerberos.kerberos.ssl.PEM_cert_to_DER_cert", return_value=b"der"
        ), patch("httpx2_kerberos.kerberos.x509.load_der_x509_certificate", return_value=cert), patch(
            "httpx2_kerberos.kerberos.get_certificate_hash", return_value=b"hash"
        ):
            result = get_channel_bindings_application_data(response)

        self.assertEqual(result, (cert, b"tls-server-end-point:hash"))

    def test_get_channel_bindings_returns_none_when_certificate_hash_is_unavailable(self) -> None:
        response = Response(200, request=Request("GET", "https://example.test/"))

        with patch("httpx2_kerberos.kerberos.ssl.get_server_certificate", return_value="pem"), patch(
            "httpx2_kerberos.kerberos.ssl.PEM_cert_to_DER_cert", return_value=b"der"
        ), patch("httpx2_kerberos.kerberos.x509.load_der_x509_certificate", return_value=object()), patch(
            "httpx2_kerberos.kerberos.get_certificate_hash", return_value=None
        ):
            result = get_channel_bindings_application_data(response)

        self.assertEqual(result, (None, None))

    def test_sanitize_response_keeps_safe_headers_and_clears_body(self) -> None:
        request = Request("GET", "https://example.test/")
        response = Response(
            500,
            headers={"date": "today", "server": "unit", "x-secret": "hide"},
            content=b"secret",
            request=request,
        )

        sanitize_response(response)

        self.assertEqual(response.headers["date"], "today")
        self.assertEqual(response.headers["server"], "unit")
        self.assertEqual(response.headers["content-length"], "0")
        self.assertNotIn("x-secret", response.headers)
        self.assertEqual(response.content, b"")
        self.assertTrue(response.is_stream_consumed)


class HTTPKerberosAuthTests(unittest.TestCase):
    def tearDown(self) -> None:
        _cached_certs.clear()

    def test_mutual_authentication_error_keeps_response(self) -> None:
        response = Response(200, request=Request("GET", "https://example.test/"))
        error = MutualAuthenticationError("failed", response=response)

        self.assertIs(error.response, response)
        self.assertIs(error.request, response.request)

    def test_kerberos_exchange_error_keeps_response(self) -> None:
        response = Response(401, request=Request("GET", "https://example.test/"))
        error = KerberosExchangeError("failed", response=response)

        self.assertIs(error.response, response)
        self.assertIs(error.request, response.request)

    def test_auth_flow_handles_initial_non_401_response(self) -> None:
        auth = HTTPKerberosAuth(send_cbt=False)
        request = Request("GET", "https://example.test/")
        response = Response(200, request=request)
        flow = auth.auth_flow(request)

        self.assertIs(next(flow), request)
        with patch.object(auth, "handle_other") as handle_other, self.assertRaises(StopIteration):
            flow.send(response)

        handle_other.assert_called_once_with(response)

    def test_auth_flow_stops_when_server_does_not_offer_negotiate(self) -> None:
        auth = HTTPKerberosAuth(send_cbt=False)
        request = Request("GET", "https://example.test/")
        response = Response(401, headers={}, request=request)
        flow = auth.auth_flow(request)

        self.assertIs(next(flow), request)
        with self.assertRaises(StopIteration):
            flow.send(response)
        self.assertNotIn("authorization", request.headers)

    def test_handle_auth_error_authenticates_when_negotiate_is_available(self) -> None:
        auth = HTTPKerberosAuth(send_cbt=False)
        request = Request("GET", "https://example.test/")
        response = make_negotiate_response()

        with patch.object(auth, "authenticate_user") as authenticate_user:
            auth.handle_auth_error(request, response)

        authenticate_user.assert_called_once_with(request, response)

    def test_handle_auth_error_raises_when_negotiate_is_missing(self) -> None:
        auth = HTTPKerberosAuth(send_cbt=False)
        request = Request("GET", "https://example.test/")
        response = Response(401, headers={}, request=request)

        with self.assertRaises(KerberosUnsupported):
            auth.handle_auth_error(request, response)

    def test_auth_flow_caches_missing_channel_bindings(self) -> None:
        auth = HTTPKerberosAuth(send_cbt=True)
        request = Request("GET", "https://example.test/")
        response = Response(401, headers={}, request=request)
        flow = auth.auth_flow(request)

        self.assertIs(next(flow), request)
        with patch(
            "httpx2_kerberos.kerberos.get_channel_bindings_application_data",
            return_value=(None, None),
        ), self.assertRaises(StopIteration):
            flow.send(response)

        self.assertIsNone(auth._cbts["example.test"])

    def test_auth_flow_uses_cached_channel_bindings(self) -> None:
        cert = SimpleNamespace(
            not_valid_after_utc=datetime.now(timezone.utc) + timedelta(days=1)
        )
        _cached_certs["example.test"] = CachedCert(cert, b"app-data")
        auth = HTTPKerberosAuth(send_cbt=True)
        auth._cbts["example.test"] = object()
        request = Request("GET", "https://example.test/")
        response = Response(401, headers={}, request=request)
        flow = auth.auth_flow(request)

        self.assertIs(next(flow), request)
        with patch(
            "httpx2_kerberos.kerberos.get_channel_bindings_application_data"
        ) as get_channel_bindings, patch.object(
            auth, "handle_auth_error", side_effect=KerberosUnsupported
        ), self.assertRaises(StopIteration):
            flow.send(response)

        get_channel_bindings.assert_not_called()

    def test_auth_flow_discards_expired_cached_channel_bindings(self) -> None:
        cert = SimpleNamespace(
            not_valid_after_utc=datetime.now(timezone.utc) - timedelta(days=1)
        )
        _cached_certs["example.test"] = CachedCert(cert, b"app-data")
        auth = HTTPKerberosAuth(send_cbt=True)
        auth._cbts["example.test"] = object()
        request = Request("GET", "https://example.test/")
        response = Response(401, headers={}, request=request)
        flow = auth.auth_flow(request)

        self.assertIs(next(flow), request)
        with patch(
            "httpx2_kerberos.kerberos.get_channel_bindings_application_data",
            return_value=(None, None),
        ), patch.object(auth, "handle_auth_error", side_effect=KerberosUnsupported), self.assertRaises(StopIteration):
            flow.send(response)

        self.assertNotIn("example.test", _cached_certs)
        self.assertIsNone(auth._cbts["example.test"])

    def test_auth_flow_caches_retrieved_channel_bindings(self) -> None:
        cert = SimpleNamespace(
            not_valid_after_utc=datetime.now(timezone.utc) + timedelta(days=1)
        )
        auth = HTTPKerberosAuth(send_cbt=True)
        request = Request("GET", "https://example.test/")
        response = Response(401, headers={}, request=request)
        flow = auth.auth_flow(request)

        self.assertIs(next(flow), request)
        with patch(
            "httpx2_kerberos.kerberos.get_channel_bindings_application_data",
            return_value=(cert, b"app-data"),
        ), patch.object(auth, "handle_auth_error", side_effect=KerberosUnsupported), self.assertRaises(StopIteration):
            flow.send(response)

        self.assertIs(_cached_certs["example.test"].cert, cert)
        self.assertEqual(_cached_certs["example.test"].application_data, b"app-data")
        self.assertEqual(auth._cbts["example.test"].application_data, b"app-data")

    def test_handle_other_requires_mutual_authentication_for_success_without_token(self) -> None:
        auth = HTTPKerberosAuth()
        response = Response(200, request=Request("GET", "https://example.test/"))

        with patch("httpx2_kerberos.kerberos._LOGGER.error"), self.assertRaises(MutualAuthenticationError):
            auth.handle_other(response)

    def test_handle_other_sanitizes_required_mutual_authentication_error_response(self) -> None:
        auth = HTTPKerberosAuth()
        response = Response(
            500,
            headers={"x-secret": "hide"},
            content=b"secret",
            request=Request("GET", "https://example.test/"),
        )

        with patch("httpx2_kerberos.kerberos._LOGGER.error"):
            auth.handle_other(response)

        self.assertEqual(response.content, b"")
        self.assertNotIn("x-secret", response.headers)

    def test_handle_other_marks_auth_done_when_server_authenticates(self) -> None:
        token = base64.b64encode(b"server-token").decode()
        auth = HTTPKerberosAuth()
        response = Response(
            200,
            headers={"www-authenticate": f"Negotiate {token}"},
            request=Request("GET", "https://example.test/"),
        )

        with patch.object(auth, "authenticate_server", return_value=True):
            auth.handle_other(response)

        self.assertTrue(auth.auth_done)

    def test_handle_other_raises_when_server_authentication_fails(self) -> None:
        token = base64.b64encode(b"server-token").decode()
        auth = HTTPKerberosAuth()
        response = Response(
            200,
            headers={"www-authenticate": f"Negotiate {token}"},
            request=Request("GET", "https://example.test/"),
        )

        with patch.object(auth, "authenticate_server", return_value=False), patch(
            "httpx2_kerberos.kerberos._LOGGER.error"
        ), self.assertRaises(MutualAuthenticationError):
            auth.handle_other(response)

    def test_handle_other_optional_allows_response_without_token(self) -> None:
        auth = HTTPKerberosAuth(mutual_authentication=MutualAuthentication.OPTIONAL)
        response = Response(200, request=Request("GET", "https://example.test/"))

        auth.handle_other(response)

    def test_handle_other_optional_raises_when_server_authentication_fails(self) -> None:
        auth = HTTPKerberosAuth(mutual_authentication=MutualAuthentication.OPTIONAL)
        response = make_negotiate_response(status_code=200)

        with patch.object(auth, "authenticate_server", return_value=False), patch(
            "httpx2_kerberos.kerberos._LOGGER.error"
        ), self.assertRaises(MutualAuthenticationError):
            auth.handle_other(response)

    def test_handle_other_required_error_response_can_keep_body(self) -> None:
        auth = HTTPKerberosAuth(sanitize_mutual_error_response=False)
        response = Response(
            500,
            headers={"x-detail": "keep"},
            content=b"detail",
            request=Request("GET", "https://example.test/"),
        )

        with patch("httpx2_kerberos.kerberos._LOGGER.error"):
            auth.handle_other(response)

        self.assertEqual(response.content, b"detail")
        self.assertEqual(response.headers["x-detail"], "keep")

    def test_handle_other_disabled_skips_mutual_authentication(self) -> None:
        auth = HTTPKerberosAuth(mutual_authentication=MutualAuthentication.DISABLED)
        response = Response(200, request=Request("GET", "https://example.test/"))

        auth.handle_other(response)

    def test_authenticate_user_sets_authorization_header(self) -> None:
        auth = HTTPKerberosAuth(send_cbt=False)
        request = Request("GET", "https://example.test/")
        response = make_negotiate_response()

        with patch.object(
            auth, "generate_request_header", return_value="Negotiate client-token"
        ) as generate_request_header:
            auth.authenticate_user(request, response)

        self.assertEqual(request.headers["authorization"], "Negotiate client-token")
        generate_request_header.assert_called_once_with(response, "example.test")

    def test_generate_request_header_uses_default_spnego_arguments(self) -> None:
        response = make_negotiate_response("http://www.example.org/")
        auth = HTTPKerberosAuth(send_cbt=False)
        context = Mock()
        context.step.return_value = b"GSSRESPONSE"

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context) as client:
            header = auth.generate_request_header(response, "www.example.org")

        expected_flags = spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth
        self.assertEqual(header, "Negotiate R1NTUkVTUE9OU0U=")
        self.assertEqual(
            client.call_args.kwargs,
            {
                "username": None,
                "hostname": "www.example.org",
                "service": "HTTP",
                "channel_bindings": None,
                "context_req": expected_flags,
                "protocol": "kerberos",
            },
        )
        context.step.assert_called_once_with(in_token=b"token")

    def test_generate_request_header_uses_spnego_client(self) -> None:
        in_token = b"server-token"
        out_token = b"client-token"
        response = SimpleNamespace(
            headers={"www-authenticate": f"Negotiate {base64.b64encode(in_token).decode()}"}
        )
        auth = HTTPKerberosAuth(
            mutual_authentication=MutualAuthentication.REQUIRED,
            delegate=True,
            principal="user@example.test:secret",
            hostname_override="kerberos.example.test",
            send_cbt=False,
        )
        context = Mock()
        context.step.return_value = out_token

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context) as client:
            header = auth.generate_request_header(response, "service.example.test")

        self.assertEqual(header, f"Negotiate {base64.b64encode(out_token).decode()}")
        context.step.assert_called_once_with(in_token=in_token)
        client.assert_called_once()
        self.assertEqual(client.call_args.kwargs["username"], "user@example.test")
        self.assertEqual(client.call_args.kwargs["password"], "secret")
        self.assertEqual(client.call_args.kwargs["hostname"], "kerberos.example.test")
        self.assertEqual(client.call_args.kwargs["service"], "HTTP")
        self.assertEqual(client.call_args.kwargs["protocol"], "kerberos")
        self.assertEqual(
            client.call_args.kwargs["context_req"],
            spnego.ContextReq.sequence_detect
            | spnego.ContextReq.delegate
            | spnego.ContextReq.mutual_auth,
        )

    def test_generate_request_header_uses_custom_service(self) -> None:
        response = make_negotiate_response("http://www.example.org/")
        auth = HTTPKerberosAuth(service="barfoo", send_cbt=False)
        context = Mock()
        context.step.return_value = b"GSSRESPONSE"

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context) as client:
            auth.generate_request_header(response, "www.example.org")

        self.assertEqual(client.call_args.kwargs["service"], "barfoo")

    def test_generate_request_header_uses_principal_without_password(self) -> None:
        response = make_negotiate_response("http://www.example.org/")
        auth = HTTPKerberosAuth(principal="user@REALM", send_cbt=False)
        context = Mock()
        context.step.return_value = b"GSSRESPONSE"

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context) as client:
            auth.generate_request_header(response, "www.example.org")

        self.assertEqual(client.call_args.kwargs["username"], "user@REALM")
        self.assertNotIn("password", client.call_args.kwargs)

    def test_generate_request_header_uses_hostname_override(self) -> None:
        response = make_negotiate_response("http://www.example.org/")
        auth = HTTPKerberosAuth(hostname_override="otherhost.otherdomain.org", send_cbt=False)
        context = Mock()
        context.step.return_value = b"GSSRESPONSE"

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context) as client:
            auth.generate_request_header(response, "www.example.org")

        self.assertEqual(client.call_args.kwargs["hostname"], "otherhost.otherdomain.org")

    def test_generate_request_header_uses_hostname_override_mapping(self) -> None:
        response = make_negotiate_response("http://www.example.org/")
        auth = HTTPKerberosAuth(
            hostname_override={"www.example.org": "otherhost.otherdomain.org"},
            send_cbt=False,
        )
        context = Mock()
        context.step.return_value = b"GSSRESPONSE"

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context) as client:
            auth.generate_request_header(response, "www.example.org")

        self.assertEqual(client.call_args.kwargs["hostname"], "otherhost.otherdomain.org")

    def test_generate_request_header_uses_request_host_for_missing_hostname_override_mapping(self) -> None:
        response = make_negotiate_response("http://www.example.org/")
        auth = HTTPKerberosAuth(
            hostname_override={"api.example.org": "kerberos.example.org"},
            send_cbt=False,
        )
        context = Mock()
        context.step.return_value = b"GSSRESPONSE"

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context) as client:
            auth.generate_request_header(response, "www.example.org")

        self.assertEqual(client.call_args.kwargs["hostname"], "www.example.org")

    def test_generate_request_header_raises_exchange_error_when_context_init_fails(self) -> None:
        response = make_negotiate_response("http://www.example.org/")
        auth = HTTPKerberosAuth(send_cbt=False)

        with patch(
            "httpx2_kerberos.kerberos.spnego.client",
            side_effect=spnego.exceptions.BadNameError(),
        ) as client, patch("httpx2_kerberos.kerberos._LOGGER.exception"), self.assertRaisesRegex(
            KerberosExchangeError, "ctx init failed"
        ):
            auth.generate_request_header(response, "www.example.org")

        client.assert_called_once()

    def test_authenticate_server_steps_existing_context(self) -> None:
        token = base64.b64encode(b"server-token").decode()
        response = Response(
            200,
            headers={"www-authenticate": f"Negotiate {token}"},
            request=Request("GET", "https://example.test/"),
        )
        auth = HTTPKerberosAuth()
        context = Mock()
        auth._context["example.test"] = context

        self.assertTrue(auth.authenticate_server(response))
        context.step.assert_called_once_with(in_token=b"server-token")

    def test_authenticate_server_returns_false_when_context_step_fails(self) -> None:
        token = base64.b64encode(b"server-token").decode()
        response = Response(
            200,
            headers={"www-authenticate": f"Negotiate {token}"},
            request=Request("GET", "https://example.test/"),
        )
        auth = HTTPKerberosAuth()
        context = Mock()
        context.step.side_effect = spnego.exceptions.SpnegoError(error_code=1)
        auth._context["example.test"] = context

        with patch("httpx2_kerberos.kerberos._LOGGER.exception"):
            self.assertFalse(auth.authenticate_server(response))

    def test_generate_request_header_warns_when_context_step_returns_none(self) -> None:
        response = SimpleNamespace(headers={"www-authenticate": "Negotiate "})
        auth = HTTPKerberosAuth(send_cbt=False)
        context = Mock()
        context.step.return_value = None

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            header = auth.generate_request_header(response, "example.test")

        self.assertEqual(header, "Negotiate ")
        self.assertEqual(caught[0].category, NegotiationStepFailedWarning)

    def test_generate_request_header_raises_exchange_error_when_context_step_fails(self) -> None:
        response = Response(
            401,
            headers={"www-authenticate": "Negotiate "},
            request=Request("GET", "https://example.test/"),
        )
        auth = HTTPKerberosAuth(send_cbt=False)
        context = Mock()
        context.step.side_effect = spnego.exceptions.SpnegoError(error_code=1)

        with patch("httpx2_kerberos.kerberos.spnego.client", return_value=context), patch(
            "httpx2_kerberos.kerberos._LOGGER.exception"
        ), self.assertRaises(KerberosExchangeError):
            auth.generate_request_header(response, "example.test")


def ssl_error() -> Exception:
    import ssl

    return ssl.SSLError("certificate unavailable")


if __name__ == "__main__":
    unittest.main()