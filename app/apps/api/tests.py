from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import RequestFactory, SimpleTestCase, override_settings
from rest_framework.exceptions import AuthenticationFailed

from apps.api.authentication import OIDCJWTAuthentication


@override_settings(
    API_OIDC_JWT_ENABLED=True,
    API_OIDC_DISCOVERY_URL="https://keycloak.example/realms/home/.well-known/openid-configuration",
    API_OIDC_ISSUER="https://keycloak.example/realms/home",
    API_OIDC_AUDIENCE="wygiwyh",
    API_OIDC_EMAIL_CLAIM="email",
    API_OIDC_REQUIRE_VERIFIED_EMAIL=True,
)
class OIDCJWTAuthenticationTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.authentication = OIDCJWTAuthentication()

    def test_returns_none_without_bearer_header(self):
        request = self.factory.get("/api/accounts/")
        self.assertIsNone(self.authentication.authenticate(request))

    def test_authenticates_existing_user_from_email_claim(self):
        request = self.factory.get(
            "/api/accounts/",
            HTTP_AUTHORIZATION="Bearer access-token",
        )
        user = Mock(is_active=True)
        user.email = "user@example.com"

        with patch.object(
            self.authentication,
            "get_openid_configuration",
            return_value={
                "issuer": "https://keycloak.example/realms/home",
                "jwks_uri": "https://keycloak.example/realms/home/protocol/openid-connect/certs",
            },
        ), patch.object(
            self.authentication,
            "get_signing_key",
            return_value=SimpleNamespace(key="dummy-signing-key"),
        ), patch(
            "apps.api.authentication.jwt.decode",
            return_value={
                "email": "user@example.com",
                "email_verified": True,
                "iss": "https://keycloak.example/realms/home",
                "aud": "wygiwyh",
            },
        ), patch(
            "apps.api.authentication.get_user_model",
        ) as mock_get_user_model:
            mock_get_user_model.return_value.objects.filter.return_value.first.return_value = (
                user
            )
            authenticated_user, claims = self.authentication.authenticate(request)

        self.assertEqual(authenticated_user, user)
        self.assertEqual(claims["email"], user.email)

    def test_rejects_token_without_matching_user(self):
        request = self.factory.get(
            "/api/accounts/",
            HTTP_AUTHORIZATION="Bearer access-token",
        )

        with patch.object(
            self.authentication,
            "get_openid_configuration",
            return_value={
                "issuer": "https://keycloak.example/realms/home",
                "jwks_uri": "https://keycloak.example/realms/home/protocol/openid-connect/certs",
            },
        ), patch.object(
            self.authentication,
            "get_signing_key",
            return_value=SimpleNamespace(key="dummy-signing-key"),
        ), patch(
            "apps.api.authentication.jwt.decode",
            return_value={
                "email": "missing@example.com",
                "email_verified": True,
                "iss": "https://keycloak.example/realms/home",
                "aud": "wygiwyh",
            },
        ), patch(
            "apps.api.authentication.get_user_model",
        ) as mock_get_user_model:
            mock_get_user_model.return_value.objects.filter.return_value.first.return_value = (
                None
            )
            with self.assertRaises(AuthenticationFailed):
                self.authentication.authenticate(request)
