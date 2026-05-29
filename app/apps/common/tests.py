import os
from unittest.mock import patch

from django.contrib.auth.hashers import check_password
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from oauth2_provider.models import get_application_model


Application = get_application_model()


@override_settings(
    PUBLIC_BASE_URL="https://wygiwyh.example.com",
    OAUTH2_PROVIDER={"SCOPES": {"mcp": "Access WYGIWYH from MCP clients."}},
)
class AuthorizationServerMetadataTests(SimpleTestCase):
    def test_returns_oauth_authorization_server_metadata(self):
        response = self.client.get(reverse("oauth-authorization-server-metadata"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["issuer"], "https://wygiwyh.example.com")
        self.assertEqual(
            response.json()["authorization_endpoint"],
            "https://wygiwyh.example.com/oauth/authorize/",
        )
        self.assertEqual(response.json()["scopes_supported"], ["mcp"])


class SetupOAuthCommandTests(TestCase):
    @patch.dict(
        os.environ,
        {
            "MCP_OAUTH_CLIENT_ID": "mcp-wygiwyh",
            "MCP_OAUTH_CLIENT_SECRET": "super-secret",
            "MCP_OAUTH_REDIRECT_URIS": "http://127.0.0.1:8765/callback",
        },
        clear=False,
    )
    def test_creates_mcp_oauth_application(self):
        call_command("setup_oauth")

        application = Application.objects.get(client_id="mcp-wygiwyh")
        self.assertEqual(application.name, "WYGIWYH MCP")
        self.assertEqual(application.client_type, Application.CLIENT_CONFIDENTIAL)
        self.assertEqual(
            application.authorization_grant_type,
            Application.GRANT_AUTHORIZATION_CODE,
        )
        self.assertEqual(
            application.redirect_uris,
            "http://127.0.0.1:8765/callback",
        )
        self.assertFalse(application.skip_authorization)
        self.assertTrue(check_password("super-secret", application.client_secret))

    @patch.dict(
        os.environ,
        {
            "MCP_OAUTH_CLIENT_ID": "mcp-wygiwyh",
            "MCP_OAUTH_CLIENT_SECRET": "new-secret",
            "MCP_OAUTH_REDIRECT_URIS": "http://127.0.0.1:8765/callback http://localhost:8765/callback",
            "MCP_OAUTH_CLIENT_NAME": "WYGIWYH MCP Production",
            "MCP_OAUTH_SKIP_AUTHORIZATION": "true",
        },
        clear=False,
    )
    def test_updates_existing_mcp_oauth_application(self):
        Application.objects.create(
            client_id="mcp-wygiwyh",
            client_secret="old-secret",
            name="Old Name",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://127.0.0.1:8765/callback",
            skip_authorization=False,
        )

        call_command("setup_oauth")

        application = Application.objects.get(client_id="mcp-wygiwyh")
        self.assertEqual(application.name, "WYGIWYH MCP Production")
        self.assertEqual(
            application.redirect_uris,
            "http://127.0.0.1:8765/callback http://localhost:8765/callback",
        )
        self.assertTrue(application.skip_authorization)
        self.assertTrue(check_password("new-secret", application.client_secret))
