from django.conf import settings
from django.http import JsonResponse


def authorization_server_metadata(request):
    base_url = settings.PUBLIC_BASE_URL or request.build_absolute_uri("/").rstrip("/")
    metadata = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize/",
        "token_endpoint": f"{base_url}/oauth/token/",
        "revocation_endpoint": f"{base_url}/oauth/revoke_token/",
        "introspection_endpoint": f"{base_url}/oauth/introspect/",
        "scopes_supported": sorted(settings.OAUTH2_PROVIDER["SCOPES"].keys()),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "code_challenge_methods_supported": ["S256"],
    }
    return JsonResponse(metadata)
