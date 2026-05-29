from functools import lru_cache

import jwt
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed


@lru_cache(maxsize=4)
def fetch_openid_configuration(discovery_url: str) -> dict:
    response = requests.get(discovery_url, timeout=5)
    response.raise_for_status()
    return response.json()


@lru_cache(maxsize=4)
def get_jwk_client(jwks_uri: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(jwks_uri)


class OIDCJWTAuthentication(BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) != 2:
            raise AuthenticationFailed("Invalid bearer token header.")

        if not settings.API_OIDC_JWT_ENABLED:
            raise AuthenticationFailed("OIDC bearer token authentication is not enabled.")

        token = auth[1].decode("utf-8")
        claims = self.decode_token(token)
        user = self.get_user_from_claims(claims)
        return (user, claims)

    def decode_token(self, token: str) -> dict:
        discovery_url = settings.API_OIDC_DISCOVERY_URL
        if not discovery_url:
            raise AuthenticationFailed("API_OIDC_DISCOVERY_URL is not configured.")

        openid_configuration = self.get_openid_configuration(discovery_url)
        issuer = settings.API_OIDC_ISSUER or openid_configuration.get("issuer")
        jwks_uri = openid_configuration.get("jwks_uri")

        if not issuer or not jwks_uri:
            raise AuthenticationFailed("OIDC discovery is missing issuer or jwks_uri.")

        try:
            signing_key = self.get_signing_key(jwks_uri, token)
            audience = settings.API_OIDC_AUDIENCE or None
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
                audience=audience,
                issuer=issuer,
                options={"verify_aud": audience is not None},
            )
        except (jwt.PyJWTError, requests.RequestException) as exc:
            raise AuthenticationFailed("Invalid bearer token.") from exc

    def get_openid_configuration(self, discovery_url: str) -> dict:
        return fetch_openid_configuration(discovery_url)

    def get_signing_key(self, jwks_uri: str, token: str) -> jwt.PyJWK:
        return get_jwk_client(jwks_uri).get_signing_key_from_jwt(token)

    def get_user_from_claims(self, claims: dict):
        email = claims.get(settings.API_OIDC_EMAIL_CLAIM)
        if not email:
            raise AuthenticationFailed(
                f"Bearer token is missing the '{settings.API_OIDC_EMAIL_CLAIM}' claim."
            )

        if (
            settings.API_OIDC_REQUIRE_VERIFIED_EMAIL
            and claims.get("email_verified") is False
        ):
            raise AuthenticationFailed("Bearer token email is not verified.")

        user = get_user_model().objects.filter(email__iexact=email).first()
        if user is None:
            raise AuthenticationFailed("No WYGIWYH user matches this bearer token.")
        if not user.is_active:
            raise AuthenticationFailed("User account is disabled.")
        return user

    def authenticate_header(self, request):
        return self.keyword
