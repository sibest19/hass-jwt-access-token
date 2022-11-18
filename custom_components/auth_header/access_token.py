"""Cookie Authentication provider.

Allow access to users based on a cookie set by a reverse-proxy.
"""

import logging
from typing import Any, Dict, Optional, cast

import jwt
from aiohttp.web_request import Request
from homeassistant.auth.models import Credentials, UserMeta
from homeassistant.auth.providers import (
    AUTH_PROVIDERS,
    AuthProvider,
    FlowResult,
    LoginFlow,
)
from homeassistant.auth.providers.trusted_networks import (
    InvalidAuthError,
    InvalidUserError,
)
from homeassistant.core import callback
from jwt import PyJWKClient

_LOGGER = logging.getLogger(__name__)

CONF_JWKS_URL = "jwks_url"
CONF_COOKIE_NAME = "cookie_name"
CONF_AUDIENCE = "audience"
CONF_USERNAME_CLAIM_KEY = "username_claim_key"


@AUTH_PROVIDERS.register("access_token")
class AccessTokenAuthProvider(AuthProvider):
    """Logs in users from an access token stored in the cookie"""

    DEFAULT_TITLE = "Access Token"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    @property
    def type(self) -> str:
        return "access_token"

    @property
    def support_mfa(self) -> bool:
        """Access Token Authentication Provider does not support MFA."""

        return False

    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        """Return a flow to login."""

        assert context is not None

        cookie_name = self.config[CONF_COOKIE_NAME]

        request = cast(Request, context.get("request"))

        access_token = None

        if cookie_name in request.cookies:
            access_token = request.cookies[cookie_name]

        return AccessTokenLoginFlow(self, access_token)

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        Will be used to populate info when creating a new user.
        """

        username = credentials.data["username"]

        return UserMeta(name=username, is_active=True)

    async def async_get_or_create_credentials(
        self, flow_result: Dict[str, Any]
    ) -> Credentials:
        """Get credentials based on the flow result."""

        # Extracts the username from the JWT claims.
        username = flow_result.get(self.config[CONF_USERNAME_CLAIM_KEY])

        assert username is not None

        for user in await self.store.async_get_users():
            for credential in user.credentials:
                if credential.data["username"] == username:
                    # Return found credentials for the user
                    return credential

        raise InvalidUserError("User does not exist")

    @callback
    async def async_validate_access(self, access_token: str) -> Dict[str, Any]:
        """Validate an access token"""

        audience = self.config[CONF_AUDIENCE]
        jwks_url = self.config[CONF_JWKS_URL]

        username_claim_key = self.config[CONF_USERNAME_CLAIM_KEY]

        try:
            jwks_client = PyJWKClient(
                jwks_url,
                cache_keys=True,
                max_cached_keys=3,
                cache_jwk_set=True,
                lifespan=60 * 60 * 6,
            )
        except jwt.exceptions.PyJWKClientError as exc:
            raise InvalidAuthError("Failed to load jwks") from exc

        if access_token is None:
            _LOGGER.info("Tried to authenticate when no access token was provided.")
            raise InvalidAuthError("No access token present")

        try:
            signing_key = await self.hass.async_add_executor_job(
                jwks_client.get_signing_key_from_jwt, access_token
            )
        except jwt.exceptions.PyJWKClientError as exc:
            raise InvalidAuthError("Failed to obtain signing key") from exc

        try:
            claims = jwt.decode(
                access_token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                do_verify=True,
                audience=audience,
                options={"require": ["exp", "nbf", username_claim_key]},
            )
        except jwt.exceptions.InvalidAlgorithmError as exc:
            raise InvalidAuthError("Invalid access token: invalid algorithm") from exc
        except jwt.exceptions.InvalidAudienceError as exc:
            raise InvalidAuthError("Invalid access token: invalid audience") from exc
        except jwt.exceptions.MissingRequiredClaimError as exc:
            raise InvalidAuthError(
                "Invalid access token: required claim missing"
            ) from exc
        except jwt.exceptions.InvalidTokenError as exc:
            raise InvalidAuthError("Invalid access token") from exc

        return claims


class AccessTokenLoginFlow(LoginFlow):
    """Handler for the login flow."""

    def __init__(
        self,
        auth_provider: AccessTokenAuthProvider,
        access_token: str | None,
    ) -> None:
        """Initialize the login flow"""

        super().__init__(auth_provider)
        self._access_token = access_token

    async def async_step_init(
        self, user_input: Optional[Dict[str, str]] = None
    ) -> FlowResult:
        """Handle the step of the form."""

        try:
            auth_provider = cast(
                AccessTokenAuthProvider, cast(Any, self._auth_provider)
            )
            result = await auth_provider.async_validate_access(self._access_token)
        except InvalidAuthError as exc:
            _LOGGER.debug("Invalid auth", exc_info=exc)
            return self.async_abort(reason="not_allowed")

        return await self.async_finish(result)
