import logging
from http import HTTPStatus
from ipaddress import ip_address
from typing import Any, OrderedDict

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from aiohttp.web import Request, Response
from homeassistant import data_entry_flow
from homeassistant.components.auth import DOMAIN as AUTH_DOMAIN
from homeassistant.components.auth import indieauth
from homeassistant.components.auth.login_flow import (
    LoginFlowIndexView,
    _prepare_result_json,
)
from homeassistant.components.http.ban import log_invalid_auth, process_success_login
from homeassistant.components.http.data_validator import RequestDataValidator
from homeassistant.core import HomeAssistant

from . import access_token

_LOGGER = logging.getLogger(__name__)

DOMAIN = "access_token"


CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(access_token.CONF_JWKS_URL): str,
                vol.Required(access_token.CONF_AUDIENCE): str,
                vol.Required(access_token.CONF_COOKIE_NAME): str,
                vol.Optional(access_token.CONF_USERNAME_CLAIM_KEY, default="sub"): str,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(home_assistant: HomeAssistant, config):
    """Register custom view which includes request in context"""

    _LOGGER.debug(home_assistant)
    _LOGGER.debug(config)

    # Because we start after auth, we have access to store_result
    store_result = home_assistant.data[AUTH_DOMAIN]

    # Remove old LoginFlowIndexView
    for route in home_assistant.http.app.router._resources:
        if route.canonical == "/auth/login_flow":
            _LOGGER.debug("Removing original login_flow route")
            home_assistant.http.app.router._resources.remove(route)
            _LOGGER.debug("Removed original login_flow route")

    _LOGGER.debug("Add new login_flow route")
    home_assistant.http.register_view(
        RequestLoginFlowIndexView(home_assistant.auth.login_flow, store_result)
    )

    # Inject Access-Token provider.
    providers = OrderedDict()
    provider = access_token.AccessTokenAuthProvider(
        home_assistant,
        home_assistant.auth._store,
        config[DOMAIN],
    )
    providers[(provider.type, provider.id)] = provider
    providers.update(home_assistant.auth._providers)
    home_assistant.auth._providers = providers
    _LOGGER.debug("Injected access_token provider")
    return True


class RequestLoginFlowIndexView(LoginFlowIndexView):
    def __init__(self, flow_mgr, store_result) -> None:
        super().__init__(flow_mgr, store_result)

    @RequestDataValidator(
        vol.Schema(
            {
                vol.Required("client_id"): str,
                vol.Required("handler"): vol.Any(str, list),
                vol.Required("redirect_uri"): str,
                vol.Optional("type", default="authorize"): str,
            }
        )
    )
    @log_invalid_auth
    async def post(self, request: Request, data: dict[str, Any]) -> Response:
        """Create a new login flow."""

        client_id: str = data["client_id"]
        redirect_uri: str = data["redirect_uri"]

        if not indieauth.verify_client_id(client_id):
            return self.json_message("Invalid client id", HTTPStatus.BAD_REQUEST)

        handler: tuple[str, ...] | str
        if isinstance(data["handler"], list):
            handler = tuple(data["handler"])
        else:
            handler = data["handler"]

        try:
            _LOGGER.debug(request.headers)

            result = await self._flow_mgr.async_init(
                handler,  # type: ignore[arg-type]
                context={
                    "request": request,
                    "ip_address": ip_address(request.remote),  # type: ignore[arg-type]
                    "credential_only": data.get("type") == "link_user",
                    "redirect_uri": redirect_uri,
                },
            )
        except data_entry_flow.UnknownHandler:
            return self.json_message("Invalid handler specified", HTTPStatus.NOT_FOUND)
        except data_entry_flow.UnknownStep:
            return self.json_message(
                "Handler does not support init", HTTPStatus.BAD_REQUEST
            )

        return await self._async_flow_result_to_response(request, client_id, result)
