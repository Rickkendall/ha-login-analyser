"""Login Analyser - see who is attacking your Home Assistant, and block them."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

try:  # HA moved from voluptuous to probatio
    import probatio as vol
except ImportError:  # pragma: no cover
    import voluptuous as vol

from homeassistant.components import frontend, panel_custom, websocket_api
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STARTED, Platform
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse, callback
from homeassistant.exceptions import HomeAssistantError
import homeassistant.helpers.config_validation as cv

from . import hooks
from .analyser import LoginAnalyser
from .const import DOMAIN, PANEL_COMPONENT, PANEL_STATIC_URL, PANEL_URL

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.SENSOR]
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

type LoginAnalyserConfigEntry = ConfigEntry[LoginAnalyser]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    _register_websocket(hass)
    _register_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: LoginAnalyserConfigEntry) -> bool:
    analyser = LoginAnalyser(hass, entry)
    await analyser.async_load()
    entry.runtime_data = analyser
    hass.data[DOMAIN] = analyser
    hooks.install(analyser)

    @callback
    def _started(_event=None) -> None:
        analyser.reapply_bans()

    entry.async_on_unload(hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _started))

    await _register_panel(hass)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def _async_options_updated(hass: HomeAssistant, entry: LoginAnalyserConfigEntry) -> None:
    entry.runtime_data.reapply_bans()


async def async_unload_entry(hass: HomeAssistant, entry: LoginAnalyserConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    hooks.uninstall()
    await entry.runtime_data.async_unload()
    hass.data.pop(DOMAIN, None)
    frontend.async_remove_panel(hass, PANEL_URL)
    return ok


# --------------------------------------------------------------------- panel
async def _register_panel(hass: HomeAssistant) -> None:
    if hass.data.get(f"{DOMAIN}_static"):
        pass
    else:
        await hass.http.async_register_static_paths(
            [StaticPathConfig(PANEL_STATIC_URL, str(Path(__file__).parent / "frontend"), False)]
        )
        hass.data[f"{DOMAIN}_static"] = True
    if PANEL_URL in hass.data.get("frontend_panels", {}):
        return
    version = "1.0.0"
    await panel_custom.async_register_panel(
        hass,
        frontend_url_path=PANEL_URL,
        webcomponent_name=PANEL_COMPONENT,
        sidebar_title="Login Analyser",
        sidebar_icon="mdi:shield-search",
        module_url=f"{PANEL_STATIC_URL}/login-analyser-panel.js?v={version}",
        require_admin=True,
        config={},
    )


# ----------------------------------------------------------------- websocket
def _get(hass: HomeAssistant) -> LoginAnalyser:
    analyser = hass.data.get(DOMAIN)
    if analyser is None:
        raise HomeAssistantError("Login Analyser is not set up")
    return analyser


def _register_websocket(hass: HomeAssistant) -> None:
    websocket_api.async_register_command(hass, ws_data)
    websocket_api.async_register_command(hass, ws_ip)
    websocket_api.async_register_command(hass, ws_ban)
    websocket_api.async_register_command(hass, ws_unban)
    websocket_api.async_register_command(hass, ws_enrich)


@websocket_api.websocket_command(
    {vol.Required("type"): "login_analyser/data", vol.Optional("event_limit", default=1000): int}
)
@websocket_api.require_admin
@callback
def ws_data(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    try:
        connection.send_result(msg["id"], _get(hass).snapshot(msg["event_limit"]))
    except HomeAssistantError as err:
        connection.send_error(msg["id"], "not_setup", str(err))


@websocket_api.websocket_command({vol.Required("type"): "login_analyser/ip", vol.Required("ip"): str})
@websocket_api.require_admin
@callback
def ws_ip(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    analyser = _get(hass)
    connection.send_result(
        msg["id"],
        {
            "ip": msg["ip"],
            "record": analyser.ips.get(msg["ip"]),
            "ban": analyser.bans.get(msg["ip"]),
            "success": analyser.successes.get(msg["ip"]),
            "whitelisted": analyser.whitelist_reason(msg["ip"]),
            "events": analyser.ip_events(msg["ip"]),
        },
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "login_analyser/ban",
        vol.Required("ip"): str,
        vol.Optional("minutes"): int,
        vol.Optional("permanent", default=False): bool,
        vol.Optional("reason", default="Manual ban"): str,
    }
)
@websocket_api.require_admin
@callback
def ws_ban(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    ban = _get(hass).ban(msg["ip"], reason=msg["reason"], minutes=msg.get("minutes"), permanent=msg["permanent"])
    connection.send_result(msg["id"], ban)


@websocket_api.websocket_command({vol.Required("type"): "login_analyser/unban", vol.Required("ip"): str})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_unban(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    connection.send_result(msg["id"], {"removed": await _get(hass).async_unban(msg["ip"])})


@websocket_api.websocket_command({vol.Required("type"): "login_analyser/enrich", vol.Required("ip"): str})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_enrich(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    connection.send_result(msg["id"], await _get(hass).async_enrich(msg["ip"], force=True))


# ------------------------------------------------------------------ services
def _register_services(hass: HomeAssistant) -> None:
    async def ban_ip(call: ServiceCall) -> None:
        _get(hass).ban(
            call.data["ip"],
            reason=call.data.get("reason", "Manual ban"),
            minutes=call.data.get("minutes"),
            permanent=call.data.get("permanent", False),
        )

    async def unban_ip(call: ServiceCall) -> None:
        await _get(hass).async_unban(call.data["ip"])

    async def lookup_ip(call: ServiceCall) -> dict[str, Any]:
        analyser = _get(hass)
        ip = call.data["ip"]
        if ip not in analyser.ips:
            from .enrich import enrich_ip  # noqa: PLC0415

            return await enrich_ip(
                hass, ip, use_geoip=True, use_shodan=True,
                abuse_key=(analyser.opt("abuseipdb_api_key") or "").strip(),
            )
        return await analyser.async_enrich(ip, force=True) or {}

    async def clear_history(call: ServiceCall) -> None:
        await _get(hass).async_clear()

    ip_schema = vol.Schema({vol.Required("ip"): cv.string})
    hass.services.async_register(
        DOMAIN,
        "ban_ip",
        ban_ip,
        schema=vol.Schema(
            {
                vol.Required("ip"): cv.string,
                vol.Optional("minutes"): vol.Coerce(int),
                vol.Optional("permanent", default=False): cv.boolean,
                vol.Optional("reason", default="Manual ban"): cv.string,
            }
        ),
    )
    hass.services.async_register(DOMAIN, "unban_ip", unban_ip, schema=ip_schema)
    hass.services.async_register(
        DOMAIN, "lookup_ip", lookup_ip, schema=ip_schema, supports_response=SupportsResponse.ONLY
    )
    hass.services.async_register(DOMAIN, "clear_history", clear_history)
