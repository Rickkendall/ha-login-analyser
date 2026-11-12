"""Config flow for Login Analyser."""

from __future__ import annotations

from typing import Any

try:
    import probatio as vol
except ImportError:  # pragma: no cover
    import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import (
    CONF_ABUSEIPDB_KEY,
    CONF_BAN_ENABLED,
    CONF_BAN_TIME,
    CONF_CAPTURE_PASSWORDS,
    CONF_ESCALATE,
    CONF_FIND_TIME,
    CONF_GEOIP,
    CONF_INSTANT_BAN_PROBES,
    CONF_MAX_ATTEMPTS,
    CONF_NOTIFY_SERVICE,
    CONF_PERMANENT_AFTER,
    CONF_REPLACE_NOTIFICATION,
    CONF_RETENTION_DAYS,
    CONF_SHODAN,
    CONF_WHITELIST,
    CONF_WHITELIST_PRIVATE,
    CONF_WHITELIST_SUCCESS,
    DEFAULTS,
    DOMAIN,
)


def _num(lo: int, hi: int, unit: str | None = None) -> selector.NumberSelector:
    extra = {"unit_of_measurement": unit} if unit else {}
    return selector.NumberSelector(
        selector.NumberSelectorConfig(min=lo, max=hi, step=1, mode=selector.NumberSelectorMode.BOX, **extra)
    )


def _schema(cur: dict[str, Any]) -> vol.Schema:
    def d(k: str) -> Any:
        return cur.get(k, DEFAULTS[k])

    return vol.Schema(
        {
            vol.Required(CONF_BAN_ENABLED, default=d(CONF_BAN_ENABLED)): bool,
            vol.Required(CONF_MAX_ATTEMPTS, default=d(CONF_MAX_ATTEMPTS)): _num(1, 100),
            vol.Required(CONF_FIND_TIME, default=d(CONF_FIND_TIME)): _num(1, 10080, "min"),
            vol.Required(CONF_BAN_TIME, default=d(CONF_BAN_TIME)): _num(0, 525600, "min"),
            vol.Required(CONF_ESCALATE, default=d(CONF_ESCALATE)): bool,
            vol.Required(CONF_PERMANENT_AFTER, default=d(CONF_PERMANENT_AFTER)): _num(0, 100),
            vol.Required(CONF_INSTANT_BAN_PROBES, default=d(CONF_INSTANT_BAN_PROBES)): bool,
            vol.Optional(CONF_WHITELIST, default=d(CONF_WHITELIST)): selector.TextSelector(
                selector.TextSelectorConfig(multiline=True)
            ),
            vol.Required(CONF_WHITELIST_PRIVATE, default=d(CONF_WHITELIST_PRIVATE)): bool,
            vol.Required(CONF_WHITELIST_SUCCESS, default=d(CONF_WHITELIST_SUCCESS)): bool,
            vol.Required(CONF_CAPTURE_PASSWORDS, default=d(CONF_CAPTURE_PASSWORDS)): bool,
            vol.Required(CONF_GEOIP, default=d(CONF_GEOIP)): bool,
            vol.Required(CONF_SHODAN, default=d(CONF_SHODAN)): bool,
            vol.Optional(CONF_ABUSEIPDB_KEY, default=d(CONF_ABUSEIPDB_KEY)): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Optional(CONF_NOTIFY_SERVICE, default=d(CONF_NOTIFY_SERVICE)): str,
            vol.Required(CONF_REPLACE_NOTIFICATION, default=d(CONF_REPLACE_NOTIFICATION)): bool,
            vol.Required(CONF_RETENTION_DAYS, default=d(CONF_RETENTION_DAYS)): _num(1, 3650, "days"),
        }
    )


def _clean(user_input: dict[str, Any]) -> dict[str, Any]:
    out = dict(user_input)
    for key in (CONF_MAX_ATTEMPTS, CONF_FIND_TIME, CONF_BAN_TIME, CONF_PERMANENT_AFTER, CONF_RETENTION_DAYS):
        out[key] = int(out[key])
    return out


class LoginAnalyserConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")
        if user_input is not None:
            return self.async_create_entry(title="Login Analyser", data={}, options=_clean(user_input))
        return self.async_show_form(step_id="user", data_schema=_schema({}))

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return LoginAnalyserOptionsFlow()


class LoginAnalyserOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=_clean(user_input))
        return self.async_show_form(step_id="init", data_schema=_schema(dict(self.config_entry.options)))
