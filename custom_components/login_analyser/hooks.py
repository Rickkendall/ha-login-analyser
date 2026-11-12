"""Patch Home Assistant's wrong-login handling so we see every failed attempt.

Home Assistant routes every failed authentication (REST API 401s, the login
form, websocket auth, /auth/token) through
``homeassistant.components.http.ban.process_wrong_login``. Several modules
import that function by name, so we replace it in every loaded module that
holds a reference to the original.

The username (and, for non-existent usernames only, the password) is taken
from the login form step itself, which runs just before process_wrong_login.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

from aiohttp.web import Request

if TYPE_CHECKING:
    from .analyser import LoginAnalyser

_LOGGER = logging.getLogger(__name__)

_state: dict[str, Any] = {}


def _replace_everywhere(original: Any, replacement: Any) -> list[str]:
    patched = []
    for name, module in list(sys.modules.items()):
        if module is None or not name.startswith("homeassistant"):
            continue
        for attr in ("process_wrong_login", "process_success_login"):
            if getattr(module, attr, None) is original:
                setattr(module, attr, replacement)
                patched.append(f"{name}.{attr}")
    return patched


def install(analyser: LoginAnalyser) -> None:
    """Install hooks (idempotent)."""
    if _state:
        _state["analyser"] = analyser
        return

    from homeassistant.components.http import ban as ban_mod  # noqa: PLC0415

    # Make sure the modules that import these by name are loaded first.
    for mod in (
        "homeassistant.components.auth.login_flow",
        "homeassistant.components.auth",
        "homeassistant.components.websocket_api.auth",
    ):
        try:
            __import__(mod)
        except ImportError:
            pass

    _state["analyser"] = analyser
    orig_wrong = ban_mod.process_wrong_login
    orig_success = ban_mod.process_success_login

    async def process_wrong_login(request: Request) -> None:
        try:
            await _state["analyser"].async_record_failure(request)
        except Exception:  # noqa: BLE001 - never break HA auth
            _LOGGER.exception("Login Analyser failed to record a wrong login")
        await orig_wrong(request)
        try:
            _state["analyser"].after_builtin()
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Login Analyser post-processing failed")

    def process_success_login(request: Request) -> None:
        orig_success(request)
        try:
            _state["analyser"].record_success(request)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Login Analyser failed to record a successful login")

    patched = _replace_everywhere(orig_wrong, process_wrong_login)
    patched += _replace_everywhere(orig_success, process_success_login)
    _state["orig_wrong"] = orig_wrong
    _state["orig_success"] = orig_success
    _state["new_wrong"] = process_wrong_login
    _state["new_success"] = process_success_login
    _LOGGER.debug("Login Analyser patched: %s", patched)

    # ---- login form: capture username / password on invalid_auth
    try:
        from homeassistant.auth.providers import homeassistant as hap  # noqa: PLC0415
        from homeassistant.data_entry_flow import FlowResultType  # noqa: PLC0415
    except ImportError:
        _LOGGER.warning("Login Analyser: could not hook the login form; usernames won't be captured")
        return

    orig_step = hap.HassLoginFlow.async_step_init

    async def async_step_init(self, user_input: dict[str, str] | None = None):
        result = await orig_step(self, user_input)
        try:
            if (
                user_input is not None
                and result.get("type") == FlowResultType.FORM
                and (result.get("errors") or {}).get("base") == "invalid_auth"
            ):
                ip = str(self.context.get("ip_address"))
                _state["analyser"].note_credentials(
                    ip, user_input.get("username"), user_input.get("password")
                )
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Login Analyser failed to capture login form data")
        return result

    hap.HassLoginFlow.async_step_init = async_step_init
    _state["hap"] = hap
    _state["orig_step"] = orig_step


def uninstall() -> None:
    """Restore the original functions."""
    if not _state:
        return
    _replace_everywhere(_state["new_wrong"], _state["orig_wrong"])
    _replace_everywhere(_state["new_success"], _state["orig_success"])
    if "hap" in _state:
        _state["hap"].HassLoginFlow.async_step_init = _state["orig_step"]
    _state.clear()
