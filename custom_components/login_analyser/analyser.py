"""Core of Login Analyser: capture, storage, enrichment and banning."""

from __future__ import annotations

import base64
import binascii
import logging
import time
import uuid
from collections import Counter
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Any

from aiohttp.web import Request

from homeassistant.components import persistent_notification
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store

from .classify import classify
from .const import (
    BUILTIN_LOGIN_NOTIFICATION,
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
    EVENT_ATTEMPT,
    EVENT_BAN,
    EVENT_UNBAN,
    MAX_EVENTS,
    MAX_EVENTS_PER_IP,
    NOTIFICATION_ID,
    SIGNAL_UPDATE,
    STORAGE_KEY,
    STORAGE_VERSION,
)
from .enrich import enrich_ip, is_public

_LOGGER = logging.getLogger(__name__)

PENDING_CRED_TTL = 15  # seconds between the login form step and the wrong-login hook
ENRICH_TTL = 7 * 86400  # re-enrich an IP after a week
NOTIFY_COOLDOWN = 3600  # push notification at most once per IP per hour
SUCCESS_TRUST_DAYS = 30
SENSITIVE_HEADERS = {"authorization", "cookie", "x-ha-access", "proxy-authorization"}
MAX_HEADERS = 40


def _now() -> float:
    return time.time()


def _addr(ip: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(ip)
    except ValueError:
        return None


class LoginAnalyser:
    """Holds state and logic. One instance per config entry."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self._store: Store[dict[str, Any]] = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self.events: list[dict[str, Any]] = []
        self.ips: dict[str, dict[str, Any]] = {}
        self.bans: dict[str, dict[str, Any]] = {}
        self.successes: dict[str, dict[str, Any]] = {}
        self._pending_creds: dict[str, dict[str, Any]] = {}
        self._enriching: set[str] = set()
        self._last_notify: dict[str, float] = {}
        self._unsubs: list[Any] = []
        self.ban_backend_available = False

    # ------------------------------------------------------------------ options
    def opt(self, key: str) -> Any:
        return self.entry.options.get(key, DEFAULTS[key])

    # ---------------------------------------------------------------- lifecycle
    async def async_load(self) -> None:
        data = await self._store.async_load() or {}
        self.events = data.get("events", [])
        self.ips = data.get("ips", {})
        self.bans = data.get("bans", {})
        self.successes = data.get("successes", {})
        self._purge()
        await self._async_import_ha_file_bans()
        self.reapply_bans()
        self._unsubs.append(
            async_track_time_interval(self.hass, self._async_tick, timedelta(seconds=60))
        )

    async def async_unload(self) -> None:
        for unsub in self._unsubs:
            unsub()
        self._unsubs.clear()
        await self._store.async_save(self._data())

    def _data(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "ips": self.ips,
            "bans": self.bans,
            "successes": self.successes,
        }

    def _save(self) -> None:
        self._store.async_delay_save(self._data, 10)

    def _changed(self) -> None:
        self._save()
        async_dispatcher_send(self.hass, SIGNAL_UPDATE)

    # ----------------------------------------------------------- known users
    def _known_usernames(self) -> set[str]:
        names: set[str] = set()
        for provider in self.hass.auth.auth_providers:
            if provider.type != "homeassistant":
                continue
            data = getattr(provider, "data", None)
            if data is None:
                continue
            for user in getattr(data, "users", []):
                names.add(str(user.get("username", "")).strip().casefold())
        return names

    def _password_policy(self, username: str | None, password: str | None) -> tuple[str | None, str]:
        """Return (password_to_store, reason).

        Passwords are ONLY stored when the username does not exist in Home
        Assistant. That way a typo of your own password is never written to
        disk, but an attacker trying admin/123456 is captured.
        """
        if password is None:
            return None, "none_submitted"
        if not self.opt(CONF_CAPTURE_PASSWORDS):
            return None, "capture_disabled"
        if username is not None and username.strip().casefold() in self._known_usernames():
            return None, "hidden_real_username"
        return password[:128], "captured"

    # ----------------------------------------------------- login-form capture
    @callback
    def note_credentials(self, ip: str, username: str | None, password: str | None) -> None:
        """Called from the patched login flow on a wrong username/password."""
        stored_pw, reason = self._password_policy(username, password)
        self._pending_creds[ip] = {
            "ts": _now(),
            "username": (username or "")[:128],
            "password": stored_pw,
            "password_reason": reason,
            "known_user": reason == "hidden_real_username",
        }

    def _pop_creds(self, ip: str) -> dict[str, Any] | None:
        creds = self._pending_creds.pop(ip, None)
        if creds and _now() - creds["ts"] <= PENDING_CRED_TTL:
            return creds
        return None

    # --------------------------------------------------------- success login
    @callback
    def record_success(self, request: Request) -> None:
        ip = str(request.remote)
        rec = self.successes.setdefault(ip, {"count": 0, "first": _now()})
        rec["count"] += 1
        rec["last"] = _now()
        rec["user_agent"] = (request.headers.get("user-agent") or "")[:300]
        if ip in self.ips:
            self.ips[ip]["successful_logins"] = rec["count"]
        self._changed()

    # ----------------------------------------------------------- failed hit
    def _headers(self, request: Request) -> tuple[dict[str, str], dict[str, Any]]:
        headers: dict[str, str] = {}
        extra: dict[str, Any] = {}
        for i, (key, value) in enumerate(request.headers.items()):
            if i >= MAX_HEADERS:
                break
            lk = key.lower()
            if lk in SENSITIVE_HEADERS:
                if lk == "authorization" and value.lower().startswith("basic "):
                    try:
                        decoded = base64.b64decode(value[6:].strip()).decode("utf-8", "replace")
                        user, _, pw = decoded.partition(":")
                        extra["basic_user"] = user[:128]
                        extra["basic_password"] = pw
                    except (binascii.Error, ValueError):
                        pass
                    headers[key] = "Basic <decoded below>"
                else:
                    scheme = value.split(" ", 1)[0] if " " in value else ""
                    headers[key] = f"{scheme} <redacted, {len(value)} chars>".strip()
                continue
            headers[key] = value[:300]
        return headers, extra

    async def async_record_failure(self, request: Request) -> None:
        """Called (patched in) every time HA counts a wrong login / bad auth."""
        ip = str(request.remote)
        now = _now()
        path = str(request.rel_url)[:1000]
        ua = request.headers.get("user-agent")
        headers, extra = self._headers(request)
        cls = classify(path, ua, request.method)

        source = "http"
        if path.startswith("/auth/login_flow"):
            source = "login_form"
        elif path.startswith("/api/websocket"):
            source = "websocket"
        elif path.startswith("/auth/token"):
            source = "token"

        creds = self._pop_creds(ip)
        username = creds["username"] if creds else None
        password = creds["password"] if creds else None
        pw_reason = creds["password_reason"] if creds else None
        known_user = creds["known_user"] if creds else False
        if not creds and "basic_user" in extra:
            username = extra["basic_user"]
            password, pw_reason = self._password_policy(username, extra["basic_password"])
            known_user = pw_reason == "hidden_real_username"
            source = "basic_auth"

        event: dict[str, Any] = {
            "id": uuid.uuid4().hex[:12],
            "ts": now,
            "ip": ip,
            "source": source,
            "method": request.method,
            "path": path,
            "host": request.host,
            "scheme": request.scheme,
            "http_version": f"{request.version.major}.{request.version.minor}",
            "user_agent": (ua or "")[:500],
            "referer": request.headers.get("referer"),
            "forwarded_for": request.headers.get("x-forwarded-for"),
            "headers": headers,
            "username": username,
            "password": password,
            "password_reason": pw_reason,
            "known_user": known_user,
            "classification": cls.as_dict(),
            "action": None,
        }
        self.events.append(event)
        if len(self.events) > MAX_EVENTS:
            del self.events[: len(self.events) - MAX_EVENTS]

        rec = self.ips.setdefault(
            ip,
            {
                "first_seen": now,
                "count": 0,
                "usernames": {},
                "passwords": {},
                "categories": {},
                "user_agents": {},
                "paths": {},
                "methods": {},
                "ban_count": 0,
                "max_severity": 0,
                "enrichment": None,
            },
        )
        rec["last_seen"] = now
        rec["count"] += 1
        rec["max_severity"] = max(rec.get("max_severity", 0), cls.severity)
        _bump(rec["categories"], cls.label)
        _bump(rec["methods"], request.method)
        if ua is not None:
            _bump(rec["user_agents"], ua[:300], cap=20)
        _bump(rec["paths"], path[:300], cap=100)
        if username:
            _bump(rec["usernames"], username, cap=200)
        if password:
            _bump(rec["passwords"], password, cap=200)
        if cls.likely_own_device:
            rec["likely_own_device"] = True
        if ip in self.successes:
            rec["successful_logins"] = self.successes[ip]["count"]

        # ---- fail2ban-style decision
        action = self._evaluate_ban(ip, cls.probe, cls.likely_own_device, cls.label)
        event["action"] = action

        # ---- bus event for automations
        self.hass.bus.async_fire(
            EVENT_ATTEMPT,
            {
                "ip": ip,
                "path": path,
                "method": request.method,
                "source": source,
                "category": cls.category,
                "label": cls.label,
                "severity": cls.severity,
                "username": username,
                "user_agent": ua,
                "attempts_total": rec["count"],
                "action": action,
            },
        )

        self._changed()

        # ---- enrichment + notifications happen in the background
        self.hass.async_create_background_task(
            self._async_after_event(ip, event), f"login_analyser enrich {ip}"
        )

    async def _async_after_event(self, ip: str, event: dict[str, Any]) -> None:
        await self.async_enrich(ip)
        await self._async_notify(ip, event)

    @callback
    def after_builtin(self) -> None:
        """Run after HA's own wrong-login handler (which creates its notification)."""
        if self.opt(CONF_REPLACE_NOTIFICATION) and self.events:
            persistent_notification.async_dismiss(self.hass, BUILTIN_LOGIN_NOTIFICATION)

    # ------------------------------------------------------------- enrichment
    async def async_enrich(self, ip: str, force: bool = False) -> dict[str, Any] | None:
        rec = self.ips.get(ip)
        if rec is None:
            return None
        current = rec.get("enrichment")
        if not force and current and _now() - current.get("looked_up", 0) < ENRICH_TTL:
            return current
        if ip in self._enriching:
            return current
        self._enriching.add(ip)
        try:
            info = await enrich_ip(
                self.hass,
                ip,
                use_geoip=self.opt(CONF_GEOIP),
                use_shodan=self.opt(CONF_SHODAN),
                abuse_key=(self.opt(CONF_ABUSEIPDB_KEY) or "").strip(),
            )
        except Exception:  # noqa: BLE001 - enrichment must never break HA
            _LOGGER.exception("Enrichment failed for %s", ip)
            return current
        finally:
            self._enriching.discard(ip)
        rec["enrichment"] = info
        self._changed()
        return info

    # --------------------------------------------------------------- whitelist
    def _whitelist_networks(self) -> list:
        nets = []
        for part in (self.opt(CONF_WHITELIST) or "").replace("\n", ",").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ip_network(part, strict=False))
            except ValueError:
                _LOGGER.warning("Ignoring invalid whitelist entry %s", part)
        return nets

    def whitelist_reason(self, ip: str) -> str | None:
        addr = _addr(ip)
        if addr is None:
            return "invalid"
        if self.opt(CONF_WHITELIST_PRIVATE) and (
            addr.is_private or addr.is_loopback or addr.is_link_local
        ):
            return "private network"
        for net in self._whitelist_networks():
            if addr in net:
                return f"whitelist {net}"
        if self.opt(CONF_WHITELIST_SUCCESS):
            succ = self.successes.get(ip)
            if succ and _now() - succ.get("last", 0) < SUCCESS_TRUST_DAYS * 86400:
                return "successful login from this IP"
        try:
            from homeassistant.helpers.hassio import get_supervisor_ip, is_hassio  # noqa: PLC0415

            if is_hassio(self.hass) and ip == get_supervisor_ip():
                return "supervisor"
        except ImportError:
            pass
        return None

    # -------------------------------------------------------------- ban logic
    def _evaluate_ban(self, ip: str, probe: bool, own_device: bool, label: str) -> str | None:
        if not self.opt(CONF_BAN_ENABLED):
            return None
        if ip in self.bans:
            return "already_banned"
        if (reason := self.whitelist_reason(ip)) is not None:
            return f"whitelisted ({reason})"

        if probe and self.opt(CONF_INSTANT_BAN_PROBES) and not own_device:
            self.ban(ip, reason=f"Exploit probe: {label}")
            return "banned"

        window = self.opt(CONF_FIND_TIME) * 60
        threshold = self.opt(CONF_MAX_ATTEMPTS)
        if own_device:
            threshold *= 5  # be lenient with HA apps holding stale tokens
        since = _now() - window
        # failures before a manual unban / expired ban don't count again
        since = max(since, (self.ips.get(ip) or {}).get("counter_reset", 0))
        recent = sum(1 for e in reversed(self.events) if e["ts"] >= since and e["ip"] == ip)
        if recent >= threshold:
            self.ban(ip, reason=f"{recent} failed attempts in {self.opt(CONF_FIND_TIME)} min")
            return "banned"
        return None

    def _ban_manager(self):
        try:
            from homeassistant.components.http.ban import KEY_BAN_MANAGER  # noqa: PLC0415
        except ImportError:
            return None
        app = getattr(getattr(self.hass, "http", None), "app", None)
        if app is None:
            return None
        return app.get(KEY_BAN_MANAGER)

    def _apply_ban(self, ip: str) -> bool:
        from homeassistant.components.http.ban import IpBan  # noqa: PLC0415

        mgr = self._ban_manager()
        addr = _addr(ip)
        if mgr is None or addr is None:
            self.ban_backend_available = False
            return False
        self.ban_backend_available = True
        if addr not in mgr.ip_bans_lookup:
            mgr.ip_bans_lookup[addr] = IpBan(addr)
        return True

    def _lift_ban(self, ip: str) -> None:
        mgr = self._ban_manager()
        addr = _addr(ip)
        if mgr is not None and addr is not None:
            mgr.ip_bans_lookup.pop(addr, None)

    @callback
    def reapply_bans(self) -> None:
        now = _now()
        for ip, ban in list(self.bans.items()):
            if ban.get("expires") and ban["expires"] <= now:
                continue
            self._apply_ban(ip)
        if self._ban_manager() is None:
            self.ban_backend_available = False
            persistent_notification.async_create(
                self.hass,
                "Login Analyser is recording attacks, but **cannot block IPs yet** because "
                "Home Assistant's IP-ban layer is off.\n\n"
                "[Open Login Analyser](/login-analyser) and press **Enable blocking**. It sets "
                "`ip_ban_enabled: true` and `login_attempts_threshold: -1` in the HTTP server settings "
                "(Settings → System → Network) and restarts Home Assistant. After the restart, confirm "
                "the new settings within 5 minutes.\n\n"
                "(`-1` hands the ban decisions to Login Analyser, which supports time-limited bans, "
                "whitelists and escalation.)",
                "Login Analyser: blocking disabled",
                f"{NOTIFICATION_ID}_setup",
            )
        else:
            self.ban_backend_available = True
            persistent_notification.async_dismiss(self.hass, f"{NOTIFICATION_ID}_setup")

    def ban(self, ip: str, *, reason: str, minutes: int | None = None, permanent: bool = False) -> dict[str, Any]:
        rec = self.ips.get(ip)
        prior = rec.get("ban_count", 0) if rec else 0
        if minutes is None and not permanent:
            minutes = self.opt(CONF_BAN_TIME)
            if self.opt(CONF_ESCALATE) and prior:
                minutes = minutes * (2**prior)
            perm_after = self.opt(CONF_PERMANENT_AFTER)
            if perm_after and prior + 1 >= perm_after:
                permanent = True
        if minutes is not None and minutes <= 0:
            permanent = True
        now = _now()
        ban = {
            "banned_at": now,
            "expires": None if permanent else now + minutes * 60,
            "reason": reason,
            "ban_number": prior + 1,
            "source": "analyser",
        }
        self.bans[ip] = ban
        if rec is not None:
            rec["ban_count"] = prior + 1
        applied = self._apply_ban(ip)
        ban["enforced"] = applied
        _LOGGER.warning(
            "Login Analyser banned %s (%s) %s",
            ip,
            reason,
            "permanently" if permanent else f"for {minutes} min",
        )
        self.hass.bus.async_fire(
            EVENT_BAN,
            {"ip": ip, "reason": reason, "permanent": permanent, "minutes": minutes, "enforced": applied},
        )
        self._changed()
        return ban

    async def async_unban(self, ip: str) -> bool:
        existed = self.bans.pop(ip, None) is not None
        self._lift_ban(ip)
        if ip in self.ips:
            self.ips[ip]["counter_reset"] = _now()
        removed_file = await self.hass.async_add_executor_job(self._remove_from_ip_bans_file, ip)
        if existed or removed_file:
            self.hass.bus.async_fire(EVENT_UNBAN, {"ip": ip})
            self._changed()
        return existed or removed_file

    def _remove_from_ip_bans_file(self, ip: str) -> bool:
        """Remove an IP from HA's own ip_bans.yaml (permanent built-in bans)."""
        from homeassistant.util import yaml as yaml_util  # noqa: PLC0415

        path = self.hass.config.path("ip_bans.yaml")
        try:
            data = yaml_util.load_yaml(path) or {}
        except FileNotFoundError:
            return False
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Could not read %s", path)
            return False
        if ip not in data:
            return False
        data.pop(ip)
        with open(path, "w", encoding="utf8") as out:
            out.write(yaml_util.dump(data) if data else "")
        return True

    async def _async_import_ha_file_bans(self) -> None:
        """Show bans HA itself made (ip_bans.yaml) in the panel."""
        mgr = self._ban_manager()
        if mgr is None:
            return
        for addr, ipban in list(mgr.ip_bans_lookup.items()):
            ip = str(addr)
            if ip not in self.bans:
                self.bans[ip] = {
                    "banned_at": ipban.banned_at.timestamp(),
                    "expires": None,
                    "reason": "Home Assistant built-in ban (ip_bans.yaml)",
                    "ban_number": 1,
                    "source": "ha_file",
                    "enforced": True,
                }

    async def _async_tick(self, _now_dt=None) -> None:
        now = _now()
        expired = [ip for ip, b in self.bans.items() if b.get("expires") and b["expires"] <= now]
        for ip in expired:
            _LOGGER.info("Login Analyser ban expired for %s", ip)
            self.bans.pop(ip, None)
            self._lift_ban(ip)
            if ip in self.ips:
                self.ips[ip]["counter_reset"] = now
            self.hass.bus.async_fire(EVENT_UNBAN, {"ip": ip, "expired": True})
        # make sure bans survive HA reloading ip_bans.yaml at http startup
        for ip, ban in self.bans.items():
            if not ban.get("expires") or ban["expires"] > now:
                ban["enforced"] = self._apply_ban(ip)
        if expired:
            self._changed()
        if int(now) % 3600 < 60:
            self._purge()

    def _purge(self) -> None:
        cutoff = _now() - self.opt(CONF_RETENTION_DAYS) * 86400
        self.events = [e for e in self.events if e["ts"] >= cutoff]
        stale = [
            ip
            for ip, rec in self.ips.items()
            if rec.get("last_seen", 0) < cutoff and ip not in self.bans
        ]
        for ip in stale:
            self.ips.pop(ip, None)

    # ----------------------------------------------------------- notifications
    async def _async_notify(self, ip: str, event: dict[str, Any]) -> None:
        rec = self.ips.get(ip, {})
        enr = rec.get("enrichment") or {}
        geo = enr.get("geo") or {}
        where = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x) or "unknown location"
        who = geo.get("isp") or geo.get("org") or enr.get("rdns") or "unknown network"
        flags = []
        if geo.get("hosting"):
            flags.append("datacenter/VPS")
        if geo.get("proxy"):
            flags.append("proxy/VPN/Tor")
        if (enr.get("abuse") or {}).get("score") is not None:
            flags.append(f"AbuseIPDB {enr['abuse']['score']}%")
        if (enr.get("shodan") or {}).get("tags"):
            flags.append("shodan: " + ", ".join(enr["shodan"]["tags"]))
        cls = event["classification"]
        action = event.get("action") or "logged"
        ban = self.bans.get(ip)

        lines = [
            f"**{cls['label']}** from `{ip}` ({enr.get('rdns') or 'no rDNS'})",
            f"📍 {where} — {who}" + (f" — AS: {geo.get('as')}" if geo.get("as") else ""),
            f"➡️ `{event['method']} {event['path'][:120]}`",
        ]
        if event.get("username"):
            lines.append(f"👤 username tried: `{event['username']}`")
        if flags:
            lines.append("⚠️ " + " · ".join(flags))
        lines.append(f"🔁 {rec.get('count', 1)} attempt(s) total from this IP · action: **{action}**")
        if ban:
            exp = "permanent" if not ban.get("expires") else time.strftime(
                "%Y-%m-%d %H:%M", time.localtime(ban["expires"])
            )
            lines.append(f"⛔ banned until {exp}" + ("" if ban.get("enforced") else " (NOT enforced - see setup)"))
        lines.append("\n[Open Login Analyser](/login-analyser)")
        message = "\n\n".join(lines)

        if self.opt(CONF_REPLACE_NOTIFICATION):
            persistent_notification.async_dismiss(self.hass, BUILTIN_LOGIN_NOTIFICATION)
            persistent_notification.async_create(
                self.hass, message, "Failed login / attack detected", NOTIFICATION_ID
            )

        service = (self.opt(CONF_NOTIFY_SERVICE) or "").strip()
        if not service:
            return
        if _now() - self._last_notify.get(ip, 0) < NOTIFY_COOLDOWN and action != "banned":
            return
        self._last_notify[ip] = _now()
        domain, _, name = service.partition(".")
        if not name:
            domain, name = "notify", domain
        try:
            await self.hass.services.async_call(
                domain,
                name,
                {
                    "title": f"⚠️ {cls['label']} from {ip}",
                    "message": message.replace("**", "").replace("`", "").replace(
                        "\n\n[Open Login Analyser](/login-analyser)", ""
                    ),
                    "data": {"url": "/login-analyser", "clickAction": "/login-analyser", "tag": f"la_{ip}"},
                },
                blocking=False,
            )
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Login Analyser could not call %s", service)

    # -------------------------------------------------------------- snapshot
    def summary(self) -> dict[str, Any]:
        now = _now()
        day = [e for e in self.events if e["ts"] >= now - 86400]
        week = [e for e in self.events if e["ts"] >= now - 7 * 86400]
        countries: Counter[str] = Counter()
        for ip, rec in self.ips.items():
            geo = (rec.get("enrichment") or {}).get("geo") or {}
            if geo.get("countryCode"):
                countries[geo["countryCode"]] += rec["count"]
        usernames: Counter[str] = Counter()
        passwords: Counter[str] = Counter()
        categories: Counter[str] = Counter()
        for rec in self.ips.values():
            usernames.update(rec.get("usernames", {}))
            passwords.update(rec.get("passwords", {}))
            categories.update(rec.get("categories", {}))
        active_bans = {ip: b for ip, b in self.bans.items() if not b.get("expires") or b["expires"] > now}
        last = self.events[-1] if self.events else None
        return {
            "total_events": len(self.events),
            "events_24h": len(day),
            "events_7d": len(week),
            "unique_ips": len(self.ips),
            "unique_ips_24h": len({e["ip"] for e in day}),
            "active_bans": len(active_bans),
            "ban_backend_available": self.ban_backend_available,
            "top_countries": countries.most_common(15),
            "top_usernames": usernames.most_common(25),
            "top_passwords": passwords.most_common(25),
            "top_categories": categories.most_common(15),
            "last_event": last,
        }

    def snapshot(self, event_limit: int = 1000) -> dict[str, Any]:
        options = {k: self.opt(k) for k in DEFAULTS}
        options[CONF_ABUSEIPDB_KEY] = bool(options[CONF_ABUSEIPDB_KEY])
        return {
            "summary": self.summary(),
            "ips": self.ips,
            "bans": self.bans,
            "successes": self.successes,
            "events": self.events[-event_limit:],
            "options": options,
            "now": _now(),
        }

    def ip_events(self, ip: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e["ip"] == ip][-MAX_EVENTS_PER_IP:]

    async def async_clear(self) -> None:
        self.events.clear()
        self.ips = {ip: rec for ip, rec in self.ips.items() if ip in self.bans}
        self._changed()

    @staticmethod
    def is_public(ip: str) -> bool:
        return is_public(ip)


def _bump(counter: dict[str, int], key: str, cap: int = 50) -> None:
    if key in counter:
        counter[key] += 1
    elif len(counter) < cap:
        counter[key] = 1
    else:
        counter["(other)"] = counter.get("(other)", 0) + 1
