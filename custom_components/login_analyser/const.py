"""Constants for Login Analyser."""

from typing import Final

DOMAIN: Final = "login_analyser"
STORAGE_KEY: Final = "login_analyser.data"
STORAGE_VERSION: Final = 1

PANEL_URL: Final = "login-analyser"
PANEL_STATIC_URL: Final = "/login_analyser_static"
PANEL_COMPONENT: Final = "login-analyser-panel"

EVENT_ATTEMPT: Final = "login_analyser_attempt"
EVENT_BAN: Final = "login_analyser_ban"
EVENT_UNBAN: Final = "login_analyser_unban"
SIGNAL_UPDATE: Final = "login_analyser_update"

NOTIFICATION_ID: Final = "login_analyser"
BUILTIN_LOGIN_NOTIFICATION: Final = "http-login"

# Options
CONF_BAN_ENABLED: Final = "ban_enabled"
CONF_MAX_ATTEMPTS: Final = "max_attempts"
CONF_FIND_TIME: Final = "find_time_minutes"
CONF_BAN_TIME: Final = "ban_time_minutes"
CONF_ESCALATE: Final = "escalate_repeat_offenders"
CONF_PERMANENT_AFTER: Final = "permanent_after_bans"
CONF_INSTANT_BAN_PROBES: Final = "instant_ban_probes"
CONF_WHITELIST: Final = "whitelist"
CONF_WHITELIST_PRIVATE: Final = "whitelist_private"
CONF_WHITELIST_SUCCESS: Final = "whitelist_successful_logins"
CONF_CAPTURE_PASSWORDS: Final = "capture_passwords"
CONF_GEOIP: Final = "geoip_lookup"
CONF_SHODAN: Final = "shodan_internetdb"
CONF_ABUSEIPDB_KEY: Final = "abuseipdb_api_key"
CONF_NOTIFY_SERVICE: Final = "notify_service"
CONF_REPLACE_NOTIFICATION: Final = "replace_builtin_notification"
CONF_RETENTION_DAYS: Final = "retention_days"

DEFAULTS: Final = {
    CONF_BAN_ENABLED: True,
    CONF_MAX_ATTEMPTS: 3,
    CONF_FIND_TIME: 60,
    CONF_BAN_TIME: 1440,  # 24h
    CONF_ESCALATE: True,
    CONF_PERMANENT_AFTER: 3,
    CONF_INSTANT_BAN_PROBES: True,
    CONF_WHITELIST: "",
    CONF_WHITELIST_PRIVATE: True,
    CONF_WHITELIST_SUCCESS: True,
    CONF_CAPTURE_PASSWORDS: True,
    CONF_GEOIP: True,
    CONF_SHODAN: True,
    CONF_ABUSEIPDB_KEY: "",
    CONF_NOTIFY_SERVICE: "",
    CONF_REPLACE_NOTIFICATION: True,
    CONF_RETENTION_DAYS: 90,
}

MAX_EVENTS: Final = 10000
MAX_EVENTS_PER_IP: Final = 500
