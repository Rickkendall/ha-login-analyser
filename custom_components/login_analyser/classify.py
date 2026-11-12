"""Classify what a failed request was trying to do.

Pure Python, no Home Assistant imports, so it can be unit tested on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote


@dataclass(frozen=True)
class Signature:
    """A known attack / probe pattern."""

    key: str
    label: str
    severity: int  # 1 (noise) .. 5 (targeted / dangerous)
    probe: bool  # True = never legitimate for HA, safe to instant-ban
    pattern: re.Pattern[str]
    description: str = ""


def _p(regex: str) -> re.Pattern[str]:
    return re.compile(regex, re.IGNORECASE)


# Order matters: first match wins for the "primary" category, but every
# matching signature is reported.
PATH_SIGNATURES: list[Signature] = [
    Signature("ha_login", "HA login brute force", 4, False,
              _p(r"^/auth/login_flow"),
              "Username/password submitted to the Home Assistant login form."),
    Signature("ha_token", "HA token abuse", 4, False,
              _p(r"^/auth/token"),
              "Invalid or stolen refresh token / auth code used against /auth/token."),
    Signature("ha_websocket", "HA websocket auth", 3, False,
              _p(r"^/api/websocket"),
              "Websocket connection with an invalid access token."),
    Signature("ha_api", "HA REST API probe", 3, False,
              _p(r"^/api(/|$)"),
              "Fingerprinting the Home Assistant REST API without a valid token."),
    Signature("ha_onboarding", "HA onboarding probe", 4, True,
              _p(r"^/api/onboarding"),
              "Looking for an un-onboarded Home Assistant to take over."),
    Signature("path_traversal", "Path traversal", 5, True,
              _p(r"(\.\./|\.\.\\|%2e%2e|%252e|/etc/passwd|win\.ini)"),
              "Trying to read files outside the web root."),
    Signature("env_secrets", "Secrets / config file hunt", 5, True,
              _p(r"(/\.env|/\.git/|/\.aws/|/\.ssh/|secrets\.ya?ml|/config\.json|/\.DS_Store|/\.svn/|/\.htpasswd|/id_rsa|/credentials)"),
              "Hunting for leaked .env, git, cloud or SSH credentials."),
    Signature("wordpress", "WordPress probe", 3, True,
              _p(r"(/wp-(login|admin|content|includes|json)|/xmlrpc\.php|/wordpress/)"),
              "Automated WordPress scanner."),
    Signature("joomla", "Joomla probe", 3, True,
              _p(r"(/administrator/|/media/system/js/|/media/jui/|/media/vendor/jquery|/components/com_|/joomla)"),
              "Automated Joomla CMS scanner (fingerprinting core JS files)."),
    Signature("phpmyadmin", "phpMyAdmin / DB admin probe", 4, True,
              _p(r"(/phpmyadmin|/pma/|/myadmin|/adminer|/mysql/|/sqladmin)"),
              "Looking for exposed database admin panels."),
    Signature("php_generic", "PHP exploit probe", 3, True,
              _p(r"(\.php(\?|$|/)|/vendor/phpunit|/eval-stdin\.php|/thinkphp|/index\.php\?s=)"),
              "Generic PHP exploit scanning (Home Assistant serves no PHP)."),
    Signature("router_iot", "Router / IoT exploit", 5, True,
              _p(r"(/cgi-bin/|/boaform|/HNAP1|/GponForm|/setup\.cgi|/goform/|/shell\?|/tmUnblock|/picsdesc\.xml|/hudson|/stssys\.htm|/sdk|/device\.rsp|/editBlackAndWhiteList)"),
              "Known exploits for routers, cameras and IoT devices (Mirai-style botnets)."),
    Signature("java_spring", "Java / Spring probe", 4, True,
              _p(r"(/actuator|/jolokia|/manager/html|/solr/|/struts|/console/login|/invoker/|\$\{jndi:)"),
              "Spring Boot actuator, Tomcat manager, Log4Shell and similar."),
    Signature("remote_admin", "Remote admin panel hunt", 3, True,
              _p(r"(/remote/login|/global-protect|/dana-na/|/vpn/|/owa/|/ecp/|/autodiscover|/RDWeb|/sslvpn|/webui|/cpanel|/whm|/plesk)"),
              "Searching for VPN gateways, Exchange, cPanel and other admin portals."),
    Signature("shell_injection", "Command injection", 5, True,
              _p(r"(;\s*(wget|curl|sh|bash)|\|\s*(sh|bash)|`|\$\(|/bin/(sh|bash)|chmod\s|cmd\.exe|powershell)"),
              "Attempting to run shell commands on the server."),
    Signature("crawler_files", "Generic file crawl", 1, False,
              _p(r"(/robots\.txt|/sitemap\.xml|/favicon\.ico|/security\.txt|/\.well-known/)"),
              "Benign-looking crawler files; usually reconnaissance."),
]

UA_SIGNATURES: list[tuple[str, str, re.Pattern[str]]] = [
    ("research_scanner", "Internet research scanner",
     _p(r"(censys|shodan|internet-measurement|expanse|paloalto|binaryedge|onyphe|leakix|criminalip|netcraft|stretchoid|recyber|internet census|zoomeye|fofa|ipip\.net|modat)")),
    ("attack_tool", "Attack / scanning tool",
     _p(r"(sqlmap|nikto|nuclei|masscan|zgrab|nmap|wpscan|dirbuster|gobuster|ffuf|feroxbuster|hydra|medusa|metasploit|jaeles|acunetix|nessus|openvas|whatweb|wfuzz)")),
    ("script", "Script / library client",
     _p(r"^(python-requests|python-urllib|aiohttp|go-http-client|curl|wget|libwww-perl|java/|okhttp|axios|node-fetch|httpx|ruby|php/|scrapy|fasthttp|undici)")),
    ("empty_ua", "No user agent", _p(r"^$")),
]

# Known legitimate Home Assistant clients (useful to spot your own devices
# with expired tokens, so you do not ban yourself).
HA_CLIENT_UA = _p(r"(Home ?Assistant/|HomeAssistant/|io\.robbie\.HomeAssistant|ha-companion|Home%20Assistant)")


@dataclass
class Classification:
    """Result of classifying a request."""

    category: str = "unknown"
    label: str = "Unknown / other"
    severity: int = 2
    probe: bool = False
    tags: list[str] = field(default_factory=list)
    descriptions: list[str] = field(default_factory=list)
    likely_own_device: bool = False

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "label": self.label,
            "severity": self.severity,
            "probe": self.probe,
            "tags": self.tags,
            "descriptions": self.descriptions,
            "likely_own_device": self.likely_own_device,
        }


def classify(path: str, user_agent: str | None, method: str = "GET") -> Classification:
    """Classify a request by URL path (incl. query) and user agent."""
    raw = path or ""
    decoded = unquote(unquote(raw))
    ua = user_agent or ""
    result = Classification()
    matched = False

    for sig in PATH_SIGNATURES:
        if sig.pattern.search(raw) or sig.pattern.search(decoded):
            if not matched:
                result.category = sig.key
                result.label = sig.label
                result.severity = sig.severity
                matched = True
            else:
                result.severity = max(result.severity, sig.severity)
            result.probe = result.probe or sig.probe
            result.tags.append(sig.key)
            if sig.description:
                result.descriptions.append(sig.description)

    for key, label, pattern in UA_SIGNATURES:
        if pattern.search(ua):
            result.tags.append(key)
            result.descriptions.append(f"User agent looks like: {label}.")
            if key == "attack_tool":
                result.severity = max(result.severity, 4)
                result.probe = True
            if not matched:
                result.category = key
                result.label = label
                matched = True

    # The ha_onboarding pattern is more specific than ha_api; prefer it.
    if "ha_onboarding" in result.tags:
        result.category, result.label = "ha_onboarding", "HA onboarding probe"

    if HA_CLIENT_UA.search(ua):
        result.likely_own_device = True
        result.tags.append("ha_client")
        result.descriptions.append(
            "User agent is a Home Assistant app - may be one of YOUR devices with an expired token."
        )
        result.probe = False

    if method.upper() not in ("GET", "POST", "HEAD", "OPTIONS"):
        result.tags.append(f"method_{method.lower()}")

    return result
