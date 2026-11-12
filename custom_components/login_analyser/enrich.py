"""IP enrichment: reverse DNS, GeoIP/ISP, Shodan InternetDB, AbuseIPDB."""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from ipaddress import ip_address
from typing import Any

import aiohttp

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

IP_API_FIELDS = (
    "status,message,continent,country,countryCode,regionName,city,district,zip,"
    "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)
TIMEOUT = aiohttp.ClientTimeout(total=8)


class RateLimiter:
    """Simple sliding-window limiter (ip-api.com free tier = 45/min)."""

    def __init__(self, per_minute: int) -> None:
        self._per_minute = per_minute
        self._calls: list[float] = []
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._calls = [t for t in self._calls if now - t < 60]
            if len(self._calls) >= self._per_minute:
                await asyncio.sleep(60 - (now - self._calls[0]) + 0.1)
            self._calls.append(time.monotonic())


_ip_api_limiter = RateLimiter(40)


def is_public(ip: str) -> bool:
    try:
        return ip_address(ip).is_global
    except ValueError:
        return False


async def reverse_dns(hass: HomeAssistant, ip: str) -> str | None:
    try:
        async with asyncio.timeout(2):
            host, _, _ = await hass.async_add_executor_job(socket.gethostbyaddr, ip)
            return host
    except (TimeoutError, OSError, UnicodeError):
        return None


async def forward_confirms(hass: HomeAssistant, host: str, ip: str) -> bool | None:
    """Forward-confirmed reverse DNS: does the hostname resolve back to the IP?"""
    try:
        async with asyncio.timeout(2):
            infos = await hass.async_add_executor_job(socket.getaddrinfo, host, None)
            return ip in {i[4][0] for i in infos}
    except (TimeoutError, OSError, UnicodeError):
        return None


async def geoip(hass: HomeAssistant, ip: str) -> dict[str, Any] | None:
    session = async_get_clientsession(hass)
    await _ip_api_limiter.wait()
    try:
        async with session.get(
            f"http://ip-api.com/json/{ip}", params={"fields": IP_API_FIELDS}, timeout=TIMEOUT
        ) as resp:
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, TimeoutError, ValueError) as err:
        _LOGGER.debug("GeoIP lookup failed for %s: %s", ip, err)
        return None
    if data.get("status") != "success":
        return None
    data.pop("status", None)
    data.pop("query", None)
    return data


async def shodan_internetdb(hass: HomeAssistant, ip: str) -> dict[str, Any] | None:
    """Free, keyless: open ports, tags (e.g. 'compromised', 'scanner'), CVEs."""
    session = async_get_clientsession(hass)
    try:
        async with session.get(f"https://internetdb.shodan.io/{ip}", timeout=TIMEOUT) as resp:
            if resp.status == 404:
                return {"ports": [], "tags": [], "vulns": [], "hostnames": [], "cpes": []}
            if resp.status != 200:
                return None
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, TimeoutError, ValueError) as err:
        _LOGGER.debug("Shodan InternetDB lookup failed for %s: %s", ip, err)
        return None
    data.pop("ip", None)
    data["vulns"] = (data.get("vulns") or [])[:25]
    return data


async def abuseipdb(hass: HomeAssistant, ip: str, api_key: str) -> dict[str, Any] | None:
    session = async_get_clientsession(hass)
    try:
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=TIMEOUT,
        ) as resp:
            if resp.status != 200:
                _LOGGER.debug("AbuseIPDB returned %s for %s", resp.status, ip)
                return None
            payload = await resp.json(content_type=None)
    except (aiohttp.ClientError, TimeoutError, ValueError) as err:
        _LOGGER.debug("AbuseIPDB lookup failed for %s: %s", ip, err)
        return None
    d = payload.get("data") or {}
    return {
        "score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "distinct_reporters": d.get("numDistinctUsers"),
        "last_reported": d.get("lastReportedAt"),
        "usage_type": d.get("usageType"),
        "domain": d.get("domain"),
        "is_tor": d.get("isTor"),
        "is_whitelisted": d.get("isWhitelisted"),
    }


async def enrich_ip(
    hass: HomeAssistant,
    ip: str,
    *,
    use_geoip: bool,
    use_shodan: bool,
    abuse_key: str,
) -> dict[str, Any]:
    """Collect everything we can find out about an IP."""
    info: dict[str, Any] = {"looked_up": time.time()}
    try:
        addr = ip_address(ip)
        info["version"] = addr.version
        info["private"] = addr.is_private
    except ValueError:
        return info

    rdns = await reverse_dns(hass, ip)
    info["rdns"] = rdns
    if rdns:
        info["rdns_confirmed"] = await forward_confirms(hass, rdns, ip)

    if not is_public(ip):
        return info

    tasks: dict[str, Any] = {}
    if use_geoip:
        tasks["geo"] = geoip(hass, ip)
    if use_shodan:
        tasks["shodan"] = shodan_internetdb(hass, ip)
    if abuse_key:
        tasks["abuse"] = abuseipdb(hass, ip, abuse_key)
    if tasks:
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for key, res in zip(tasks, results):
            if isinstance(res, Exception):
                _LOGGER.debug("Enrichment %s failed for %s: %s", key, ip, res)
                continue
            if res is not None:
                info[key] = res
    return info
