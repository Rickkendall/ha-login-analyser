"""Sensors for Login Analyser."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .analyser import LoginAnalyser
from .const import DOMAIN, SIGNAL_UPDATE


@dataclass(frozen=True, kw_only=True)
class LASensorDescription(SensorEntityDescription):
    value_fn: Callable[[LoginAnalyser], Any]
    attrs_fn: Callable[[LoginAnalyser], dict[str, Any]] | None = None


def _last_event_attrs(a: LoginAnalyser) -> dict[str, Any]:
    if not a.events:
        return {}
    e = a.events[-1]
    rec = a.ips.get(e["ip"], {})
    enr = rec.get("enrichment") or {}
    geo = enr.get("geo") or {}
    return {
        "ip": e["ip"],
        "hostname": enr.get("rdns"),
        "country": geo.get("country"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "asn": geo.get("as"),
        "hosting": geo.get("hosting"),
        "proxy": geo.get("proxy"),
        "abuse_score": (enr.get("abuse") or {}).get("score"),
        "method": e["method"],
        "path": e["path"],
        "category": e["classification"]["label"],
        "severity": e["classification"]["severity"],
        "username": e.get("username"),
        "user_agent": e.get("user_agent"),
        "attempts_from_ip": rec.get("count"),
        "action": e.get("action"),
        "latitude": geo.get("lat"),
        "longitude": geo.get("lon"),
    }


def _last_ts(a: LoginAnalyser) -> datetime | None:
    if not a.events:
        return None
    return datetime.fromtimestamp(a.events[-1]["ts"], tz=timezone.utc)


SENSORS: tuple[LASensorDescription, ...] = (
    LASensorDescription(
        key="attempts_24h",
        translation_key="attempts_24h",
        icon="mdi:shield-alert",
        native_unit_of_measurement="attempts",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda a: a.summary()["events_24h"],
    ),
    LASensorDescription(
        key="attempts_total",
        translation_key="attempts_total",
        icon="mdi:counter",
        native_unit_of_measurement="attempts",
        state_class=SensorStateClass.TOTAL,
        value_fn=lambda a: len(a.events),
    ),
    LASensorDescription(
        key="attackers_24h",
        translation_key="attackers_24h",
        icon="mdi:account-alert",
        native_unit_of_measurement="IPs",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda a: a.summary()["unique_ips_24h"],
    ),
    LASensorDescription(
        key="active_bans",
        translation_key="active_bans",
        icon="mdi:shield-lock",
        native_unit_of_measurement="IPs",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda a: a.summary()["active_bans"],
        attrs_fn=lambda a: {
            "banned_ips": sorted(a.bans)[:50],
            "blocking_enforced": a.ban_backend_available,
        },
    ),
    LASensorDescription(
        key="last_attacker",
        translation_key="last_attacker",
        icon="mdi:ip-network",
        value_fn=lambda a: a.events[-1]["ip"] if a.events else None,
        attrs_fn=_last_event_attrs,
    ),
    LASensorDescription(
        key="last_attempt",
        translation_key="last_attempt",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=_last_ts,
    ),
    LASensorDescription(
        key="top_country",
        translation_key="top_country",
        icon="mdi:earth",
        value_fn=lambda a: (a.summary()["top_countries"] or [[None]])[0][0],
        attrs_fn=lambda a: {"countries": dict(a.summary()["top_countries"])},
    ),
)


async def async_setup_entry(hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback) -> None:
    analyser: LoginAnalyser = entry.runtime_data
    async_add_entities(LASensor(analyser, d, entry.entry_id) for d in SENSORS)


class LASensor(SensorEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False
    _unrecorded_attributes = frozenset({"banned_ips", "countries", "user_agent", "path"})

    def __init__(self, analyser: LoginAnalyser, description: LASensorDescription, entry_id: str) -> None:
        self.entity_description = description
        self._analyser = analyser
        self._attr_unique_id = f"{entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry_id)},
            name="Login Analyser",
            manufacturer="Login Analyser",
            entry_type=DeviceEntryType.SERVICE,
            configuration_url="homeassistant://login-analyser",
        )

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(async_dispatcher_connect(self.hass, SIGNAL_UPDATE, self._update))

    @callback
    def _update(self) -> None:
        self.async_write_ha_state()

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self._analyser)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self._analyser)
