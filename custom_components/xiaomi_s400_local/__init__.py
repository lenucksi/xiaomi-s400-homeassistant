"""Xiaomi S400 Local integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntry

from .const import CONF_BINDKEY, CONF_TOKEN, DOMAIN
from .coordinator import S400Coordinator

PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR]

type S400ConfigEntry = ConfigEntry[S400Coordinator]


async def async_setup_entry(hass: HomeAssistant, entry: S400ConfigEntry) -> bool:
    """Start passive local reception for one S400."""
    token_hex = entry.data.get(CONF_TOKEN, "")
    coordinator = S400Coordinator(
        hass,
        entry.data["address"],
        bytes.fromhex(entry.data[CONF_BINDKEY]),
        bytes.fromhex(token_hex) if token_hex else None,
        entry.entry_id,
    )
    entry.runtime_data = coordinator
    coordinator.start()
    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except Exception:
        await coordinator.stop()
        raise
    return True


async def async_unload_entry(hass: HomeAssistant, entry: S400ConfigEntry) -> bool:
    """Unload an S400 and its Bluetooth listener."""
    if not await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        return False
    await entry.runtime_data.stop()
    return True


async def async_remove_config_entry_device(
    hass: HomeAssistant,
    entry: S400ConfigEntry,
    device_entry: DeviceEntry,
) -> bool:
    """Allow removing stale devices, but retain the configured scale."""
    return (DOMAIN, entry.data["address"].upper()) not in device_entry.identifiers
