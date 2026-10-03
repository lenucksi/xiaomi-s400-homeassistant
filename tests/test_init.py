"""Tests for setup/unload, entities and diagnostics."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.xiaomi_s400_local.const import DOMAIN

ADDRESS = "02:00:00:00:00:03"


def _entry(**data) -> MockConfigEntry:
    payload = {"address": ADDRESS, "bindkey": "00" * 16, "token": ""}
    payload.update(data)
    return MockConfigEntry(
        domain=DOMAIN,
        title="Xiaomi S400 FC:29",
        unique_id=ADDRESS,
        data=payload,
    )


async def test_setup_creates_entities_and_unloads(hass: HomeAssistant) -> None:
    entry = _entry()
    entry.add_to_hass(hass)

    with patch(
        "custom_components.xiaomi_s400_local.coordinator.bluetooth.async_register_callback",
        return_value=lambda: None,
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

        assert hass.states.get("sensor.xiaomi_s400_fc_29_weight") is not None
        assert hass.states.get("sensor.xiaomi_s400_fc_29_heart_rate") is not None
        assert hass.states.get("sensor.xiaomi_s400_fc_29_impedance_50_khz") is not None
        assert hass.states.get("sensor.xiaomi_s400_fc_29_impedance_250_khz") is not None
        assert hass.states.get("sensor.xiaomi_s400_fc_29_profile_id") is not None
        assert (
            hass.states.get("binary_sensor.xiaomi_s400_fc_29_measurement_stabilized")
            is not None
        )

        assert await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()


async def test_diagnostics_redacts_secrets(hass: HomeAssistant) -> None:
    entry = _entry(token="ab" * 12)
    entry.add_to_hass(hass)

    with patch(
        "custom_components.xiaomi_s400_local.coordinator.bluetooth.async_register_callback",
        return_value=lambda: None,
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

        from custom_components.xiaomi_s400_local.diagnostics import (
            async_get_config_entry_diagnostics,
        )

        result = await async_get_config_entry_diagnostics(hass, entry)
        assert result["config"]["bindkey"] == "**REDACTED**"
        assert result["config"]["token"] == "**REDACTED**"
        assert "last_error" in result
        assert "values" in result

        await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()


async def test_sensor_restore_paths(hass: HomeAssistant) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from custom_components.xiaomi_s400_local.coordinator import S400Coordinator
    from custom_components.xiaomi_s400_local.entity import S400Entity
    from custom_components.xiaomi_s400_local.sensor import SENSORS, S400Sensor

    entry = _entry()
    entry.add_to_hass(hass)
    coordinator = S400Coordinator(hass, ADDRESS, bytes(16), None, entry.entry_id)
    entity = S400Sensor(entry, coordinator, SENSORS[0])
    entity.hass = hass

    with (
        patch.object(S400Entity, "async_added_to_hass", new=AsyncMock()),
        patch.object(
            entity,
            "async_get_last_sensor_data",
            new=AsyncMock(return_value=SimpleNamespace(native_value=123.4)),
        ),
        patch.object(entity, "async_write_ha_state"),
    ):
        coordinator.values["weight"] = 50.0
        await entity.async_added_to_hass()
        assert coordinator.values["weight"] == 50.0

        coordinator.values["weight"] = None
        await entity.async_added_to_hass()
        assert coordinator.values["weight"] == 123.4


async def test_remove_stale_device_returns_true(hass: HomeAssistant) -> None:
    entry = _entry()
    entry.add_to_hass(hass)

    with patch(
        "custom_components.xiaomi_s400_local.coordinator.bluetooth.async_register_callback",
        return_value=lambda: None,
    ):
        from custom_components.xiaomi_s400_local import (
            async_remove_config_entry_device,
        )

        current = SimpleNamespace(identifiers={(DOMAIN, ADDRESS)})
        stale = SimpleNamespace(identifiers={(DOMAIN, "02:00:00:00:00:04")})
        assert not await async_remove_config_entry_device(hass, entry, current)
        assert await async_remove_config_entry_device(hass, entry, stale)
