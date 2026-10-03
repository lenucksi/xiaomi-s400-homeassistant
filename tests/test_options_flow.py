"""Exercise per-scale operational options through Home Assistant."""

from __future__ import annotations

from unittest.mock import patch

import probatio
import pytest
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType, InvalidData
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.xiaomi_s400_local.const import (
    CONF_ACTIVE_RETRY_INTERVAL,
    CONF_CMTP_WAIT_TIMEOUT,
    CONF_FAILURE_THRESHOLD,
    CONF_GATT_TIMEOUT,
    DOMAIN,
)


async def test_options_flow_updates_and_reloads(hass: HomeAssistant) -> None:
    """Saved tuning values reach a new coordinator after the automatic reload."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Scale",
        unique_id="02:00:00:00:00:03",
        data={
            "address": "02:00:00:00:00:03",
            "bindkey": "aa" * 16,
            "token": "bb" * 12,
        },
    )
    entry.add_to_hass(hass)
    with patch(
        "custom_components.xiaomi_s400_local.coordinator.bluetooth.async_register_callback",
        return_value=lambda: None,
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        initial_coordinator = entry.runtime_data

        result = await hass.config_entries.options.async_init(entry.entry_id)
        assert result["type"] == FlowResultType.FORM
        assert result["step_id"] == "init"
        schema = result["data_schema"]
        assert isinstance(schema, probatio.Schema)
        defaults = {marker.schema: marker.default() for marker in schema.schema}
        assert defaults == {
            CONF_FAILURE_THRESHOLD: 5,
            CONF_ACTIVE_RETRY_INTERVAL: 15.0,
            CONF_GATT_TIMEOUT: 8.0,
            CONF_CMTP_WAIT_TIMEOUT: 5.0,
        }

        options = {
            CONF_FAILURE_THRESHOLD: 3,
            CONF_ACTIVE_RETRY_INTERVAL: 30.0,
            CONF_GATT_TIMEOUT: 12.0,
            CONF_CMTP_WAIT_TIMEOUT: 2.0,
        }
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], options
        )
        await hass.async_block_till_done()
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert entry.options == options
        assert entry.runtime_data is not initial_coordinator
        assert entry.runtime_data.failure_threshold == 3
        assert entry.runtime_data.active_retry_interval == 30.0
        assert entry.runtime_data.gatt_timeout == 12.0
        assert entry.runtime_data.cmtp_wait_timeout == 2.0

        reopened = await hass.config_entries.options.async_init(entry.entry_id)
        saved_defaults = {
            marker.schema: marker.default() for marker in reopened["data_schema"].schema
        }
        assert saved_defaults == options

        assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.parametrize(
    ("key", "invalid"),
    [
        (CONF_FAILURE_THRESHOLD, 0),
        (CONF_FAILURE_THRESHOLD, 2.5),
        (CONF_ACTIVE_RETRY_INTERVAL, 0),
        (CONF_GATT_TIMEOUT, 61),
        (CONF_CMTP_WAIT_TIMEOUT, 0.1),
    ],
)
async def test_options_schema_rejects_out_of_range_values(
    hass: HomeAssistant, key: str, invalid: float
) -> None:
    """The form rejects out-of-range and fractional threshold values."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Scale",
        data={"address": "02:00:00:00:00:03", "bindkey": "aa" * 16, "token": ""},
    )
    entry.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    schema = result["data_schema"]
    options = {
        CONF_FAILURE_THRESHOLD: 5,
        CONF_ACTIVE_RETRY_INTERVAL: 15.0,
        CONF_GATT_TIMEOUT: 8.0,
        CONF_CMTP_WAIT_TIMEOUT: 5.0,
    }
    options[key] = invalid
    with pytest.raises(probatio.Invalid):
        schema(options)
    with pytest.raises(InvalidData) as error:
        await hass.config_entries.options.async_configure(result["flow_id"], options)
    assert key in error.value.schema_errors
