"""Exercise credential reconfiguration through Home Assistant's flow manager."""

from __future__ import annotations

import probatio
import pytest
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType, InvalidData
from homeassistant.helpers import config_validation as cv
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.xiaomi_s400_local.const import DOMAIN


async def test_reconfigure_prefills_and_updates_credentials(
    hass: HomeAssistant,
) -> None:
    address = "02:00:00:00:00:03"
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Xiaomi S400 FC:29",
        unique_id=address,
        data={"address": address, "bindkey": "aa" * 16, "token": "bb" * 12},
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "reconfigure", "entry_id": entry.entry_id}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    defaults = {
        marker.schema: marker.default() for marker in result["data_schema"].schema
    }
    assert defaults == {"bindkey": "aa" * 16, "token": "bb" * 12}
    assert probatio.to_field_list(
        result["data_schema"], custom_serializer=cv.custom_serializer
    ) == [
        {
            "type": "string",
            "name": "bindkey",
            "required": True,
            "default": "aa" * 16,
        },
        {
            "type": "string",
            "name": "token",
            "required": False,
            "optional": True,
            "default": "bb" * 12,
        },
    ]

    with pytest.raises(InvalidData) as error:
        await hass.config_entries.flow.async_configure(
            result["flow_id"], {"bindkey": 42}
        )
    assert "bindkey" in error.value.schema_errors

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"bindkey": "cc" * 16, "token": "dd" * 12}
    )
    assert result["type"] == FlowResultType.ABORT
    assert entry.data["bindkey"] == "cc" * 16
    assert entry.data["token"] == "dd" * 12
