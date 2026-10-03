"""Tests for the invalid bindkey repair flow."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.xiaomi_s400_local import repairs
from custom_components.xiaomi_s400_local.const import DOMAIN


async def test_invalid_bindkey_repair_flow(hass: HomeAssistant) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Scale",
        data={"address": "02:00:00:00:00:03", "bindkey": "00" * 16, "token": ""},
    )
    entry.add_to_hass(hass)
    flow = await repairs.async_create_fix_flow(
        hass, "invalid_bindkey_test", {"entry_id": entry.entry_id}
    )
    assert isinstance(flow, repairs.InvalidBindkeyRepairFlow)

    result = await flow.async_step_init()
    assert result["type"] == "form"
    assert result["step_id"] == "credentials"

    result = await flow.async_step_credentials({"bindkey": "bad"})
    assert result["errors"] == {"base": "invalid_key"}
    assert entry.data["bindkey"] == "00" * 16

    with patch.object(
        hass.config_entries, "async_reload", new=AsyncMock(return_value=False)
    ):
        result = await flow.async_step_credentials(
            {"bindkey": "ab" * 16, "token": "cd" * 12}
        )
    assert result["type"] == "form"
    assert result["errors"] == {"base": "reload_failed"}
    assert entry.data["bindkey"] == "ab" * 16

    with patch.object(
        hass.config_entries, "async_reload", new=AsyncMock(return_value=True)
    ):
        result = await flow.async_step_credentials(
            {"bindkey": "ab" * 16, "token": "cd" * 12}
        )
    assert result["type"] == "create_entry"
    assert entry.data["bindkey"] == "ab" * 16
    assert entry.data["token"] == "cd" * 12
