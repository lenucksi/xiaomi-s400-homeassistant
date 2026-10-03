"""Repair flows for Xiaomi S400 Local."""

from __future__ import annotations

from typing import Any

import probatio
from homeassistant.components.repairs import RepairsFlow
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .config_flow import _normalise_hex
from .const import CONF_BINDKEY, CONF_TOKEN

# HA 2026.9's form type hint still names voluptuous; probatio works at runtime.


class InvalidBindkeyRepairFlow(RepairsFlow):
    """Update credentials for the config entry named by the repair issue."""

    def __init__(self, hass: HomeAssistant, entry_id: str | None) -> None:
        self.hass = hass
        self.entry_id = entry_id

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Start credential replacement."""
        return await self.async_step_credentials()

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Save validated credentials and reload the scale."""
        entry = self.hass.config_entries.async_get_entry(self.entry_id or "")
        if entry is None:
            return self.async_abort(reason="entry_not_found")
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                bindkey = _normalise_hex(user_input[CONF_BINDKEY], 16)
                token_input = user_input.get(CONF_TOKEN, "").strip()
                token = _normalise_hex(token_input, 12) if token_input else ""
            except ValueError:
                errors["base"] = "invalid_key"
            else:
                self.hass.config_entries.async_update_entry(
                    entry,
                    data={**entry.data, CONF_BINDKEY: bindkey, CONF_TOKEN: token},
                )
                if await self.hass.config_entries.async_reload(entry.entry_id):
                    return self.async_create_entry(data={})
                errors["base"] = "reload_failed"
        return self.async_show_form(
            step_id="credentials",
            data_schema=probatio.Schema(  # type: ignore[arg-type]
                {
                    probatio.Required(CONF_BINDKEY): str,
                    probatio.Optional(CONF_TOKEN): str,
                }
            ),
            errors=errors,
        )


async def async_create_fix_flow(
    hass: HomeAssistant, issue_id: str, data: dict[str, Any] | None
) -> RepairsFlow:
    """Create the repair flow for the invalid bindkey issue."""
    return InvalidBindkeyRepairFlow(hass, data.get("entry_id") if data else None)
