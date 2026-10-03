"""Configure an already provisioned Xiaomi S400 with locally stored keys."""

from __future__ import annotations

from typing import Any

import probatio
from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import HomeAssistant

from .const import (
    CONF_BINDKEY,
    CONF_TOKEN,
    DOMAIN,
    MIBEACON_UUID,
    S400_PRODUCT_IDS,
)
from .pairing import product_id_from_service_data

# HA 2026.9's form type hints still name voluptuous, although its runtime
# serializer and validator accept probatio.Schema (covered by flow tests).


def _normalise_hex(value: str, byte_length: int) -> str:
    cleaned = value.strip().lower()
    raw = bytes.fromhex(cleaned)
    if len(raw) != byte_length:
        raise ValueError
    return raw.hex()


def _normalise_address(value: str) -> str:
    raw = bytes.fromhex(value.strip().replace(":", "").replace("-", ""))
    if len(raw) != 6:
        raise ValueError
    return ":".join(f"{part:02X}" for part in raw)


def _discovered(hass: HomeAssistant) -> dict[str, str]:
    choices: dict[str, str] = {}
    for info in bluetooth.async_discovered_service_info(hass, connectable=False):
        pid = product_id_from_service_data(info.service_data.get(MIBEACON_UUID))
        if pid in S400_PRODUCT_IDS or "s400" in (info.name or "").lower():
            choices[info.address] = f"{info.name or 'Xiaomi S400'} ({info.address})"
    return choices


class S400ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Configure the local FE95 and GATT credentials without cloud access."""

    VERSION = 1

    def __init__(self) -> None:
        self._address: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                address = _normalise_address(user_input[CONF_ADDRESS])
            except ValueError:
                errors[CONF_ADDRESS] = "invalid_address"
            else:
                await self.async_set_unique_id(address)
                self._abort_if_unique_id_configured()
                self._address = address
                return await self.async_step_keys()
        choices = _discovered(self.hass)
        address_field = (
            probatio.Required(CONF_ADDRESS, default=next(iter(choices)))
            if choices
            else probatio.Required(CONF_ADDRESS)
        )
        return self.async_show_form(
            step_id="user",
            data_schema=probatio.Schema({address_field: str}),  # type: ignore[arg-type]
            errors=errors,
        )

    async def async_step_keys(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                bindkey = _normalise_hex(user_input[CONF_BINDKEY], 16)
                token_input = user_input.get(CONF_TOKEN, "").strip()
                token = _normalise_hex(token_input, 12) if token_input else ""
            except ValueError:
                errors["base"] = "invalid_key"
            else:
                if self._address is None:
                    return self.async_abort(reason="not_supported")
                return self.async_create_entry(
                    title=f"Xiaomi S400 {self._address[-5:]}",
                    data={
                        CONF_ADDRESS: self._address,
                        CONF_BINDKEY: bindkey,
                        CONF_TOKEN: token,
                    },
                )
        return self.async_show_form(
            step_id="keys",
            data_schema=probatio.Schema(  # type: ignore[arg-type]
                {
                    probatio.Required(CONF_BINDKEY): str,
                    probatio.Optional(CONF_TOKEN): str,
                }
            ),
            errors=errors,
        )

    async def async_step_bluetooth(self, discovery_info: Any) -> ConfigFlowResult:
        pid = product_id_from_service_data(
            discovery_info.service_data.get(MIBEACON_UUID)
        )
        if pid not in S400_PRODUCT_IDS:
            return self.async_abort(reason="not_supported")
        await self.async_set_unique_id(discovery_info.address.upper())
        self._abort_if_unique_id_configured()
        self._address = _normalise_address(discovery_info.address)
        self.context["title_placeholders"] = {"name": discovery_info.name}
        return await self.async_step_discovery_confirm()

    async def async_step_discovery_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return await self.async_step_keys()
        self._set_confirm_only()
        return self.async_show_form(step_id="discovery_confirm")

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Replace credentials after a new bind without creating a second device."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                bindkey = _normalise_hex(user_input[CONF_BINDKEY], 16)
                token_input = user_input.get(CONF_TOKEN, "").strip()
                token = _normalise_hex(token_input, 12) if token_input else ""
            except ValueError:
                errors["base"] = "invalid_key"
            else:
                await self.async_set_unique_id(entry.unique_id)
                self._abort_if_unique_id_mismatch()
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={CONF_BINDKEY: bindkey, CONF_TOKEN: token},
                )
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=probatio.Schema(  # type: ignore[arg-type]
                {
                    probatio.Required(
                        CONF_BINDKEY, default=entry.data.get(CONF_BINDKEY, "")
                    ): str,
                    probatio.Optional(
                        CONF_TOKEN, default=entry.data.get(CONF_TOKEN, "")
                    ): str,
                }
            ),
            errors=errors,
        )
