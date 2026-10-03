"""Keep the HA setup flow limited to supported local credential import."""

from __future__ import annotations

import asyncio
import sys
from importlib import import_module
from types import ModuleType, SimpleNamespace

import probatio
import pytest
from test_crypto_parser import PACKAGE


@pytest.fixture
def flow_module(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    ha = ModuleType("homeassistant")
    components = ModuleType("homeassistant.components")
    bluetooth = ModuleType("homeassistant.components.bluetooth")
    entries = ModuleType("homeassistant.config_entries")
    constants = ModuleType("homeassistant.const")
    core = ModuleType("homeassistant.core")

    class ConfigFlow:
        def __init_subclass__(cls, **kwargs):
            return super().__init_subclass__()

        async def async_set_unique_id(self, unique_id):
            self._unique_id = unique_id

        def _abort_if_unique_id_configured(self):
            pass

        def _abort_if_unique_id_mismatch(self):
            assert self._unique_id == self._entry.unique_id

        def _get_reconfigure_entry(self):
            return self._entry

        def async_show_form(self, **kwargs):
            return {"type": "form", **kwargs}

        def async_create_entry(self, **kwargs):
            return {"type": "create_entry", **kwargs}

        def async_update_reload_and_abort(self, entry, **kwargs):
            return {"type": "reconfigure", "entry": entry, **kwargs}

        def async_abort(self, **kwargs):
            return {"type": "abort", **kwargs}

        def _set_confirm_only(self):
            pass

    bluetooth.async_discovered_service_info = lambda hass, connectable: []
    components.bluetooth = bluetooth
    ha.components = components
    entries.ConfigFlow = ConfigFlow
    entries.ConfigFlowResult = dict
    constants.CONF_ADDRESS = "address"
    core.HomeAssistant = object
    for name, module in (
        ("homeassistant", ha),
        ("homeassistant.components", components),
        ("homeassistant.components.bluetooth", bluetooth),
        ("homeassistant.config_entries", entries),
        ("homeassistant.const", constants),
        ("homeassistant.core", core),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setitem(sys.modules, PACKAGE.__name__, PACKAGE)
    sys.modules.pop("s400_test_core.config_flow", None)
    yield import_module("s400_test_core.config_flow")
    sys.modules.pop("s400_test_core.config_flow", None)


def test_user_setup_only_imports_existing_keys(flow_module: ModuleType) -> None:
    flow = flow_module.S400ConfigFlow()
    flow.hass = object()
    initial = asyncio.run(flow.async_step_user())
    assert initial["step_id"] == "user"
    assert isinstance(initial["data_schema"], probatio.Schema)
    assert [field.schema for field in initial["data_schema"].schema] == ["address"]

    keys = asyncio.run(flow.async_step_user({"address": "02-00-00-00-00-05"}))
    assert keys["step_id"] == "keys"
    assert [field.schema for field in keys["data_schema"].schema] == [
        "bindkey",
        "token",
    ]
    entry = asyncio.run(
        flow.async_step_keys({"bindkey": "AA" * 16, "token": "BB" * 12})
    )
    assert entry["data"] == {
        "address": "02:00:00:00:00:05",
        "bindkey": "aa" * 16,
        "token": "bb" * 12,
    }


def test_reconfigure_reloads_existing_entry(flow_module: ModuleType) -> None:
    flow = flow_module.S400ConfigFlow()
    flow._entry = SimpleNamespace(
        unique_id="02:00:00:00:00:05", data={"bindkey": "aa" * 16}
    )
    invalid = asyncio.run(flow.async_step_reconfigure({"bindkey": "wrong"}))
    assert invalid["errors"] == {"base": "invalid_key"}

    result = asyncio.run(
        flow.async_step_reconfigure({"bindkey": "00" * 16, "token": "11" * 12})
    )
    assert result["type"] == "reconfigure"
    assert result["entry"] is flow._entry
    assert result["data_updates"] == {"bindkey": "00" * 16, "token": "11" * 12}
