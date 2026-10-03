"""Unit tests for the Bluetooth coordinator."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from homeassistant.core import HomeAssistant

from custom_components.xiaomi_s400_local import active
from custom_components.xiaomi_s400_local.const import DOMAIN, MIBEACON_UUID
from custom_components.xiaomi_s400_local.coordinator import S400Coordinator
from custom_components.xiaomi_s400_local.protocol import CMTP

ADDRESS = "02:00:00:00:00:03"
BINDKEY = bytes.fromhex("00112233445566778899aabbccddeeff")
_MAC = bytes.fromhex("020000000003")
_EMBEDDED_MAC = _MAC[::-1]


def _frame(
    *, mass: int, hr: int, imp: int, profile: int = 1, ts: int = 1700000000
) -> bytes:
    prefix = (0x5858).to_bytes(2, "little") + bytes.fromhex("d9302a")
    packed = mass | (hr << 11) | (imp << 18)
    payload = (
        bytes.fromhex("166e09")
        + bytes([profile])
        + packed.to_bytes(4, "little")
        + ts.to_bytes(4, "little")
    )
    ext = bytes.fromhex("010203")
    # The parser builds the nonce from the reversed (embedded) MAC bytes.
    nonce = _EMBEDDED_MAC + bytes.fromhex("d9302a") + ext
    enc = AESCCM(BINDKEY, tag_length=4).encrypt(nonce, payload, b"\x11")
    return prefix + _EMBEDDED_MAC + enc[:-4] + ext + enc[-4:]


def _service_info(raw: bytes) -> SimpleNamespace:
    return SimpleNamespace(service_data={MIBEACON_UUID: raw}, rssi=-70)


def _coordinator(hass: HomeAssistant, token: bytes | None = None) -> S400Coordinator:
    with patch(
        "custom_components.xiaomi_s400_local.coordinator.bluetooth.async_register_callback",
        return_value=lambda: None,
    ):
        coordinator = S400Coordinator(hass, ADDRESS, BINDKEY, token)
        coordinator.start()
    return coordinator


async def test_advertisement_updates_weight_and_low_impedance(
    hass: HomeAssistant,
) -> None:
    coordinator = _coordinator(hass)
    # mass 1001 (100.1 kg), hr_raw 31 (81 bpm), imp 4620 (462.0 ohm) on the weight frame
    coordinator._advertisement(_service_info(_frame(mass=1001, hr=31, imp=4620)), None)
    assert coordinator.values["weight"] == 100.1
    assert coordinator.values["heart_rate"] == 81
    assert coordinator.values["impedance_low"] == 462.0
    assert coordinator.values["profile_id"] == 1
    assert coordinator.last_error is None


async def test_advertisement_final_frame_sets_high_impedance(
    hass: HomeAssistant,
) -> None:
    coordinator = _coordinator(hass)
    coordinator._advertisement(_service_info(_frame(mass=0, hr=0, imp=4228)), None)
    assert coordinator.values["impedance_high"] == 422.8
    assert coordinator.values["weight"] is None


async def test_invalid_advertisement_sets_and_clears_error(
    hass: HomeAssistant,
) -> None:
    coordinator = _coordinator(hass)
    bad = bytes.fromhex("5858d9302a") + _EMBEDDED_MAC + bytes(15)
    coordinator._advertisement(_service_info(bad), None)
    assert coordinator.last_error is not None

    # A valid frame clears the error again.
    coordinator._advertisement(_service_info(_frame(mass=500, hr=0, imp=0)), None)
    assert coordinator.last_error is None


async def test_advertisement_without_service_data_is_ignored(
    hass: HomeAssistant,
) -> None:
    coordinator = _coordinator(hass)
    coordinator._advertisement(SimpleNamespace(service_data={}, rssi=-70), None)
    assert coordinator.values["weight"] is None
    assert coordinator.last_error is None


async def test_active_session_skipped_without_token(hass: HomeAssistant) -> None:
    coordinator = _coordinator(hass)
    with patch.object(
        coordinator, "_active_session", new=AsyncMock()
    ) as active_session:
        coordinator._start_active_session()
        active_session.assert_not_called()


async def test_active_session_throttled(hass: HomeAssistant) -> None:
    coordinator = _coordinator(hass, token=bytes(12))
    with patch.object(coordinator, "_active_session", new=AsyncMock()):
        coordinator._start_active_session()
        coordinator._start_active_session()  # within the throttle window


async def test_active_session_without_connectable_device(hass: HomeAssistant) -> None:
    coordinator = _coordinator(hass, token=bytes(12))
    with patch(
        "custom_components.xiaomi_s400_local.coordinator.bluetooth.async_ble_device_from_address",
        return_value=None,
    ):
        await coordinator._active_session()
    assert coordinator.last_error is None


async def test_active_session_connection_error_sets_last_error(
    hass: HomeAssistant,
) -> None:
    coordinator = _coordinator(hass, token=bytes(12))
    with (
        patch(
            "custom_components.xiaomi_s400_local.coordinator.bluetooth.async_ble_device_from_address",
            return_value=object(),
        ),
        patch(
            "custom_components.xiaomi_s400_local.coordinator.establish_connection",
            side_effect=RuntimeError("boom"),
        ),
    ):
        await coordinator._active_session()
    assert coordinator.last_error is not None
    assert coordinator.last_error == "active GATT: RuntimeError"


async def test_apply_active_measurement_and_stop(hass: HomeAssistant) -> None:
    coordinator = _coordinator(hass)
    coordinator._apply_active_measurement(
        active.ActiveMeasurement(
            weight=99.9,
            stabilized=True,
            profile_id=2,
            timestamp=1700000000,
            impedance_low=500.0,
            impedance_high=450.0,
        )
    )
    assert coordinator.values["weight"] == 99.9
    assert coordinator.values["impedance_low"] == 500.0
    assert coordinator.values["impedance_high"] == 450.0
    assert coordinator.values["stabilized"] is True
    await coordinator.stop()


class _ActiveClient:
    def __init__(self, queue) -> None:
        self._queue = queue

    @property
    def is_connected(self) -> bool:
        return not self._queue.empty()

    async def disconnect(self) -> None: ...


class _ActiveTransport:
    def __init__(self, queue) -> None:
        self.queues = {CMTP: queue}

    async def start_official_order(self) -> None: ...
    async def official_init(self) -> None: ...
    async def finish_subscriptions(self) -> None: ...
    async def write(self, uuid, value) -> None: ...


async def test_active_session_applies_cmtp_measurement(hass: HomeAssistant) -> None:
    import asyncio

    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    from custom_components.xiaomi_s400_local.crypto import SessionKeys
    from custom_components.xiaomi_s400_local.protocol import RCV_OK, RCV_RDY

    keys = SessionKeys(
        device_key=bytes.fromhex("00112233445566778899aabbccddeeff"),
        app_key=bytes(16),
        device_iv=bytes.fromhex("01020304"),
        app_iv=bytes(4),
    )
    counter = bytes.fromhex("1700")
    nonce = keys.device_iv + bytes(4) + counter + bytes(2)
    plaintext = b"\x00" * 12 + b"\xa0" + b"1001,1"
    ciphertext = AESCCM(keys.device_key, tag_length=4).encrypt(nonce, plaintext, None)
    message = counter + ciphertext

    queue: asyncio.Queue[bytes] = asyncio.Queue()
    queue.put_nowait(bytes.fromhex("000000") + b"\x00" + (1).to_bytes(2, "little"))
    queue.put_nowait(b"\x01\x00" + message)

    client = _ActiveClient(queue)
    transport = _ActiveTransport(queue)
    coordinator = _coordinator(hass, token=bytes(12))

    with (
        patch(
            "custom_components.xiaomi_s400_local.coordinator.bluetooth.async_ble_device_from_address",
            return_value=object(),
        ),
        patch(
            "custom_components.xiaomi_s400_local.coordinator.establish_connection",
            new=AsyncMock(return_value=client),
        ),
        patch(
            "custom_components.xiaomi_s400_local.coordinator._GattTransport",
            lambda *a, **k: transport,
        ),
        patch(
            "custom_components.xiaomi_s400_local.coordinator._login",
            new=AsyncMock(return_value=keys),
        ),
    ):
        await coordinator._active_session()

    assert coordinator.values["weight"] == 100.1
    assert RCV_RDY and RCV_OK  # symbols used


async def test_advertisement_with_token_triggers_active(hass: HomeAssistant) -> None:
    coordinator = _coordinator(hass, token=bytes(12))
    with patch.object(
        coordinator, "_active_session", new=AsyncMock()
    ) as active_session:
        coordinator._advertisement(_service_info(_frame(mass=500, hr=0, imp=0)), None)
        assert active_session.called


async def test_stop_cancels_running_task(hass: HomeAssistant) -> None:
    import asyncio

    coordinator = _coordinator(hass, token=bytes(12))

    async def _never() -> None:
        await asyncio.sleep(10)

    coordinator._active_task = hass.async_create_task(_never())
    await coordinator.stop()


async def test_repeated_failures_raise_and_clear_repair_issue(
    hass: HomeAssistant,
) -> None:
    from homeassistant.helpers import issue_registry as ir

    coordinator = _coordinator(hass)
    coordinator.entry_id = "01TESTENTRY"
    key = (DOMAIN, coordinator._issue_id())
    bad = bytes.fromhex("5858d9302a") + _EMBEDDED_MAC + bytes(15)
    for _ in range(5):
        coordinator._advertisement(_service_info(bad), None)
    assert key in ir.async_get(hass).issues

    coordinator._advertisement(_service_info(_frame(mass=500, hr=0, imp=0)), None)
    assert key not in ir.async_get(hass).issues


async def test_new_weighing_clears_previous_persons_metrics(
    hass: HomeAssistant,
) -> None:
    coordinator = _coordinator(hass)
    coordinator._advertisement(_service_info(_frame(mass=500, hr=0, imp=0)), None)
    coordinator.values["heart_rate"] = 82
    coordinator.values["impedance_high"] = 470.0
    assert coordinator.values["stabilized"] is True

    coordinator._advertisement(_service_info(bytes.fromhex("0051d9302a")), None)
    assert coordinator.values["stabilized"] is True

    coordinator._advertisement(_service_info(_frame(mass=600, hr=0, imp=5000)), None)
    assert coordinator.values["weight"] == 60.0
    assert coordinator.values["stabilized"] is False
    assert coordinator.values["heart_rate"] is None
    assert coordinator.values["impedance_high"] is None


async def test_only_authentication_failures_raise_bindkey_repair(
    hass: HomeAssistant,
) -> None:
    from homeassistant.helpers import issue_registry as ir

    coordinator = _coordinator(hass)
    coordinator.entry_id = "01TESTENTRY"
    key = (DOMAIN, coordinator._issue_id())
    for _ in range(6):
        coordinator._advertisement(_service_info(bytes.fromhex("005100002a")), None)
    coordinator._note_error("active GATT: TimeoutError")
    assert key not in ir.async_get(hass).issues

    bad = bytes.fromhex("5858d9302a") + _EMBEDDED_MAC + bytes(15)
    for _ in range(5):
        coordinator._advertisement(_service_info(bad), None)
    assert key in ir.async_get(hass).issues
    coordinator._advertisement(_service_info(bytes.fromhex("0051d9302a")), None)
    assert key in ir.async_get(hass).issues


@pytest.mark.parametrize("token", [None, bytes(12)])
async def test_listener_registration(hass: HomeAssistant, token) -> None:
    coordinator = _coordinator(hass, token=token)
    calls: list[int] = []

    def listener() -> None:
        calls.append(1)

    remove = coordinator.add_listener(listener)
    coordinator._notify_listeners()
    assert calls == [1]
    remove()
    coordinator._notify_listeners()
    assert calls == [1]
