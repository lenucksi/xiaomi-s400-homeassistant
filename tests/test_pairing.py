"""Tests for the local pairing helpers and GATT transport."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from custom_components.xiaomi_s400_local import pairing
from custom_components.xiaomi_s400_local.crypto import generate_keypair
from custom_components.xiaomi_s400_local.protocol import (
    AVDTP,
    CMD_TRANSPORT_INIT,
    DEVICE_INFO_QUERIES,
    RCV_ACK,
    RCV_OK,
    RCV_RDY,
    REGISTER_OK,
    TRANSPORT_OFFER,
    TRANSPORT_PROBE,
    UPNP,
    VEND1C,
)


class FakeClient:
    def __init__(self) -> None:
        self.writes: list[tuple[str, bytes]] = []
        self.notify: dict[str, object] = {}
        self.version = bytes.fromhex("02000000")

    async def start_notify(self, uuid, callback):
        self.notify[uuid] = callback

    async def write_gatt_char(self, uuid, data, response=False):
        self.writes.append((uuid, bytes(data)))

    async def read_gatt_char(self, uuid):
        return self.version


def _transport(timeout: float = 0.5) -> tuple[pairing._GattTransport, FakeClient]:
    client = FakeClient()
    return pairing._GattTransport(client, pairing.TraceRecorder(None), timeout), client


def _put(transport: pairing._GattTransport, uuid: str, data: bytes) -> None:
    transport.queues[uuid].put_nowait(data)


async def test_trace_recorder_writes_and_handles_errors(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    with pairing.TraceRecorder(path) as recorder:
        recorder.record("event", value=1)
    assert '"event"' in path.read_text()
    assert oct(path.stat().st_mode & 0o777) == "0o600"

    recorder = pairing.TraceRecorder(None)
    recorder.record("ignored")
    with pytest.raises(ValueError), pairing.TraceRecorder(path) as rec:
        rec.record("before")
        raise ValueError("boom")
    assert "pairing_error" in path.read_text()


async def test_transport_subscribe_write_and_receive() -> None:
    transport, client = _transport()
    await transport.subscribe(UPNP)
    await transport.subscribe(UPNP)  # idempotent
    client.notify[UPNP](None, bytearray(b"abc"))
    assert await transport.receive(UPNP) == b"abc"

    await transport.write(UPNP, b"\x01\x02")
    assert client.writes[-1] == (UPNP, b"\x01\x02")


async def test_transport_expect_parcel_command_and_send() -> None:
    transport, client = _transport()
    _put(transport, AVDTP, RCV_OK)
    await transport.expect(AVDTP, RCV_OK, "context")

    _put(transport, AVDTP, b"\xff")
    with pytest.raises(pairing.PairingError):
        await transport.expect(AVDTP, RCV_OK, "mismatch")

    transport.parcel_chunk_size = 4
    header = transport.parcel_command(0x00, b"abcdefgh")
    assert header == bytes.fromhex("000000") + b"\x00" + (2).to_bytes(2, "little")

    with pytest.raises(pairing.PairingError):
        transport.parcel_command(0x100, b"x")

    await transport.send_parcel(b"abcdefgh", inter_frame_delay=0)
    assert [w[1][:2] for w in client.writes[-2:]] == [
        (1).to_bytes(2, "little"),
        (2).to_bytes(2, "little"),
    ]


async def test_transport_receive_multi_frame_parcel() -> None:
    transport, client = _transport()
    _put(
        transport, AVDTP, bytes.fromhex("000000") + b"\x03" + (2).to_bytes(2, "little")
    )
    _put(transport, AVDTP, (1).to_bytes(2, "little") + b"abc")
    _put(transport, AVDTP, (2).to_bytes(2, "little") + b"de")
    result = await transport.receive_parcel(expected_type=0x03)
    assert result == b"abcde"
    assert (AVDTP, RCV_RDY) in client.writes
    assert (AVDTP, RCV_OK) in client.writes


async def test_transport_receive_single_frame_parcel() -> None:
    transport, client = _transport()
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x03" + b"payload")
    assert await transport.receive_parcel(expected_type=0x03) == b"payload"
    assert (AVDTP, RCV_ACK) in client.writes


async def test_transport_receive_parcel_rejects_bad_header() -> None:
    transport, _ = _transport()
    _put(transport, AVDTP, b"\x01\x02")
    with pytest.raises(pairing.PairingError):
        await transport.receive_parcel()


async def test_transport_receive_parcel_rejects_wrong_type() -> None:
    transport, _ = _transport()
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x05" + b"payload")
    with pytest.raises(pairing.PairingError):
        await transport.receive_parcel(expected_type=0x03)


async def test_official_init_negotiates_mtu() -> None:
    transport, client = _transport()
    mtu = 18
    for _ in DEVICE_INFO_QUERIES:
        _put(transport, VEND1C, b"\x00")
    _put(transport, AVDTP, TRANSPORT_OFFER + bytes([0x00, mtu]))
    _put(transport, AVDTP, TRANSPORT_PROBE + bytes([mtu] * (mtu - 2)))
    await transport.official_init()
    assert transport.parcel_chunk_size == mtu
    assert (UPNP, CMD_TRANSPORT_INIT) in client.writes


async def test_official_init_rejects_bad_offer() -> None:
    transport, _ = _transport()
    for _ in DEVICE_INFO_QUERIES:
        _put(transport, VEND1C, b"\x00")
    _put(transport, AVDTP, b"\x00\x00")
    with pytest.raises(pairing.PairingError):
        await transport.official_init()


def test_check_registration_support() -> None:
    pairing.check_registration_support(1, 0)
    with pytest.raises(pairing.RegistrationUnsupported):
        pairing.check_registration_support(2, 0)
    with pytest.raises(pairing.RegistrationUnsupported):
        pairing.check_registration_support(3, 0)
    with pytest.raises(pairing.RegistrationUnsupported):
        pairing.check_registration_support(1, 1)


def test_new_did_and_product_id() -> None:
    did = pairing._new_did()
    assert len(did) == 20
    assert pairing.product_id_from_service_data(bytes.fromhex("0000d930")) == 0x30D9
    assert pairing.product_id_from_service_data(None) is None
    assert pairing.product_id_from_service_data(b"\x00") is None


def test_save_credentials(tmp_path: Path) -> None:
    result = pairing.PairingResult(
        mac="02:00:00:00:00:03",
        product_id="0x30D9",
        did="blt.3.1abc",
        did_hex="00" * 20,
        bindkey="aa" * 16,
        token="bb" * 12,
    )
    path = tmp_path / "secrets.json"
    pairing.save_credentials(path, result)
    assert "aa" * 16 in path.read_text()
    assert oct(path.stat().st_mode & 0o777) == "0o600"


class FakeTransport:
    """Scripted replacement for _GattTransport used by pair_device tests."""

    def __init__(self, device_pub: bytes, version: bytes = bytes.fromhex("01000000")):
        self.rp = {0x00: version, 0x03: device_pub}

    async def start_official_order(self) -> None: ...
    async def official_init(self) -> None: ...
    async def finish_subscriptions(self) -> None: ...
    async def write(self, uuid, value) -> None: ...
    def parcel_command(self, parcel_type, value, **kwargs) -> bytes:
        return b""

    async def expect(self, uuid, expected, context) -> None: ...
    async def send_parcel(self, value, **kwargs) -> None: ...
    async def receive_parcel(self, expected_type=None) -> bytes:
        return self.rp[expected_type]

    async def receive(self, uuid, timeout=None) -> bytes:
        return REGISTER_OK


class FakeBleakClient:
    def __init__(self, *args, **kwargs) -> None: ...
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args) -> bool:
        return False

    async def read_gatt_char(self, uuid) -> bytes:
        return bytes.fromhex("02000000")


async def test_login_verifies_device_and_reports_success() -> None:
    from unittest.mock import patch as _patch

    from custom_components.xiaomi_s400_local.crypto import (
        derive_login_keys,
        login_hmac,
    )
    from custom_components.xiaomi_s400_local.protocol import CMD_LOGIN, LOGIN_OK

    token = bytes.fromhex("000102030405060708090a0b")
    app_random = b"\x11" * 16
    device_random = b"\x22" * 16
    keys = derive_login_keys(token, app_random, device_random)
    device_info = login_hmac(keys.device_key, device_random + app_random)

    transport, client = _transport()
    _put(transport, AVDTP, RCV_RDY)
    _put(transport, AVDTP, RCV_OK)
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x0d" + device_random)
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x0c" + device_info)
    _put(transport, AVDTP, RCV_RDY)
    _put(transport, AVDTP, RCV_OK)
    _put(transport, UPNP, LOGIN_OK)

    with _patch.object(pairing.secrets, "token_bytes", return_value=app_random):
        result = await pairing._login(transport, token)
    assert result == keys
    assert (UPNP, CMD_LOGIN) in client.writes


async def test_login_rejects_wrong_token() -> None:
    from unittest.mock import patch as _patch

    token = bytes.fromhex("000102030405060708090a0b")
    transport, _ = _transport()
    _put(transport, AVDTP, RCV_RDY)
    _put(transport, AVDTP, RCV_OK)
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x0d" + b"\x22" * 16)
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x0c" + b"\x00" * 32)

    with (
        _patch.object(pairing.secrets, "token_bytes", return_value=b"\x11" * 16),
        pytest.raises(pairing.PairingError),
    ):
        await pairing._login(transport, token)


async def test_find_s400_scans_and_matches() -> None:
    from unittest.mock import patch as _patch

    device = type("Dev", (), {"address": "02:00:00:00:00:03"})()
    with _patch(
        "custom_components.xiaomi_s400_local.pairing.BleakScanner.find_device_by_filter",
        return_value=device,
    ) as finder:
        found, _pid = await pairing.find_s400(address="02:00:00:00:00:03")
        assert found is device
        matcher = finder.call_args.args[0]
        adv = type(
            "Adv",
            (),
            {"service_data": {}, "local_name": "Xiaomi Scale S400", "name": None},
        )()
        assert matcher(device, adv) is True


async def test_find_s400_raises_when_missing() -> None:
    from unittest.mock import patch as _patch

    with (
        _patch(
            "custom_components.xiaomi_s400_local.pairing.BleakScanner.find_device_by_filter",
            return_value=None,
        ),
        pytest.raises(pairing.PairingError),
    ):
        await pairing.find_s400()


async def test_pair_device_v1_success() -> None:
    from unittest.mock import AsyncMock
    from unittest.mock import patch as _patch

    _, device_pub = generate_keypair()
    fake_transport = FakeTransport(device_pub)
    with (
        _patch(
            "custom_components.xiaomi_s400_local.pairing.BleakClient", FakeBleakClient
        ),
        _patch(
            "custom_components.xiaomi_s400_local.pairing._GattTransport",
            lambda *a, **k: fake_transport,
        ),
        _patch(
            "custom_components.xiaomi_s400_local.pairing._login",
            new=AsyncMock(return_value=object()),
        ),
    ):
        result = await pairing.pair_device(
            ble_device=type("Dev", (), {"address": "02:00:00:00:00:03"})(),
            product_id=0x30D9,
            official_init=True,
        )
    assert result.mac == "02:00:00:00:00:03"
    assert len(result.bindkey) == 32
    assert len(result.token) == 24


async def test_pair_device_v2_is_unsupported() -> None:
    from unittest.mock import AsyncMock
    from unittest.mock import patch as _patch

    _, device_pub = generate_keypair()
    fake_transport = FakeTransport(device_pub, version=bytes.fromhex("02000000"))
    with (
        _patch(
            "custom_components.xiaomi_s400_local.pairing.BleakClient", FakeBleakClient
        ),
        _patch(
            "custom_components.xiaomi_s400_local.pairing._GattTransport",
            lambda *a, **k: fake_transport,
        ),
        _patch(
            "custom_components.xiaomi_s400_local.pairing._login",
            new=AsyncMock(return_value=object()),
        ),
        pytest.raises(pairing.RegistrationUnsupported),
    ):
        await pairing.pair_device(
            ble_device=type("Dev", (), {"address": "02:00:00:00:00:03"})(),
            product_id=0x30D9,
            official_init=True,
        )


async def test_transport_receive_parcel_error_branches() -> None:
    transport, _ = _transport()
    _put(
        transport, AVDTP, bytes.fromhex("000000") + b"\x00" + (0).to_bytes(2, "little")
    )
    with pytest.raises(pairing.PairingError):
        await transport.receive_parcel()

    transport, _ = _transport()
    _put(transport, AVDTP, b"\x00\x00\x00\x01")
    with pytest.raises(pairing.PairingError):
        await transport.receive_parcel()

    transport, _ = _transport()
    _put(
        transport, AVDTP, bytes.fromhex("000000") + b"\x00" + (2).to_bytes(2, "little")
    )
    _put(transport, AVDTP, (5).to_bytes(2, "little") + b"xx")
    with pytest.raises(pairing.PairingError):
        await transport.receive_parcel()


async def test_transport_receive_timeout() -> None:
    transport, _ = _transport(timeout=0.05)
    with pytest.raises(pairing.PairingError):
        await transport.receive(UPNP)


async def test_login_failure_results() -> None:
    from unittest.mock import patch as _patch

    from custom_components.xiaomi_s400_local.crypto import (
        derive_login_keys,
        login_hmac,
    )
    from custom_components.xiaomi_s400_local.protocol import LOGIN_ERROR

    token = bytes.fromhex("000102030405060708090a0b")

    # device random with the wrong length
    transport, _ = _transport()
    _put(transport, AVDTP, RCV_RDY)
    _put(transport, AVDTP, RCV_OK)
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x0d" + b"\x22" * 8)
    with (
        _patch.object(pairing.secrets, "token_bytes", return_value=b"\x11" * 16),
        pytest.raises(pairing.PairingError),
    ):
        await pairing._login(transport, token)

    # explicit LOGIN_ERROR result
    keys = derive_login_keys(token, b"\x11" * 16, b"\x22" * 16)
    device_info = login_hmac(keys.device_key, b"\x22" * 16 + b"\x11" * 16)
    transport, _ = _transport()
    _put(transport, AVDTP, RCV_RDY)
    _put(transport, AVDTP, RCV_OK)
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x0d" + b"\x22" * 16)
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x0c" + device_info)
    _put(transport, AVDTP, RCV_RDY)
    _put(transport, AVDTP, RCV_OK)
    _put(transport, UPNP, LOGIN_ERROR)
    with (
        _patch.object(pairing.secrets, "token_bytes", return_value=b"\x11" * 16),
        pytest.raises(pairing.PairingError),
    ):
        await pairing._login(transport, token)


async def test_pair_device_by_address_and_without_official_init() -> None:
    from unittest.mock import AsyncMock
    from unittest.mock import patch as _patch

    _, device_pub = generate_keypair()
    fake_transport = FakeTransport(device_pub)
    device = type("Dev", (), {"address": "02:00:00:00:00:03"})()
    with (
        _patch(
            "custom_components.xiaomi_s400_local.pairing.find_s400",
            new=AsyncMock(return_value=(device, 0x30D9)),
        ),
        _patch(
            "custom_components.xiaomi_s400_local.pairing.BleakClient", FakeBleakClient
        ),
        _patch(
            "custom_components.xiaomi_s400_local.pairing._GattTransport",
            lambda *a, **k: fake_transport,
        ),
        _patch(
            "custom_components.xiaomi_s400_local.pairing._login",
            new=AsyncMock(return_value=object()),
        ),
    ):
        result = await pairing.pair_device(
            address="02:00:00:00:00:03", official_init=False
        )
    assert result.product_id == "0x30D9"


async def test_pair_device_rejects_bad_did() -> None:
    from unittest.mock import patch as _patch

    _, device_pub = generate_keypair()
    fake_transport = FakeTransport(device_pub)
    with (
        _patch(
            "custom_components.xiaomi_s400_local.pairing.BleakClient", FakeBleakClient
        ),
        _patch(
            "custom_components.xiaomi_s400_local.pairing._GattTransport",
            lambda *a, **k: fake_transport,
        ),
        pytest.raises(pairing.PairingError),
    ):
        await pairing.pair_device(
            ble_device=type("Dev", (), {"address": "02:00:00:00:00:03"})(),
            did=bytes(10),
        )


async def test_find_s400_matcher_branches() -> None:
    from unittest.mock import patch as _patch

    from custom_components.xiaomi_s400_local.const import MIBEACON_UUID

    device = type("Dev", (), {"address": "02:00:00:00:00:03", "name": None})()
    with _patch(
        "custom_components.xiaomi_s400_local.pairing.BleakScanner.find_device_by_filter",
        return_value=device,
    ) as finder:
        await pairing.find_s400(address="02:00:00:00:00:03")
        matcher = finder.call_args.args[0]
        adv = type(
            "Adv",
            (),
            {
                "service_data": {MIBEACON_UUID: bytes.fromhex("0000d930")},
                "local_name": None,
                "name": "Xiaomi Scale S400",
            },
        )()
        assert matcher(device, adv) is True
        other = type("Dev", (), {"address": "02:00:00:00:00:05", "name": None})()
        assert matcher(other, adv) is False

    with _patch(
        "custom_components.xiaomi_s400_local.pairing.BleakScanner.find_device_by_filter",
        return_value=device,
    ) as finder:
        await pairing.find_s400()
        matcher = finder.call_args.args[0]
        adv = type(
            "Adv",
            (),
            {"service_data": {}, "local_name": "Xiaomi Scale S400", "name": None},
        )()
        assert matcher(device, adv) is True

        adv_pid = type(
            "Adv",
            (),
            {
                "service_data": {MIBEACON_UUID: bytes.fromhex("0000d930")},
                "local_name": None,
                "name": None,
            },
        )()
        assert matcher(device, adv_pid) is True


async def test_login_unexpected_result() -> None:
    from unittest.mock import patch as _patch

    from custom_components.xiaomi_s400_local.crypto import (
        derive_login_keys,
        login_hmac,
    )

    token = bytes.fromhex("000102030405060708090a0b")
    keys = derive_login_keys(token, b"\x11" * 16, b"\x22" * 16)
    device_info = login_hmac(keys.device_key, b"\x22" * 16 + b"\x11" * 16)
    transport, _ = _transport()
    _put(transport, AVDTP, RCV_RDY)
    _put(transport, AVDTP, RCV_OK)
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x0d" + b"\x22" * 16)
    _put(transport, AVDTP, bytes.fromhex("000002") + b"\x0c" + device_info)
    _put(transport, AVDTP, RCV_RDY)
    _put(transport, AVDTP, RCV_OK)
    _put(transport, UPNP, b"\x99\x00\x00\x00")
    with (
        _patch.object(pairing.secrets, "token_bytes", return_value=b"\x11" * 16),
        pytest.raises(pairing.PairingError),
    ):
        await pairing._login(transport, token)


async def test_transport_write_failure_records_and_raises() -> None:
    class FailingClient(FakeClient):
        async def write_gatt_char(self, uuid, data, response=False):
            raise RuntimeError("nope")

    transport = pairing._GattTransport(
        FailingClient(), pairing.TraceRecorder(None), 0.5
    )
    with pytest.raises(RuntimeError):
        await transport.write(UPNP, b"\x01")


async def test_official_init_invalid_probe_and_mtu_mismatch() -> None:
    from unittest.mock import patch as _patch

    transport, _ = _transport()
    with _patch.object(pairing, "DEVICE_INFO_QUERIES", ()):
        _put(transport, AVDTP, TRANSPORT_OFFER + bytes([0x00, 18]))
        _put(transport, AVDTP, b"\x00\x00")
        with pytest.raises(pairing.PairingError):
            await transport.official_init()

    transport, _ = _transport()
    with _patch.object(pairing, "DEVICE_INFO_QUERIES", ()):
        _put(transport, AVDTP, TRANSPORT_OFFER + bytes([0x00, 18]))
        _put(transport, AVDTP, TRANSPORT_PROBE + bytes([19] * 16))
        with pytest.raises(pairing.PairingError):
            await transport.official_init()


async def test_official_init_device_info_timeout() -> None:
    from unittest.mock import patch as _patch

    transport, _ = _transport()
    mtu = 18
    with _patch.object(pairing, "DEVICE_INFO_QUERIES", (bytes.fromhex("00"),)):
        _put(transport, AVDTP, TRANSPORT_OFFER + bytes([0x00, mtu]))
        _put(transport, AVDTP, TRANSPORT_PROBE + bytes([mtu] * (mtu - 2)))
        await transport.official_init()
    assert transport.parcel_chunk_size == mtu


def test_pairing_result_is_frozen() -> None:
    result = pairing.PairingResult(
        mac="02:00:00:00:00:03",
        product_id=None,
        did="blt.3.1abc",
        did_hex="00" * 20,
        bindkey="aa" * 16,
        token="bb" * 12,
    )
    with pytest.raises(FrozenInstanceError):
        result.mac = "x"  # type: ignore[misc]
