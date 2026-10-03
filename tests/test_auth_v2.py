from __future__ import annotations

import asyncio
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from importlib import import_module, util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ModuleType("s400_v2_test_core")
PACKAGE.__path__ = [str(ROOT / "custom_components" / "xiaomi_s400_local")]
sys.modules[PACKAGE.__name__] = PACKAGE
auth = import_module(f"{PACKAGE.__name__}.auth_v2")
protocol = import_module(f"{PACKAGE.__name__}.protocol")
pairing = import_module(f"{PACKAGE.__name__}.pairing")
spec = util.spec_from_file_location(
    "trace_analyzer", ROOT / "tools/s400_analyze_trace.py"
)
assert spec and spec.loader
analyzer = util.module_from_spec(spec)
spec.loader.exec_module(analyzer)


def test_get_info_is_protocol_and_capabilities_not_status() -> None:
    info = protocol.parse_registration_info(bytes.fromhex("02000000"))
    assert (info.version, info.io_capability, info.did) == (2, 0, None)
    info = protocol.parse_registration_info(b"\x01\x00\x10\x00" + b"D" * 20)
    assert (info.version, info.io_capability, info.did) == (1, 16, b"D" * 20)
    with pytest.raises(ValueError):
        protocol.parse_registration_info(bytes(23))


def test_registration_refuses_unimplemented_variants() -> None:
    pairing.check_registration_support(1, 0)
    for version, capabilities in ((2, 0), (3, 0), (1, 16)):
        with pytest.raises(pairing.PairingError):
            pairing.check_registration_support(version, capabilities)


def test_v2_guard_stops_before_key_exchange(monkeypatch) -> None:
    writes = []

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def read_gatt_char(self, _uuid):
            return b"lab"

        async def start_notify(self, *_args):
            pass

        async def write_gatt_char(self, uuid, data, **_kwargs):
            writes.append((uuid, data))

    async def info(_self, expected_type=None):
        assert expected_type == 0
        return bytes.fromhex("02000000")

    def unexpected_key_generation():
        pytest.fail("version 2 must be detected before generating registration keys")

    monkeypatch.setattr(pairing, "BleakClient", Client)
    monkeypatch.setattr(pairing._GattTransport, "receive_parcel", info)
    monkeypatch.setattr(pairing, "generate_keypair", unexpected_key_generation)
    with pytest.raises(pairing.RegistrationUnsupported, match="auth version 2"):
        asyncio.run(
            pairing.pair_device(
                ble_device=SimpleNamespace(address="02:00:00:00:00:01"),
                official_init=False,
            )
        )
    assert writes == [(protocol.UPNP, protocol.CMD_GET_INFO)]


def test_wrong_parcel_type_is_not_acknowledged() -> None:
    class Client:
        async def write_gatt_char(self, *_args, **_kwargs):
            pytest.fail("unexpected parcel must not be acknowledged")

    async def scenario():
        transport = pairing._GattTransport(Client(), pairing.TraceRecorder(), 0.1)
        transport.queues[protocol.AVDTP].put_nowait(bytes.fromhex("0000020302000000"))
        with pytest.raises(pairing.PairingError, match="parcel type"):
            await transport.receive_parcel(expected_type=0)

    asyncio.run(scenario())


def test_transport_negotiates_242_byte_data_mtu() -> None:
    writes = []

    class Client:
        async def write_gatt_char(self, uuid, data, **_kwargs):
            writes.append((uuid, bytes(data)))

    async def scenario():
        transport = pairing._GattTransport(Client(), pairing.TraceRecorder(), 0.1)
        device_info_replies = iter((b"a", b"b", b"c", b"d"))
        avdtp_replies = iter(
            (
                bytes.fromhex("0000040006f2"),
                bytes.fromhex("00000401") + bytes([0xF2]) * 240,
            )
        )

        async def receive(uuid, timeout=None):
            del timeout
            if uuid == protocol.VEND1C:
                return next(device_info_replies)
            return next(avdtp_replies)

        transport.receive = receive
        await transport.official_init()
        return transport

    transport = asyncio.run(scenario())
    assert transport.parcel_chunk_size == 242
    assert writes[-2:] == [
        (protocol.AVDTP, bytes.fromhex("0000050006f2")),
        (protocol.AVDTP, bytes.fromhex("00000501") + bytes([0xF2]) * 240),
    ]


def make_credential():
    # Synthetic lab root and server; no Xiaomi private keys or real credentials.
    root = ec.generate_private_key(ec.SECP256R1())
    server = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Lab")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(server.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(root, hashes.SHA256())
    )
    did, bindkey, utc = b"D" * 20, bytes(range(16)), bytes.fromhex("01020304")
    signature = server.sign(did + bindkey + utc, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    credential = auth.RegistrationCredentialV2(
        did,
        r.to_bytes(32, "big") + s.to_bytes(32, "big"),
        utc,
        certificate.public_bytes(serialization.Encoding.DER),
    )
    root_xy = root.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )[1:]
    return credential, bindkey, root_xy


def test_v2_signature_binds_did_bindkey_and_utc() -> None:
    credential, bindkey, root = make_credential()
    credential.verify_signatures(bindkey, root_public_xy=root)
    for changed in (
        replace(credential, did=b"X" * 20),
        replace(credential, utc=bytes(4)),
        replace(credential, signature=bytes(64)),
    ):
        with pytest.raises(InvalidSignature):
            changed.verify_signatures(bindkey, root_public_xy=root)
    with pytest.raises(InvalidSignature):
        credential.verify_signatures(bytes(16), root_public_xy=root)
    with pytest.raises(InvalidSignature):
        credential.verify_signatures(bindkey)  # Own CA fails the SDK trust anchor.
    credential.verify_registration_signature(bindkey)
    with pytest.raises(InvalidSignature):
        credential.verify_certificate_signature()


def test_v2_payload_is_92_bytes_and_authenticated() -> None:
    credential, _, _ = make_credential()
    key = bytes(range(16))
    encrypted = credential.encrypt(key)
    assert len(encrypted) == 92
    plain = AESCCM(key, tag_length=4).decrypt(
        protocol.DID_NONCE, encrypted, protocol.DID_ASSOCIATED_DATA
    )
    assert plain[:20] == credential.did
    assert plain[20:84] == credential.signature
    assert plain[84:88] == credential.utc


def trace_rows(*, inline: bool, auth_first: bool = False, version: int = 2):
    def row(event, uuid, value):
        return {"event": event, "uuid": uuid, "value": value.hex()}

    yield row("write", protocol.UPNP, protocol.CMD_GET_INFO)
    payload = version.to_bytes(2, "little") + bytes(2)
    if inline:
        yield row("notify", protocol.AVDTP, b"\0\0\2\0" + payload)
    else:
        yield row("notify", protocol.AVDTP, bytes.fromhex("000000000100"))
        yield row("notify", protocol.AVDTP, b"\1\0" + payload)
    yield row("write", protocol.UPNP, protocol.CMD_SET_KEY)
    if inline:
        yield row("notify", protocol.AVDTP, b"\0\0\2\3" + b"P" * 64)
    else:
        yield row("notify", protocol.AVDTP, bytes.fromhex("000000030200"))
        yield row("notify", protocol.AVDTP, b"\1\0" + b"P" * 32)
        yield row("notify", protocol.AVDTP, b"\2\0" + b"P" * 32)
    if auth_first:
        yield row("write", protocol.UPNP, protocol.CMD_AUTH)
    yield row("write", protocol.AVDTP, bytes.fromhex("000000000100"))


@pytest.mark.parametrize("inline", [False, True])
def test_offline_trace_detects_ordering_conflict(inline) -> None:
    report = analyzer.summarize(trace_rows(inline=inline))
    assert report["auth_version"] == 2
    assert report["device_public_key_bytes"] == 64
    assert report["finding"] == "legacy_order_conflicts_with_public_auth_v2_sdk"
    assert not report["registration_confirmed"]
    for kwargs in ({"auth_first": True}, {"version": 1}):
        report = analyzer.summarize(trace_rows(inline=inline, **kwargs))
        assert report["finding"] == "no_v2_ordering_conflict_demonstrated"


def test_incomplete_trace_does_not_establish_public_key_exchange() -> None:
    rows = list(trace_rows(inline=False))
    del rows[-2]  # Drop the second device key fragment.
    report = analyzer.summarize(rows)
    assert report["incomplete_incoming_parcel"]
    assert report["device_public_key_bytes"] is None
    assert report["finding"] == "no_v2_ordering_conflict_demonstrated"


def test_trace_reports_successful_registration_result() -> None:
    rows = list(trace_rows(inline=True, auth_first=True))
    rows.append({"event": "registration_result", "value": "11000000"})
    rows.append({"event": "login_verified"})
    report = analyzer.summarize(rows)
    assert report["registration_confirmed"]
    assert report["login_verified"]
