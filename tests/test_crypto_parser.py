from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path
from types import ModuleType

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_PATH = ROOT / "custom_components" / "xiaomi_s400_local"
PACKAGE = ModuleType("s400_test_core")
PACKAGE.__path__ = [str(PACKAGE_PATH)]
sys.modules[PACKAGE.__name__] = PACKAGE

crypto = import_module("s400_test_core.crypto")
parser = import_module("s400_test_core.parser")


def test_login_key_derivation_vector() -> None:
    keys = crypto.derive_login_keys(
        bytes.fromhex("000102030405060708090a0b"),
        bytes.fromhex("101112131415161718191a1b1c1d1e1f"),
        bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
    )
    assert keys.device_key.hex() == "c155874e9070ceea1442268a104c32a2"
    assert keys.app_key.hex() == "e3d45937fa34418380b6747d1cac84e6"
    assert keys.device_iv.hex() == "8d9e0842"
    assert keys.app_iv.hex() == "c57b6232"


def test_setup_ecdh_derives_identical_secrets_and_encrypts_did() -> None:
    app_private, app_public = crypto.generate_keypair()
    device_private, device_public = crypto.generate_keypair()

    app_secrets = crypto.derive_setup_secrets(app_private, device_public)
    device_secrets = crypto.derive_setup_secrets(device_private, app_public)
    assert app_secrets == device_secrets
    assert len(app_secrets.token) == 12
    assert len(app_secrets.bindkey) == 16

    did = b"\x00blt.3.129vABC123ATC"
    encrypted = crypto.encrypt_did(did, app_secrets.did_key)
    assert (
        AESCCM(app_secrets.did_key, tag_length=4).decrypt(
            bytes.fromhex("101112131415161718191a1b"), encrypted, b"devID"
        )
        == did
    )


def test_parse_encrypted_s400_object() -> None:
    address = "02:00:00:00:00:04"
    bindkey = bytes.fromhex("00112233445566778899aabbccddeeff")
    frame_control = 0x5858  # v5, registered, object, MAC and encryption
    prefix = frame_control.to_bytes(2, "little") + bytes.fromhex("d9302a")
    embedded_mac = bytes.fromhex("040000000002")
    packed = 736 | ((101 - 50) << 11) | (5106 << 18)
    payload = (
        bytes.fromhex("166e09")
        + bytes([3])
        + packed.to_bytes(4, "little")
        + (123).to_bytes(4, "little")
    )
    ext_counter = bytes.fromhex("010203")
    nonce = embedded_mac + bytes.fromhex("d9302a") + ext_counter
    encrypted = AESCCM(bindkey, tag_length=4).encrypt(nonce, payload, b"\x11")
    service_data = prefix + embedded_mac + encrypted[:-4] + ext_counter + encrypted[-4:]

    value = parser.parse_mibeacon(address, service_data, bindkey)
    assert value.product_id == 0x30D9
    assert value.profile_id == 3
    assert value.timestamp == 123
    assert value.weight == 73.6
    assert value.heart_rate == 101
    assert value.impedance_low == 510.6
    assert value.impedance_high is None


def test_parse_rejects_wrong_bindkey() -> None:
    address = "02:00:00:00:00:04"
    prefix = (0x5858).to_bytes(2, "little") + bytes.fromhex("d9302a")
    embedded_mac = bytes.fromhex("040000000002")
    payload = bytes.fromhex("166e09") + bytes(9)
    counter = bytes.fromhex("010203")
    good_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    nonce = embedded_mac + bytes.fromhex("d9302a") + counter
    encrypted = AESCCM(good_key, tag_length=4).encrypt(nonce, payload, b"\x11")
    frame = prefix + embedded_mac + encrypted[:-4] + counter + encrypted[-4:]
    try:
        parser.parse_mibeacon(address, frame, bytes(16))
    except parser.AdvertisementError as error:
        assert "authentication tag" in str(error)
    else:
        raise AssertionError("wrong key was accepted")
