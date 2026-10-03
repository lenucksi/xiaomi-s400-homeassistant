"""Edge-case tests for parser, crypto and CMTP helpers."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from custom_components.xiaomi_s400_local import active, crypto, parser

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
MAC = bytes.fromhex("020000000003")
EMB = MAC[::-1]


def frame(
    payload: bytes,
    *,
    fc: int = 0x5858,
    pid: int = 0x30D9,
    counter: int = 0x2A,
    embedded: bytes = EMB,
    bindkey: bytes = KEY,
) -> bytes:
    prefix = fc.to_bytes(2, "little") + pid.to_bytes(2, "little") + bytes([counter])
    ext = bytes.fromhex("010203")
    nonce = embedded + pid.to_bytes(2, "little") + bytes([counter]) + ext
    enc = AESCCM(bindkey, tag_length=4).encrypt(nonce, payload, b"\x11")
    return prefix + embedded + enc[:-4] + ext + enc[-4:]


def obj(object_id: int, value: bytes) -> bytes:
    return object_id.to_bytes(2, "little") + bytes([len(value)]) + value


def measurement(mass: int = 0, hr: int = 0, imp: int = 0, profile: int = 1) -> bytes:
    packed = mass | (hr << 11) | (imp << 18)
    return bytes([profile]) + packed.to_bytes(4, "little") + (0).to_bytes(4, "little")


def test_parser_rejects_bad_address() -> None:
    # A valid frame reaching _mac_bytes with a malformed address
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("zz", frame(b""), KEY)
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("04:AE:47:5C:FC", frame(b""), KEY)


def test_parser_rejects_bad_bindkey_and_short_data() -> None:
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("02:00:00:00:00:03", b"\x00" * 20, bytes(8))
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("02:00:00:00:00:03", b"\x00\x00", KEY)


def test_parser_rejects_unknown_product_and_version() -> None:
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("02:00:00:00:00:03", frame(b"", pid=0x0000), KEY)
    # version 3 in the frame control high nibble
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("02:00:00:00:00:03", frame(b"", fc=0x3858), KEY)


def test_parser_rejects_mac_mismatch_and_truncation() -> None:
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("02:00:00:00:00:03", frame(b"", embedded=bytes(6)), KEY)
    # MAC flag set (fc 0x5010 little-endian) but no room for the MAC field
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("02:00:00:00:00:03", bytes.fromhex("1050d9302a"), KEY)


def test_parser_capability_and_no_object() -> None:
    # Capability flag set (fc 0x5020) but no capability byte present
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("02:00:00:00:00:03", bytes.fromhex("2050d9302a"), KEY)

    # Capability byte with the 0x20 sub-flag, no object -> returns the base frame
    data = bytes.fromhex("2050d9302a") + bytes([0x20, 0x00])
    result = parser.parse_mibeacon("02:00:00:00:00:03", data, KEY)
    assert result.weight is None

    # No object flag at all -> returns the base frame
    base = parser.parse_mibeacon(
        "02:00:00:00:00:03", bytes.fromhex("0050d9302a00"), KEY
    )
    assert base.product_id == 0x30D9


def test_parser_rejects_truncated_object_and_short_encryption() -> None:
    # Declared object length (9) exceeds the available payload bytes
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon(
            "02:00:00:00:00:03", frame(b"\x16\x6e\x09" + bytes(5)), KEY
        )

    # Encrypted payload shorter than nonce + tag
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon(
            "02:00:00:00:00:03", bytes.fromhex("5858d9302a") + EMB + b"\x00\x00", KEY
        )


def test_parser_rejects_bad_object_lengths() -> None:
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("02:00:00:00:00:03", frame(obj(0x6E16, bytes(8))), KEY)
    with pytest.raises(parser.AdvertisementError):
        parser.parse_mibeacon("02:00:00:00:00:03", frame(obj(0x6E16, bytes(12))), KEY)


def test_parser_ignores_unknown_objects() -> None:
    result = parser.parse_mibeacon(
        "02:00:00:00:00:03", frame(obj(0x1234, b"\x01\x02")), KEY
    )
    assert result.weight is None


def test_parser_unencrypted_payload() -> None:
    # frame control without the encryption bit: payload used verbatim
    fc = 0x5040  # version 5, object present, not encrypted, no mac
    data = (
        fc.to_bytes(2, "little")
        + bytes.fromhex("d9302a")
        + obj(0x6E16, measurement(mass=1001, hr=31, imp=4620))
    )
    result = parser.parse_mibeacon("02:00:00:00:00:03", data, KEY)
    assert result.weight == 100.1


def test_crypto_length_validation() -> None:
    _, pub = crypto.generate_keypair()
    private, _ = crypto.generate_keypair()
    with pytest.raises(ValueError):
        crypto.derive_setup_secrets(private, pub[:32])
    with pytest.raises(ValueError):
        crypto.encrypt_did(bytes(10), bytes(16))
    with pytest.raises(ValueError):
        crypto.encrypt_did(bytes(20), bytes(8))
    with pytest.raises(ValueError):
        crypto.derive_login_keys(b"short", bytes(16), bytes(16))
    with pytest.raises(ValueError):
        crypto.derive_login_keys(bytes(12), bytes(8), bytes(16))
    with pytest.raises(ValueError):
        crypto.decrypt_cmtp(
            crypto.SessionKeys(bytes(16), bytes(16), bytes(4), bytes(4)), b"\x00"
        )


def test_cmtp_frames_validation() -> None:
    frames = active.CmtpFrames()
    with pytest.raises(ValueError):
        frames.start(b"\x01\x02")
    with pytest.raises(ValueError):
        frames.start(bytes.fromhex("000000") + b"\x00" + (0).to_bytes(2, "little"))
    with pytest.raises(ValueError):
        frames.add(b"\x01\x00")  # no header yet
    frames.start(bytes.fromhex("000000") + b"\x00" + (2).to_bytes(2, "little"))
    with pytest.raises(ValueError):
        frames.add(b"\x02\x00x")  # wrong frame number


def test_parse_cmtp_plaintext_edges() -> None:
    assert active.parse_cmtp_plaintext(b"no marker here") is None
    assert active.parse_cmtp_plaintext(b"\xa0notanint,1") is None
    assert active.parse_cmtp_plaintext(b"\xa0only,1") is None
    assert active.parse_cmtp_plaintext(b"\xa01,2,3") is None  # <8 fields
    assert active.parse_cmtp_plaintext(b"\xa0\xff\xfe") is None
    # UnicodeDecodeError path
    assert active.parse_cmtp_plaintext(b"\xa0\xff\xfe\xfd,1") is None


def test_decode_cmtp_rejects_short_message() -> None:
    keys = crypto.SessionKeys(bytes(16), bytes(16), bytes(4), bytes(4))
    with pytest.raises(ValueError):
        active.decode_cmtp(keys, b"\x00")
