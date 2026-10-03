from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from s400_xiaomi_pair import _did_bytes, _did_text  # noqa: E402
from xiaomi_cloud import (  # noqa: E402
    XiaomiAuthenticationError,
    XiaomiCloudClient,
    XiaomiCloudError,
    _decode_urlsafe,
    _encrypted_fields,
    _rc4,
)


class _LoginFixtureClient(XiaomiCloudClient):
    def __init__(self) -> None:
        super().__init__("account@example.test", "plain-password", "de")
        self.requests: list[tuple[str, str, dict[str, str] | None]] = []

    def _request(
        self,
        url: str,
        *,
        method: str = "GET",
        fields: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        self.requests.append((url, method, fields))
        if "serviceLoginAuth2" in url:
            return b'&&&START&&&{"location":"https://sts.api.io.mi.com/sts?d=1","ssecurity":"c2VjcmV0","userId":"42"}'
        if "serviceLogin" in url:
            return b'&&&START&&&{"sid":"xiaomiio","qs":"query","callback":"https://sts.api.io.mi.com/sts","_sign":"signed"}'
        return b"ok"

    def _cookie(self, name: str) -> str | None:
        return "service-token" if name == "serviceToken" else None


class _RejectedCaptchaClient(_LoginFixtureClient):
    def __init__(self) -> None:
        super().__init__()
        self.auth_attempts = 0

    def _request(
        self,
        url: str,
        *,
        method: str = "GET",
        fields: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        self.requests.append((url, method, fields))
        if "serviceLoginAuth2" in url:
            self.auth_attempts += 1
            code = 0 if self.auth_attempts == 1 else 87001
            return (
                f'&&&START&&&{{"code":{code},"captchaUrl":"/pass/captcha.jpg"}}'
            ).encode()
        if "captcha.jpg" in url:
            return b"image"
        return b'&&&START&&&{"sid":"xiaomiio","_sign":"signed"}'


def test_rc4_matches_published_vector() -> None:
    assert _rc4(b"Key", b"Plaintext", drop=0).hex() == "bbf316e8d940af0ad3"


def test_api_envelope_keeps_required_unencrypted_fields() -> None:
    ssecurity = base64.b64encode(bytes(range(32))).decode()
    nonce = base64.b64encode(bytes(range(12))).decode()
    fields = _encrypted_fields(
        "POST",
        "https://de.api.io.mi.com/app/device/bltapplydid",
        {"data": '{"example":true}'},
        ssecurity,
        nonce,
    )

    assert set(fields) == {
        "data",
        "rc4_hash__",
        "signature",
        "ssecurity",
        "_nonce",
    }
    assert fields["data"] != '{"example":true}'
    assert fields["ssecurity"] == ssecurity
    assert fields["_nonce"] == nonce


def test_did_is_zero_padded_to_firmware_width() -> None:
    assert _did_bytes("blt.3.example") == bytes(7) + b"blt.3.example"
    assert _did_text(bytes(7) + b"blt.3.example") == "blt.3.example"
    assert len(_did_bytes("12345678901234567890")) == 20
    with pytest.raises(ValueError):
        _did_bytes("x" * 21)


def test_urlsafe_cloud_fields_accept_missing_padding() -> None:
    encoded = base64.urlsafe_b64encode(b"credential").decode().rstrip("=")
    assert _decode_urlsafe(encoded, "fixture") == b"credential"
    with pytest.raises(XiaomiCloudError):
        _decode_urlsafe("\N{EURO SIGN}", "fixture")


def test_login_keeps_plaintext_password_out_of_requests() -> None:
    client = _LoginFixtureClient()
    client.login()

    auth_fields = client.requests[1][2]
    assert auth_fields is not None
    assert auth_fields["hash"] == "9A0EF3ECF101A8B0856F98EB6B2E2C24"
    assert "plain-password" not in json.dumps(client.requests)


def test_login_stops_after_one_rejected_captcha() -> None:
    prompts = 0

    def solve(_image: bytes) -> str:
        nonlocal prompts
        prompts += 1
        return "entered-once"

    client = _RejectedCaptchaClient()
    client._captcha_callback = solve

    with pytest.raises(XiaomiAuthenticationError, match="rejected"):
        client.login()

    assert prompts == 1
    assert client.auth_attempts == 2


def test_bind_response_decodes_production_field_shapes() -> None:
    client = XiaomiCloudClient("user", "password", "de")
    certificate = b"synthetic DER fixture"
    signature = bytes(range(64))
    client._api = lambda _path, _payload: {  # type: ignore[method-assign]
        "code": 0,
        "result": {
            "success": True,
            "cloud_cert": base64.urlsafe_b64encode(certificate).decode().rstrip("="),
            "cloud_sign": base64.urlsafe_b64encode(signature).decode().rstrip("="),
            "utc": 1_700_000_000,
        },
    }

    result = client.bind_standard(
        did="blt.3.fixture",
        token_hex="00" * 12,
        bindkey_hex="11" * 16,
        smac="02:00:00:00:00:02",
    )

    assert result.certificate_der == certificate
    assert result.signature == signature
    assert result.utc == 1_700_000_000
