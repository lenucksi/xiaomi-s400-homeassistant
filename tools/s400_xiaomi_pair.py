#!/usr/bin/env python3
"""Provision a factory-new Xiaomi S400 using one Xiaomi signing request.

ECDH, token and bindkey generation happen locally. Xiaomi receives the same
logical values as Mi Home and returns the root-signed auth-v2 credential. The
resulting long-lived secrets are verified against the scale and saved locally.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import re
import sys
import tempfile
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from types import ModuleType

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from xiaomi_cloud import (
    REGIONS,
    XiaomiCaptchaRequired,
    XiaomiCloudClient,
    XiaomiVerificationRequired,
)


def load_core():
    """Load reusable integration modules without importing Home Assistant."""
    root = Path(__file__).resolve().parents[1]
    package_path = root / "custom_components" / "xiaomi_s400_local"
    package = ModuleType("s400_xiaomi_pair_core")
    package.__path__ = [str(package_path)]
    sys.modules[package.__name__] = package
    return (
        import_module(f"{package.__name__}.pairing"),
        import_module(f"{package.__name__}.protocol"),
        import_module(f"{package.__name__}.crypto"),
        import_module(f"{package.__name__}.auth_v2"),
    )


def _did_bytes(did: str) -> bytes:
    """Match Mi Home's left-padded twenty-byte copy of the server DID."""
    raw = did.encode("utf-8")
    if not raw or len(raw) > 20:
        raise ValueError("Xiaomi BLE DID must contain between 1 and 20 bytes")
    return raw.rjust(20, b"\x00")


def _did_text(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    return raw.lstrip(b"\x00").decode("utf-8")


async def _send_parcel(
    transport,
    protocol,
    parcel_type,
    value,
    context,
    *,
    chunk_size,
    inter_frame_delay,
):
    chunks = [
        value[offset : offset + chunk_size]
        for offset in range(0, len(value), chunk_size)
    ]
    await transport.write(
        protocol.AVDTP,
        transport.parcel_command(parcel_type, value, chunk_size=chunk_size),
    )
    await transport.expect(protocol.AVDTP, protocol.RCV_RDY, f"{context} readiness")
    await transport.send_parcel(
        value,
        chunk_size=chunk_size,
        inter_frame_delay=inter_frame_delay,
    )
    for _ in range(8):
        acknowledgement = await transport.receive(protocol.AVDTP)
        if acknowledgement == protocol.RCV_OK:
            return
        if (
            acknowledgement.startswith(protocol.RCV_LOST_PREFIX)
            and len(acknowledgement) >= 6
            and (len(acknowledgement) - 4) % 2 == 0
        ):
            missing_frames = [
                int.from_bytes(acknowledgement[offset : offset + 2], "little")
                for offset in range(4, len(acknowledgement), 2)
            ]
            if any(not 1 <= missing <= len(chunks) for missing in missing_frames):
                raise RuntimeError(
                    f"{context}: invalid missing frames {missing_frames}"
                )
            for missing in missing_frames:
                transport.trace.record(
                    "retransmit", context=context, frame_number=missing
                )
                await transport.write(
                    protocol.AVDTP,
                    missing.to_bytes(2, "little") + chunks[missing - 1],
                )
                await asyncio.sleep(inter_frame_delay)
            continue
        raise RuntimeError(
            f"{context}: unexpected acknowledgement {acknowledgement.hex()}"
        )
    raise RuntimeError(f"{context}: retransmit limit exceeded")


def _verification_prompt(url: str) -> None:
    print("Xiaomi requires account verification. Open this URL in a browser:")
    print(url)
    input("Complete verification, then press Enter to retry login: ")


def _captcha_prompt(image: bytes) -> str:
    fd, name = tempfile.mkstemp(prefix="xiaomi-captcha-", suffix=".jpg")
    path = Path(name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(image)
        print(f"Xiaomi requires a captcha saved temporarily at: {path}")
        if os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606
        return input("Captcha text: ").strip()
    finally:
        path.unlink(missing_ok=True)


def _write_error_status(path: Path, category: str, exit_code: int) -> None:
    """Persist only a non-sensitive failure category for WSL diagnostics."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "category": category,
                    "exit_code": exit_code,
                    "occurred_at": datetime.now(UTC).isoformat(),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            path.chmod(0o600)
    except OSError:
        pass


async def run(args: argparse.Namespace, password: str) -> int:
    pairing, protocol, crypto, auth_v2 = load_core()
    cloud = XiaomiCloudClient(
        args.username,
        password,
        args.region,
        verification_callback=_verification_prompt,
        captcha_callback=_captcha_prompt,
        timeout=args.cloud_timeout,
    )
    print(f"Logging in to Xiaomi region {args.region} for one-time signing...")
    if args.browser_cdp:
        await asyncio.to_thread(cloud.login_via_browser, args.browser_cdp)
    else:
        await asyncio.to_thread(cloud.login)
    print("Xiaomi account session established. Searching for S400...")

    device, product_id = await pairing.find_s400(address=args.address)
    with pairing.TraceRecorder(args.trace) as trace:
        trace.record(
            "xiaomi_v2_pair_start",
            address=device.address,
            product_id=(f"0x{product_id:04X}" if product_id is not None else None),
            model=args.model,
            region=args.region,
        )
        async with pairing.BleakClient(device, timeout=20.0) as client:
            trace.record("connected", address=device.address)
            transport = pairing._GattTransport(client, trace, args.protocol_timeout)
            await transport.start_official_order()
            await transport.official_init()
            await transport.finish_subscriptions()

            await transport.write(protocol.UPNP, protocol.CMD_GET_INFO)
            info = protocol.parse_registration_info(
                await transport.receive_parcel(expected_type=0x00)
            )
            trace.record(
                "registration_info",
                auth_version=info.version,
                io_capability=info.io_capability,
                has_did=info.did is not None,
            )
            if info.version != 2 or info.io_capability != 0:
                raise pairing.RegistrationUnsupported(
                    "cloud-assisted provisioner requires auth v2/io 0, got "
                    f"v{info.version}/io {info.io_capability}"
                )

            private_key, public_xy = crypto.generate_keypair()
            await transport.write(protocol.UPNP, protocol.CMD_SET_KEY)
            chunk_size = transport.parcel_chunk_size
            if args.parcel_chunk_size is not None:
                chunk_size = min(args.parcel_chunk_size, chunk_size)
            trace.record(
                "parcel_transport_selected",
                chunk_size=chunk_size,
                inter_frame_delay=args.inter_frame_delay,
            )
            await _send_parcel(
                transport,
                protocol,
                0x03,
                public_xy,
                "public key",
                chunk_size=chunk_size,
                inter_frame_delay=args.inter_frame_delay,
            )
            device_public_xy = await transport.receive_parcel(expected_type=0x03)
            setup = crypto.derive_setup_secrets(private_key, device_public_xy)
            trace.record("local_setup_secrets_derived")

            existing_did = _did_text(info.did)
            did = await asyncio.to_thread(
                cloud.apply_did,
                mac=device.address.upper(),
                model=args.model,
                token_hex=setup.token.hex(),
                existing_did=existing_did,
            )
            trace.record("xiaomi_did_allocated", did_length=len(did.encode()))
            bind = await asyncio.to_thread(
                cloud.bind_standard,
                did=did,
                token_hex=setup.token.hex(),
                bindkey_hex=setup.bindkey.hex(),
                smac=device.address.upper(),
            )
            credential = auth_v2.RegistrationCredentialV2(
                did=_did_bytes(did),
                signature=bind.signature,
                utc=bind.utc.to_bytes(4, "little"),
                certificate_der=bind.certificate_der,
            )
            certificate = x509.load_der_x509_certificate(bind.certificate_der)
            certificate_fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
            credential.verify_registration_signature(setup.bindkey)
            trace.record(
                "registration_signature_verified",
                certificate_sha256=certificate_fingerprint,
            )
            credential.verify_certificate_signature()
            trace.record(
                "sdk_root_verified",
                certificate_sha256=certificate_fingerprint,
            )
            encrypted = credential.encrypt(setup.did_key)
            trace.record(
                "xiaomi_credential_verified",
                encrypted_length=len(encrypted),
                certificate_length=len(bind.certificate_der),
            )

            await transport.write(protocol.UPNP, protocol.CMD_AUTH)
            await _send_parcel(
                transport,
                protocol,
                0x00,
                encrypted,
                "registration credential",
                chunk_size=chunk_size,
                inter_frame_delay=args.inter_frame_delay,
            )
            await _send_parcel(
                transport,
                protocol,
                0x07,
                bind.certificate_der,
                "server certificate",
                chunk_size=chunk_size,
                inter_frame_delay=args.inter_frame_delay,
            )
            result = await transport.receive(protocol.UPNP)
            trace.record("registration_result", value=result.hex())
            if result == protocol.REGISTER_ERROR:
                raise pairing.PairingError(
                    "scale rejected Xiaomi's registration credential"
                )
            if result != protocol.REGISTER_OK:
                raise pairing.PairingError(
                    f"unexpected registration result: {result.hex()}"
                )
            await pairing._login(transport, setup.token)
            trace.record("login_verified")

    credentials = pairing.PairingResult(
        mac=device.address.upper(),
        product_id=(f"0x{product_id:04X}" if product_id is not None else None),
        did=did,
        did_hex=credential.did.hex(),
        bindkey=setup.bindkey.hex(),
        token=setup.token.hex(),
        auth_protocol="Mi Home BLE standard-auth v2 (Xiaomi-signed once)",
    )
    pairing.save_credentials(args.output, credentials)
    print("S400 registration and local token login succeeded.")
    print(f"Credentials saved with owner-only permissions: {args.output}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--username", help="Xiaomi account ID/email; prompts if omitted"
    )
    parser.add_argument(
        "--region",
        choices=sorted(REGIONS),
        default="de",
        help="Mi Home account region (default: de)",
    )
    parser.add_argument(
        "--model", default="yunmai.scales.ms104", help="Mi Home model identifier"
    )
    parser.add_argument(
        "--trace", type=Path, default=Path("captures/s400-xiaomi-pair.jsonl")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("private/s400-secrets.json")
    )
    parser.add_argument(
        "--error-status",
        type=Path,
        default=Path("private/s400-last-error.json"),
        help="non-sensitive machine-readable failure category",
    )
    parser.add_argument("--protocol-timeout", type=float, default=12.0)
    parser.add_argument("--cloud-timeout", type=float, default=20.0)
    parser.add_argument(
        "--parcel-chunk-size",
        type=int,
        help="override the negotiated parcel data MTU (diagnostics only)",
    )
    parser.add_argument(
        "--inter-frame-delay",
        type=float,
        default=0.12,
        help="seconds between parcel frames (default: 0.12)",
    )
    parser.add_argument(
        "--browser-cdp",
        help="use an already authenticated Chromium/Edge CDP session",
    )
    args = parser.parse_args()
    args.address = os.environ.get("S400_BLE_ADDRESS", "").strip().upper()
    if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", args.address):
        parser.error("set S400_BLE_ADDRESS to a six-byte colon-separated BLE address")
    return args


def main() -> int:
    args = parse_args()
    args.error_status.unlink(missing_ok=True)
    if not args.username:
        args.username = input("Xiaomi account ID/email: ").strip()
    if not args.username:
        print("Xiaomi account ID/email cannot be empty", file=sys.stderr)
        _write_error_status(args.error_status, "empty_username", 2)
        return 2
    password = getpass.getpass("Xiaomi account password (not stored): ")
    try:
        return asyncio.run(run(args, password))
    except XiaomiVerificationRequired as error:
        print("Account verification is still required:", file=sys.stderr)
        print(error.url, file=sys.stderr)
        _write_error_status(args.error_status, "account_verification_required", 2)
        return 2
    except XiaomiCaptchaRequired as error:
        print("Xiaomi account captcha could not be completed.", file=sys.stderr)
        print(error.url, file=sys.stderr)
        _write_error_status(args.error_status, "account_captcha_required", 2)
        return 2
    except KeyboardInterrupt:
        _write_error_status(args.error_status, "interrupted", 130)
        return 130
    except Exception as error:
        print(f"s400_xiaomi_pair: {error}", file=sys.stderr)
        _write_error_status(args.error_status, type(error).__name__, 1)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
