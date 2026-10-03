#!/usr/bin/env python3
"""Probe S400 auth v2 with a structurally valid, locally signed credential.

This is an active interoperability experiment for a factory-new scale. It runs
the observed ECDH exchange and sends a lab CA/server certificate chain. Xiaomi's
private keys and services are neither used nor contacted. A normal result is a
registration rejection; acceptance demonstrates that the device does not pin
the expected root on this path and the derived local credentials are saved.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import secrets
import sys
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from types import ModuleType

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def load_core():
    """Load reusable modules without importing Home Assistant setup."""
    root = Path(__file__).resolve().parents[1]
    package_path = root / "custom_components" / "xiaomi_s400_local"
    package = ModuleType("s400_v2_probe_core")
    package.__path__ = [str(package_path)]
    sys.modules[package.__name__] = package
    return (
        import_module(f"{package.__name__}.pairing"),
        import_module(f"{package.__name__}.protocol"),
        import_module(f"{package.__name__}.crypto"),
        import_module(f"{package.__name__}.auth_v2"),
    )


def make_lab_credential(auth_v2, did: bytes, bindkey: bytes):
    """Create a valid root -> server -> registration chain for a negative test."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    server_key = ec.generate_private_key(ec.SECP256R1())
    # Empty distinguished names and a one-byte serial keep this negative-test
    # credential compact; the transport itself supports multi-frame parcels.
    root_name = x509.Name([])
    server_name = x509.Name([])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(root_name)
        .public_key(server_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(root_key, hashes.SHA256())
    )
    utc = int(now.timestamp()).to_bytes(4, "little")
    signed = server_key.sign(did + bindkey + utc, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signed)
    credential = auth_v2.RegistrationCredentialV2(
        did=did,
        signature=r.to_bytes(32, "big") + s.to_bytes(32, "big"),
        utc=utc,
        certificate_der=certificate.public_bytes(serialization.Encoding.DER),
    )
    root_xy = root_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )[1:]
    credential.verify_signatures(bindkey, root_public_xy=root_xy)
    return credential


def new_did() -> bytes:
    """Generate a 20-byte local DID with the shape used by the existing tool."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    suffix = "".join(secrets.choice(alphabet) for _ in range(6)).encode("ascii")
    return b"\x00blt.3.129v" + suffix + b"ATC"


async def send_parcel_reliably(
    transport, protocol, parcel_type, value, context, *, chunk_size=None
):
    """Send one parcel and honor the receiver's A_LOST retransmit requests."""
    chunk_size = chunk_size or transport.parcel_chunk_size
    chunks = [
        value[offset : offset + chunk_size]
        for offset in range(0, len(value), chunk_size)
    ]
    await transport.write(
        protocol.AVDTP,
        transport.parcel_command(parcel_type, value, chunk_size=chunk_size),
    )
    await transport.expect(protocol.AVDTP, protocol.RCV_RDY, f"{context} readiness")
    await transport.send_parcel(value, chunk_size=chunk_size)

    for _ in range(8):
        acknowledgement = await transport.receive(protocol.AVDTP)
        if acknowledgement == protocol.RCV_OK:
            return
        if (
            acknowledgement.startswith(protocol.RCV_LOST_PREFIX)
            and len(acknowledgement) == 6
        ):
            missing = int.from_bytes(acknowledgement[4:6], "little")
            if not 1 <= missing <= len(chunks):
                raise RuntimeError(f"{context}: invalid missing frame number {missing}")
            transport.trace.record("retransmit", context=context, frame_number=missing)
            await transport.write(
                protocol.AVDTP,
                missing.to_bytes(2, "little") + chunks[missing - 1],
            )
            continue
        raise RuntimeError(
            f"{context}: unexpected acknowledgement {acknowledgement.hex()}"
        )
    raise RuntimeError(f"{context}: retransmit limit exceeded")


async def run(args: argparse.Namespace) -> int:
    pairing, protocol, crypto, auth_v2 = load_core()
    device, product_id = await pairing.find_s400(address=args.address)
    selected_did = new_did()

    registration_rejected = False
    with pairing.TraceRecorder(args.trace) as trace:
        trace.record(
            "v2_probe_start",
            address=device.address,
            product_id=f"0x{product_id:04X}" if product_id is not None else None,
            probe="locally_signed_valid_structure",
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
                    "probe requires auth v2/io 0, got "
                    f"v{info.version}/io {info.io_capability}"
                )
            if info.did is not None:
                selected_did = info.did

            private_key, public_xy = crypto.generate_keypair()
            await transport.write(protocol.UPNP, protocol.CMD_SET_KEY)
            await send_parcel_reliably(transport, protocol, 0x03, public_xy, "key")

            device_public_xy = await transport.receive_parcel(expected_type=0x03)
            setup = crypto.derive_setup_secrets(private_key, device_public_xy)
            credential = make_lab_credential(auth_v2, selected_did, setup.bindkey)
            encrypted = credential.encrypt(setup.did_key)
            trace.record(
                "lab_credential_ready",
                encrypted_length=len(encrypted),
                certificate_length=len(credential.certificate_der),
            )

            # Auth v2 reverses the legacy order: opcode 0x13 precedes type 0.
            await transport.write(protocol.UPNP, protocol.CMD_AUTH)
            await send_parcel_reliably(
                transport, protocol, 0x00, encrypted, "credential"
            )

            certificate = credential.certificate_der
            await send_parcel_reliably(
                transport,
                protocol,
                0x07,
                certificate,
                "certificate",
                chunk_size=args.certificate_chunk_size,
            )

            result = await transport.receive(protocol.UPNP)
            trace.record("registration_result", value=result.hex())
            if result == protocol.REGISTER_ERROR:
                print("S400 rejected the locally signed v2 credential (0x12).")
                print(
                    "The complete protocol trace was accepted up to "
                    "certificate validation."
                )
                registration_rejected = True
            elif result != protocol.REGISTER_OK:
                raise pairing.PairingError(
                    f"unexpected registration result: {result.hex()}"
                )
            else:
                trace.record("lab_credential_accepted")
                await pairing._login(transport, setup.token)
                trace.record("login_verified")

        if registration_rejected:
            # Some firmware writes derived keys before reporting a later
            # credential failure. Reconnect and prove whether that happened.
            await asyncio.sleep(0.5)
            trace.record("post_rejection_login_start")
            try:
                async with pairing.BleakClient(device, timeout=20.0) as client:
                    transport = pairing._GattTransport(
                        client, trace, args.protocol_timeout
                    )
                    await transport.start_official_order()
                    await transport.official_init()
                    await transport.finish_subscriptions()
                    await pairing._login(transport, setup.token)
            except Exception as error:
                trace.record(
                    "post_rejection_login_failed",
                    error_type=type(error).__name__,
                    error=str(error),
                )
                print("Post-rejection login with the derived token also failed.")
                return 3
            trace.record("post_rejection_login_verified")
            print("S400 stored the ECDH-derived token despite REGISTER_ERROR.")

    did_text = selected_did.lstrip(b"\x00").decode("ascii", errors="replace")
    credentials = pairing.PairingResult(
        mac=device.address.upper(),
        product_id=f"0x{product_id:04X}" if product_id is not None else None,
        did=did_text,
        did_hex=selected_did.hex(),
        bindkey=setup.bindkey.hex(),
        token=setup.token.hex(),
        auth_protocol="Mi Home BLE standard-auth v2 (lab credential accepted)",
    )
    pairing.save_credentials(args.output, credentials)
    print("S400 ACCEPTED the locally signed v2 credential and login succeeded.")
    print(f"Credentials saved: {args.output}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trace", type=Path, default=Path("captures/s400-v2-lab-cert.jsonl")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("private/s400-secrets.json")
    )
    parser.add_argument("--protocol-timeout", type=float, default=10.0)
    parser.add_argument(
        "--certificate-chunk-size",
        type=int,
        default=240,
        help="certificate payload bytes per frame (default: negotiated maximum)",
    )
    args = parser.parse_args()
    args.address = os.environ.get("S400_BLE_ADDRESS", "").strip().upper()
    if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", args.address):
        parser.error("set S400_BLE_ADDRESS to a six-byte colon-separated BLE address")
    if not 1 <= args.certificate_chunk_size <= 240:
        parser.error("--certificate-chunk-size must be between 1 and 240")
    return args


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(run(parse_args())))
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception as error:
        print(f"s400_probe_v2: {error}", file=sys.stderr)
        raise SystemExit(1) from None
