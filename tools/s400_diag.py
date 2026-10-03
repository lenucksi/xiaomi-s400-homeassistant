#!/usr/bin/env python3
"""Discover an S400, enumerate GATT and capture every available notification.

This tool is deliberately read-only at the application protocol level: it does
not write pairing or login commands. Enabling notifications causes BlueZ to
write CCC descriptors as part of normal subscription setup.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("Missing dependency: python3 -m pip install bleak", file=sys.stderr)
    raise SystemExit(2) from None

MIBEACON_UUID = "0000fe95-0000-1000-8000-00805f9b34fb"
S400_PRODUCT_IDS = {0x30D9, 0x3BD5, 0x48CF}


class JsonlTrace:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        self.handle = os.fdopen(fd, "w", encoding="utf-8")
        self.started = time.monotonic()

    def write(self, event: str, **fields: Any) -> None:
        row = {"t": round(time.monotonic() - self.started, 6), "event": event, **fields}
        self.handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        self.handle.flush()

    def close(self) -> None:
        self.handle.close()


def product_id(data: bytes | None) -> int | None:
    return int.from_bytes(data[2:4], "little") if data and len(data) >= 4 else None


async def locate(address: str, scan_timeout: float, trace: JsonlTrace):
    chosen: tuple[Any, Any] | None = None

    def callback(device: Any, adv: Any) -> None:
        nonlocal chosen
        data = adv.service_data.get(MIBEACON_UUID)
        pid = product_id(data)
        matches_address = bool(address and device.address.upper() == address.upper())
        name = (adv.local_name or device.name or "").lower()
        matches_s400 = pid in S400_PRODUCT_IDS or "s400" in name
        if not matches_address:
            return
        services = {key: value.hex() for key, value in adv.service_data.items()}
        trace.write(
            "advertisement",
            name=adv.local_name or device.name,
            rssi=adv.rssi,
            service_uuids=list(adv.service_uuids),
            service_data=services,
            manufacturer_data={
                str(k): v.hex() for k, v in adv.manufacturer_data.items()
            },
        )
        if matches_s400:
            chosen = device, adv

    async with BleakScanner(detection_callback=callback):
        deadline = asyncio.get_running_loop().time() + scan_timeout
        while chosen is None and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.1)
    if chosen is None:
        raise RuntimeError("S400 not found; check S400_BLE_ADDRESS and wake the scale")
    return chosen


async def run(args: argparse.Namespace) -> None:
    trace = JsonlTrace(args.output)
    subscribed: list[str] = []
    try:
        trace.write("scan_start")
        device, advertisement = await locate(args.address, args.scan_timeout, trace)
        pid = product_id(advertisement.service_data.get(MIBEACON_UUID))
        print(f"Found {device.name or advertisement.local_name or 'S400'}")
        print(
            f"MiBeacon product id: {f'0x{pid:04X}' if pid is not None else 'unknown'}"
        )
        trace.write("connect_start", product_id=pid)

        async with BleakClient(device, timeout=args.connect_timeout) as client:
            trace.write("connected")
            print("\nGATT database:")
            for service in client.services:
                print(f"service {service.uuid}  {service.description}")
                trace.write(
                    "service", uuid=service.uuid, description=service.description
                )
                for characteristic in service.characteristics:
                    props = list(characteristic.properties)
                    handle = f"0x{characteristic.handle:04x}"
                    print(
                        f"  char {characteristic.uuid} handle={handle} "
                        f"props={','.join(props)}"
                    )
                    trace.write(
                        "characteristic",
                        service_uuid=service.uuid,
                        uuid=characteristic.uuid,
                        handle=characteristic.handle,
                        properties=props,
                    )
                    if args.read and "read" in props:
                        try:
                            value = bytes(await client.read_gatt_char(characteristic))
                        except Exception as err:  # device-specific permissions
                            trace.write(
                                "read_error", uuid=characteristic.uuid, error=repr(err)
                            )
                        else:
                            trace.write(
                                "read", uuid=characteristic.uuid, value=value.hex()
                            )

            def notify(sender: Any, data: bytearray) -> None:
                uuid = getattr(sender, "uuid", str(sender))
                value = bytes(data)
                trace.write("notify", uuid=uuid, value=value.hex())
                print(f"notify {uuid}: {value.hex(' ')}")

            for service in client.services:
                for characteristic in service.characteristics:
                    if {"notify", "indicate"}.intersection(characteristic.properties):
                        try:
                            await client.start_notify(characteristic, notify)
                        except Exception as err:
                            trace.write(
                                "subscribe_error",
                                uuid=characteristic.uuid,
                                error=repr(err),
                            )
                        else:
                            subscribed.append(characteristic.uuid)
                            trace.write("subscribed", uuid=characteristic.uuid)
            subscription_count = len(subscribed)
            print(
                f"\nListening for {args.duration:g}s on "
                f"{subscription_count} characteristics…"
            )
            print("Keep the scale awake; step on it if you want measurement traffic.")
            await asyncio.sleep(args.duration)
            trace.write("capture_complete", subscriptions=len(subscribed))
    except Exception as error:
        trace.write("capture_error", error=repr(error))
        raise
    finally:
        trace.close()
    print(f"Trace saved with mode 0600: {args.output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("s400-gatt-trace.jsonl"))
    parser.add_argument("--scan-timeout", type=float, default=20.0)
    parser.add_argument("--connect-timeout", type=float, default=20.0)
    parser.add_argument("--duration", type=float, default=45.0)
    parser.add_argument(
        "--read",
        action="store_true",
        help="also read every characteristic marked readable",
    )
    args = parser.parse_args()
    args.address = os.environ.get("S400_BLE_ADDRESS", "").strip().upper()
    if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", args.address):
        parser.error("set S400_BLE_ADDRESS to a six-byte colon-separated BLE address")
    return args


if __name__ == "__main__":
    try:
        asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception as error:
        print(f"s400_diag: {error}", file=sys.stderr)
        raise SystemExit(1) from None
