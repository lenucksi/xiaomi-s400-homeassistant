"""Bluetooth listener and state holder for Xiaomi S400 Local."""

from __future__ import annotations

import logging
import time
from asyncio import CancelledError, Task, wait_for
from collections.abc import Callable
from contextlib import suppress
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from bleak import BleakClient
from bleak_retry_connector import establish_connection
from cryptography.exceptions import InvalidTag
from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import (
    BluetoothCallbackMatcher,
    BluetoothChange,
    BluetoothScanningMode,
    BluetoothServiceInfoBleak,
)
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from .active import CmtpFrames, decode_cmtp
from .const import (
    DEFAULT_ACTIVE_RETRY_INTERVAL,
    DEFAULT_CMTP_WAIT_TIMEOUT,
    DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_GATT_TIMEOUT,
    DOMAIN,
    MIBEACON_UUID,
)
from .pairing import _GattTransport, _login
from .parser import AdvertisementError, parse_mibeacon
from .protocol import CMTP, RCV_OK, RCV_RDY

_LOGGER = logging.getLogger(__name__)


class S400Coordinator:
    """Convert advertisements into stable entity values."""

    def __init__(
        self,
        hass: HomeAssistant,
        address: str,
        bindkey: bytes,
        token: bytes | None = None,
        entry_id: str | None = None,
        *,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        active_retry_interval: float = DEFAULT_ACTIVE_RETRY_INTERVAL,
        gatt_timeout: float = DEFAULT_GATT_TIMEOUT,
        cmtp_wait_timeout: float = DEFAULT_CMTP_WAIT_TIMEOUT,
    ) -> None:
        self.hass = hass
        self.address = address.upper()
        self.bindkey = bindkey
        self.token = token
        self.entry_id = entry_id
        self.failure_threshold = failure_threshold
        self.active_retry_interval = active_retry_interval
        self.gatt_timeout = gatt_timeout
        self.cmtp_wait_timeout = cmtp_wait_timeout
        self.values: dict[str, Any] = {
            "weight": None,
            "heart_rate": None,
            "impedance_low": None,
            "impedance_high": None,
            "profile_id": None,
            "stabilized": False,
            "measurement_time": None,
            "gatt_connected": False,
            "rssi": None,
            "last_seen": None,
            "product_id": None,
            "mibeacon_version": None,
        }
        self._listeners: set[Callable[[], None]] = set()
        self._cancel: CALLBACK_TYPE | None = None
        self._active_task: Task[None] | None = None
        self._last_active_attempt = -float("inf")
        self.last_error: str | None = None
        self._consecutive_failures = 0

    def start(self) -> None:
        """Register a passive Bluetooth callback."""
        self._cancel = bluetooth.async_register_callback(
            self.hass,
            self._advertisement,
            BluetoothCallbackMatcher(
                address=self.address,
                service_data_uuid=MIBEACON_UUID,
                connectable=False,
            ),
            BluetoothScanningMode.PASSIVE,
        )

    async def stop(self) -> None:
        """Remove the Bluetooth callback."""
        if self._cancel:
            self._cancel()
            self._cancel = None
        if self._active_task:
            self._active_task.cancel()
            with suppress(CancelledError):
                await self._active_task
            self._active_task = None

    def _note_error(self, err: object) -> None:
        """Record a failure and log the healthy -> failing transition once."""
        message = str(err)
        if self.last_error is None:
            _LOGGER.warning(
                "Xiaomi S400 %s is not reachable: %s", self.address, message
            )
        self.last_error = message

    def _note_decryption_failure(self, err: AdvertisementError) -> None:
        """Count only authenticated measurement frames with a bad tag."""
        self._note_error(err)
        self._consecutive_failures += 1
        if self.entry_id and self._consecutive_failures == self.failure_threshold:
            self._create_repair_issue()

    def _clear_error(self) -> None:
        """Clear a recorded failure and log the failing -> healthy transition once."""
        if self.last_error is not None:
            _LOGGER.info("Xiaomi S400 %s is reachable again", self.address)
        self.last_error = None

    def _clear_decryption_failure(self) -> None:
        """A decrypted object proves the stored bindkey still works."""
        self._consecutive_failures = 0
        self._delete_repair_issue()

    def _issue_id(self) -> str:
        """Return the repair issue id for this scale."""
        return f"invalid_bindkey_{self.address.replace(':', '').lower()}"

    def _create_repair_issue(self) -> None:
        """Raise a repair issue when advertisements keep failing to decrypt."""
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            self._issue_id(),
            is_fixable=True,
            severity=ir.IssueSeverity.WARNING,
            translation_key="invalid_bindkey",
            translation_placeholders={"address": self.address},
            data={"entry_id": self.entry_id},
        )

    def _delete_repair_issue(self) -> None:
        if self.entry_id:
            ir.async_delete_issue(self.hass, DOMAIN, self._issue_id())

    @callback
    def add_listener(self, listener: Callable[[], None]) -> CALLBACK_TYPE:
        self._listeners.add(listener)

        @callback
        def remove() -> None:
            self._listeners.discard(listener)

        return remove

    @callback
    def _advertisement(
        self, service_info: BluetoothServiceInfoBleak, change: BluetoothChange
    ) -> None:
        raw = service_info.service_data.get(MIBEACON_UUID)
        if raw is None:
            return
        self._start_active_session()
        try:
            update = parse_mibeacon(self.address, raw, self.bindkey)
        except AdvertisementError as err:
            if str(err) == "MiBeacon authentication tag is invalid":
                self._note_decryption_failure(err)
            else:
                self._note_error(err)
            _LOGGER.debug("Discarding S400 advertisement: %s", err)
            return
        self._clear_error()
        if update.encrypted and int.from_bytes(raw[:2], "little") & (1 << 6):
            self._clear_decryption_failure()
        parsed = asdict(update)
        if parsed["weight"] is not None and parsed["stabilized"] is False:
            self._start_measurement()
        for key in (
            "weight",
            "heart_rate",
            "impedance_low",
            "impedance_high",
            "profile_id",
            "stabilized",
        ):
            if parsed[key] is not None:
                self.values[key] = parsed[key]
        if (
            update.stabilized
            and update.timestamp is not None
            and update.timestamp >= 1_577_836_800
        ):
            with suppress(OverflowError, OSError, ValueError):
                self.values["measurement_time"] = datetime.fromtimestamp(
                    update.timestamp, UTC
                )
        self.values.update(
            rssi=service_info.rssi,
            last_seen=datetime.now(UTC),
            product_id=f"0x{update.product_id:04X}",
            mibeacon_version=update.frame_version,
        )
        self._notify_listeners()

    @callback
    def _start_measurement(self) -> None:
        """Clear fields from the previous stable reading when weighing restarts."""
        if not self.values["stabilized"]:
            return
        for key in (
            "heart_rate",
            "impedance_low",
            "impedance_high",
            "profile_id",
            "measurement_time",
        ):
            self.values[key] = None
        self.values["stabilized"] = False

    @callback
    def _start_active_session(self) -> None:
        """Connect after an advertisement shows that the scale is awake."""
        if not self.token or (self._active_task and not self._active_task.done()):
            return
        now = time.monotonic()
        if now - self._last_active_attempt < self.active_retry_interval:
            return
        self._last_active_attempt = now
        self._active_task = self.hass.async_create_task(
            self._active_session(), f"S400 active measurement {self.address}"
        )

    async def _active_session(self) -> None:
        """Log in and consume automatic measurements until disconnection."""
        device = bluetooth.async_ble_device_from_address(
            self.hass, self.address, connectable=True
        )
        if device is None or self.token is None:
            return
        client: BleakClient | None = None
        try:
            client = await establish_connection(
                BleakClient,
                device,
                f"Xiaomi S400 {self.address}",
            )
            transport = _GattTransport(client, _NoTrace(), timeout=self.gatt_timeout)
            await transport.start_official_order()
            await transport.official_init()
            await transport.finish_subscriptions()
            keys = await _login(transport, self.token)
            self._clear_error()
            self.values["gatt_connected"] = True
            self._notify_listeners()
            frames = CmtpFrames()
            queue = transport.queues[CMTP]
            while client.is_connected:
                try:
                    data = await wait_for(queue.get(), timeout=self.cmtp_wait_timeout)
                except TimeoutError:
                    continue
                if len(data) >= 6 and data[:3] == b"\x00\x00\x00":
                    try:
                        frames.start(data)
                    except ValueError:
                        frames = CmtpFrames()
                        continue
                    await transport.write(CMTP, RCV_RDY)
                    continue
                if not frames.expected:
                    continue
                try:
                    complete = frames.add(data)
                except ValueError:
                    frames = CmtpFrames()
                    continue
                if complete is None:
                    continue
                await transport.write(CMTP, RCV_OK)
                try:
                    measurement = decode_cmtp(keys, complete)
                except (InvalidTag, ValueError):
                    _LOGGER.debug("Discarding unauthenticated S400 CMTP frame")
                    continue
                if measurement is not None:
                    self._apply_active_measurement(measurement)
        except CancelledError:
            raise
        except Exception as err:
            self._note_error(f"active GATT: {type(err).__name__}")
            _LOGGER.debug("S400 active session ended: %s", type(err).__name__)
            self._notify_listeners()
        finally:
            self.values["gatt_connected"] = False
            self._notify_listeners()
            if client and client.is_connected:
                with suppress(Exception):
                    await client.disconnect()

    @callback
    def _apply_active_measurement(self, measurement: Any) -> None:
        if measurement.timestamp is not None and self.values["measurement_time"]:
            previous = self.values["measurement_time"].timestamp()
            if abs(measurement.timestamp - previous) > 15:
                self.values["stabilized"] = True
                self._start_measurement()
        if measurement.weight is not None and not measurement.stabilized:
            self._start_measurement()
        for key in (
            "weight",
            "impedance_low",
            "impedance_high",
            "profile_id",
        ):
            value = getattr(measurement, key)
            if value is not None:
                self.values[key] = value
        self.values["stabilized"] = measurement.stabilized
        if measurement.timestamp is not None:
            with suppress(OverflowError, OSError, ValueError):
                self.values["measurement_time"] = datetime.fromtimestamp(
                    measurement.timestamp, UTC
                )
        self.values["last_seen"] = datetime.now(UTC)
        self._clear_error()
        self._notify_listeners()

    @callback
    def _notify_listeners(self) -> None:
        for listener in tuple(self._listeners):
            listener()


class _NoTrace:
    """Drop protocol trace events during normal Home Assistant operation."""

    def record(self, event: str, **values: Any) -> None:
        """Intentionally avoid logging protocol payloads or secrets."""
