# Xiaomi S400 Local for Home Assistant

[![Validate](https://github.com/kbpk/xiaomi-s400-homeassistant/actions/workflows/validate.yml/badge.svg)](https://github.com/kbpk/xiaomi-s400-homeassistant/actions/workflows/validate.yml)
[![HACS custom repository](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://hacs.xyz/docs/faq/custom_repositories/)

Experimental HACS integration for the Xiaomi Body Composition Scale S400
(`MJTZC01YM`, `yunmai.scales.ms103/ms104/ms107`). Data reception and key storage
happen locally. The Home Assistant integration itself contains no Xiaomi Cloud
client and does not ask for Xiaomi account credentials. A separate lab tool can
request a one-time signature from the Xiaomi backend, which a factory-new S400
with auth version 2 requires.

Requires Home Assistant 2026.9.4 or newer.

> [!WARNING]
> Measurement reception in Home Assistant still needs further hardware testing.
> Auth v2 provisioning was confirmed on an S400 with
> firmware `2.1.1_0006`: the scale returned `REGISTER_OK` and then accepted a
> local login with the token. The first bind requires a one-time credential
> signature from Xiaomi; afterwards data reception and GATT logins are local.
> The purely local provisioner still supports only the older auth version 1.
> Detailed evidence, compatibility limits and the Bluetooth-free analysis are in
> [AUTH_V2.md](research/AUTH_V2.md). The
> [analysis of the official Mi Home APK](research/MIHOME_V2.md) independently
> confirms this order and identifies the missing registration credential.

## Implementation status

- experimental standard-auth version 1 provisioning without OOB via P-256 ECDH,
  HKDF-SHA256 and AES-CCM;
- an auth v2 tool that performs ECDH locally, asks Xiaomi only for the signed
  credential, verifies both signatures locally and was verified on the S400 via
  `REGISTER_OK` and a subsequent token login;
- Bluetooth-free capture analysis and an offline-tested auth v2 credential
  format;
- storing the 16-byte bindkey and the 12-byte token only after the device's
  registration response and a successful login;
- MiBeacon v4/v5 decryption and entities: weight, heart rate, 50 kHz impedance,
  250 kHz impedance, user profile, stabilization and RSSI;
- automatic connection when the scale wakes, token login and local reception of
  live and final measurements from the encrypted CMTP channel;
- redaction of secrets from Home Assistant diagnostics;
- self-contained GATT trace and pairing tools for Raspberry Pi OS/Debian.

The older standard-auth sequence comes from analysis of open source
implementations. It does not match the full version 2 procedure found in the
public SDK. The integration only reports success after a `0x11000000` response
and a successful login, so it will not store random, unagreed keys.

## Installation via HACS

1. Add this repository to HACS as a custom repository of type **Integration**.
2. Download **Xiaomi S400 Local** and restart Home Assistant.
3. Wake the scale and choose
   **Settings → Devices & services → Add integration → Xiaomi S400 Local**.
4. Enter the 16-byte bindkey and, optionally, the 12-byte token. The token
   enables active GATT reception; without it, reception uses FE95 advertisements.

Home Assistant setup does not pair or reset the scale. Use **Reconfigure** if
its keys change. Home Assistant stores the keys in the config entry, so protect
its `.storage` directory and backups.

The 50 and 250 kHz impedance labels are inferred from frame order and values;
electrode frequencies have not been measured directly. Body composition
percentages are not calculated from unverified formulas. A new weighing clears
the previous person's heart rate and impedance values.

Manual installation means copying the `custom_components/xiaomi_s400_local`
directory into the `custom_components` directory of a Home Assistant instance
and restarting HA.

## Obtaining the bindkey

The S400 broadcasts its measurements as **encrypted** MiBeacon frames, so Home
Assistant needs the scale's 16-byte **bindkey** to decrypt them. There is no way
to derive an existing bindkey locally — it is generated once when the scale is
paired — so it has to be read from your Xiaomi account:

1. Add the scale to the **Xiaomi Home** app and weigh yourself once. This mints
   the bindkey.
2. Run the [Xiaomi Cloud Tokens Extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor)
  using the extractor's current installation instructions. Log in with the Xiaomi account: QR login,
   e-mail/password, 2FA and captcha are supported interactively, so 2FA is not a
   blocker. Pick your region (e.g. `de` for Europe).
3. Find the S400 in the output and copy:
   - **`BLE KEY`** — the 16-byte bindkey (32 hex characters). **Required.**
   - **`TOKEN`** — the 12-byte login token (24 hex characters). Optional; only
     needed for the active GATT stream.
4. Enter the bindkey (and optionally the token) in the integration's setup or
   **Reconfigure** dialog.

Notes:

- The 12-byte token is **not** the bindkey. Passive weight, heart rate and
  impedance only need the bindkey; the token is only for the optional active
  GATT connection.
- The bindkey rotates if you factory-reset the scale or remove and re-add it in
  the Xiaomi Home app. Re-run the extractor and update the integration through
  **Reconfigure**. The integration raises a repair issue when advertisements stop
  decrypting.
- The e-mail/password re-authentication inside Home Assistant is unreliable for
  the S400; the extractor above is the route that works.

## First diagnostic trace

Existing captures can be analysed in WSL without a Bluetooth adapter:

```bash
uv run python tools/s400_analyze_trace.py captures/s400-pair*.jsonl
```

The result contains the auth version, information about the key exchange and the
order of `0x13` relative to the registration data. It does not reveal raw frames
or keys.

On Raspberry Pi OS or Debian:

```bash
export S400_BLE_ADDRESS='AA:BB:CC:DD:EE:FF'  # replace with your scale's address
uv run --no-project --with-requirements requirements-lab.txt \
  tools/s400_diag.py --duration 60 --output captures/s400-gatt.jsonl
```

Bleak uses the D-Bus BlueZ service. On a typical Raspberry Pi OS a user with
Bluetooth access is enough; if the local D-Bus policy rejects the connection,
run the individual tool through `sudo uv run ...`.

The script detects the S400 PID, prints the full GATT database, subscribes to
all `notify`/`indicate` characteristics and writes advertisements and
notifications to JSONL with `0600` permissions. It does not send auth commands.
The `--read` option additionally reads characteristics marked as readable by
GATT.

### Windows / WSL

WSL does not automatically use the Windows Bluetooth stack. Without a passed
through USB adapter, the tools can be run directly through the Windows Python
and Bleak's WinRT backend:

```powershell
$repo = "\\wsl.localhost\Ubuntu\home\kbpk\xiaomi\xiaomi-s400-homeassistant"
uv run --no-project --with-requirements "$repo\requirements-lab.txt" `
  "$repo\tools\s400_diag.py" --duration 60 `
  --output "$repo\captures\s400-gatt.jsonl"
```

The distribution name `Ubuntu` in the path may differ; `wsl -l -v` shows it.
Files on Windows inherit the directory ACL instead of the Unix `0600` mode.
Set `$env:S400_BLE_ADDRESS = "AA:BB:CC:DD:EE:FF"` in the same PowerShell
session before running the diagnostic tool; replace the example with your scale's
address.

## Standalone local pairing

This applies only to the experimental GET_INFO version 1 path without OOB. The
tested S400 reports version 2 and will receive a message that it is not
supported.

After a factory reset and waking the scale:

```bash
export S400_BLE_ADDRESS='AA:BB:CC:DD:EE:FF'  # replace with your scale's address
uv run --no-project --with-requirements requirements-lab.txt \
  tools/s400_pair.py \
  --output private/s400-secrets.json \
  --trace captures/s400-pair.jsonl
```

On Windows, run the same file through `uv` and the WinRT backend:
Set `$env:S400_BLE_ADDRESS = "AA:BB:CC:DD:EE:FF"` first, using your own
scale's address.

```powershell
$repo = "\\wsl.localhost\Ubuntu\home\kbpk\xiaomi\xiaomi-s400-homeassistant"
uv run --no-project --with-requirements "$repo\requirements-lab.txt" `
  "$repo\tools\s400_pair.py" `
  --output "$repo\private\s400-secrets.json" `
  --trace "$repo\captures\s400-pair.jsonl"
```

The `--stage-delay` option controls the experimental pause between the scale's
public-key acknowledgement and `SEND_DID` (0 s by default). The trace also
records the completion of every write, the disconnection and the exception, so
that a rejected frame can be told apart from a Bluetooth backend error.

The secrets file has `0600` permissions. The trace contains GATT frames and
public keys, but not the derived token, bindkey or session keys. Do not publish
the `s400-secrets.json` file.

## One-time auth v2 provisioning through Xiaomi

This is the confirmed path for a factory-new S400 with auth v2. The token and
bindkey are still derived locally from ECDH. The MAC, model, token and bindkey
are sent to Xiaomi, exactly as in Mi Home; the server returns the DID, a
certificate and a signature over `DID || bindkey || UTC`. The textual DID is
left-padded with zeros to 20 bytes, exactly as in Mi Home. The script verifies
the credential signature and the certificate against the public root key from
the SDK, requires `REGISTER_OK` and then verifies the token with a local GATT
login.

On Windows with an ASUS USB-BT400, run the tool in a regular PowerShell. The
launcher opens a dedicated Edge profile on the current Xiaomi account page.
Finish the login and any e-mail verification there, and only then return to the
terminal. Before sending the request the provisioner requires the `passToken`
cookie; an unfinished login ends with a local error and does not generate
another code. The login and password are read interactively; the password,
cookies and API responses never end up in arguments, the trace or the result
file:

```powershell
$repo = "\\wsl.localhost\Ubuntu\home\kbpk\xiaomi\xiaomi-s400-homeassistant"
& "$repo\tools\windows\run_s400_xiaomi_pair.ps1" -Region de
```

Before starting this launcher, set `$env:S400_BLE_ADDRESS` in the same
PowerShell session to your scale's address (for example,
`$env:S400_BLE_ADDRESS = "AA:BB:CC:DD:EE:FF"`). The tools read it directly from
the process environment; the address is not passed in command arguments.

The region must match the region of the Mi Home account. For an account used in
Poland the usual value is `de`; `cn`, `us`, `ru`, `tw`, `sg`, `in` and `i2` are
also available. The dedicated profile is stored locally in
`%LOCALAPPDATA%\XiaomiS400Provisioner\EdgeProfile`, so cookies survive a restart
after a Xiaomi time limit. The script does not automatically retry a rejected
captcha.

After a success, Xiaomi is no longer needed for the integration to work. In Home
Assistant enter the 32 `bindkey` characters and the 24 `token` characters from
the result file. The tool does not fetch existing keys from the account and does
not compute measurements in the cloud.

A hardware test on 2026-09-21 confirmed the DMTU 242 negotiation, the
multi-frame certificate transfer, the local verification of both signatures, the
`11000000` (`REGISTER_OK`) response and the later `21000000` (`LOGIN_OK`)
response.

Details of the protocol, the state of evidence and the capture workflow are in
[`research/PROTOCOL.md`](research/PROTOCOL.md) and
[`research/CAPTURE.md`](research/CAPTURE.md).

## Supported devices

| Model | Marketing name | Notes |
|---|---|---|
| `MJTZC01YM` | Xiaomi Body Composition Scale S400 (`yunmai.scales.ms103` / `ms104` / `ms107`) | Weight, heart rate, dual-frequency impedance, profile id. Broadcasts encrypted MiBeacon v4/v5 and needs a bindkey. |

The parser recognises the product ids `0x30D9`, `0x3BD5` and `0x48CF`. The scale
is a "sleepy" device: it only advertises around a weigh-in.

## Supported functionality

One device with these entities:

- `sensor.weight` — last stabilised weight (kg)
- `sensor.heart_rate` — heart rate (bpm), when measured barefoot
- `sensor.impedance_50_khz` — low-frequency impedance (Ω)
- `sensor.impedance_250_khz` — high-frequency impedance (Ω)
- `sensor.profile_id` — scale user slot the reading was assigned to
- `sensor.signal_strength` — RSSI (diagnostic, disabled by default)
- `binary_sensor.measurement_stabilized` — measurement cycle finished

Body-composition metrics (BMI, body fat, muscle, water, …) are not computed
here. Feed weight and both impedances into
[`bodymiscale`](https://github.com/dckiller51/bodymiscale) (dual-frequency S400
mode) for that.

## How data is updated

The integration is push-based (`iot_class: local_push`). It listens for the
scale's encrypted MiBeacon advertisements and updates the entities as frames
arrive. A barefoot weigh-in produces two measurement frames (weight + 50 kHz
impedance + heart rate, then 250 kHz impedance). If a 12-byte login token is
configured, an authenticated GATT session is also consumed for live and final
measurements. Values are restored after a Home Assistant restart. There is no
polling and no cloud connection.

## Use cases

- Track a weight/composition trend with long-term statistics, independent of the
  Xiaomi Cloud.
- Automate on a finished measurement, for example:

```yaml
triggers:
  - trigger: state
    entity_id: binary_sensor.xiaomi_s400_measurement_stabilized
    to: "on"
actions:
  - action: notify.mobile_app_phone
    data:
      message: >-
        {{ states('sensor.xiaomi_s400_weight') }} kg
```

## Configuration parameters

- **Bluetooth address** — the scale's six-byte address.
- **Bindkey** (16 bytes / 32 hex) — decrypts the advertisements. Required.
- **Login token** (12 bytes / 24 hex) — optional; only for the active GATT stream.

Both credentials can be updated later through **Reconfigure** on the config entry.

## Removal

1. **Settings → Devices & services → Xiaomi S400 Local → Delete** to remove the
   config entry (this stops the Bluetooth listener).
2. Optionally delete the `custom_components/xiaomi_s400_local` folder (or remove
   it through HACS) and restart Home Assistant.
3. Historical statistics remain in the recorder after removal; purge them with
   `recorder.purge_entities` if desired.

## Troubleshooting

- **No entities / only signal strength** — the scale has not been paired in the
  Xiaomi Home app yet, so it never minted a bindkey. Pair it once, extract the
  bindkey, then add the integration.
- **No data while the phone app is open** — the app holds the GATT connection
  and the scale stops broadcasting. Close the app (or its Bluetooth) while
  weighing.
- **`invalid_address` / `invalid_key`** — check the six-byte MAC and that the
  bindkey is 32 hex characters, the token 24.
- **Weak/flickering signal** — the S400 is sleepy and low power. Move a
  Bluetooth proxy closer, or prefer a local adapter over a distant proxy.
- **`registration_unsupported`** — the scale reports auth version 2, for which a
  fully local first pairing is not possible (it needs a one-time Xiaomi-signed
  credential). Use **Existing keys** with a bindkey from the token extractor.

## Known limitations

- The bindkey must be extracted once from the Xiaomi Cloud
  ([Xiaomi Cloud Tokens Extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor));
  the email/password re-auth inside Home Assistant is unreliable for the S400.
- Body-composition metrics are not computed locally; use `bodymiscale`.
- Auth version 2 first-bind cannot be done fully offline (see Troubleshooting).
- The optional active GATT stream needs a connectable adapter/proxy and a valid
  token; it is not required for weight, heart rate or impedance, which all
  arrive passively.

## Development

```bash
uv sync --dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

BLE traces and secret files are ignored by Git. The rules for reporting results
and for safely preparing captures are described in
[`CONTRIBUTING.md`](CONTRIBUTING.md).
