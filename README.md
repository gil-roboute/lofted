# lofted — local control for the Loftie alarm clock

Tooling and notes for moving a [Loftie](https://byloftie.com) smart alarm clock off the vendor
cloud and onto **your own MQTT broker, with your own certificates on both ends**, driven from
[Home Assistant](https://www.home-assistant.io/). The stock firmware and its on-device UI are kept;
the image is patched in place so the clock talks only to your LAN.

This builds on Ian Kilgore's original work: his
[security write-up](https://iank.org/posts/loftie-rce/) on the clocks and his proof-of-concept
patch for firmware `v0007_1.6.0` at
[iank/alarmclock-firmware](https://github.com/iank/alarmclock-firmware). That repository's notes
(debug-header pinout, original `patch.py`) are not reproduced here — read them there.

> **Scope.** Local control of hardware you own. No cloud service is impersonated and no TLS
> validation is defeated: the clock trusts *your* CA and presents *your* client cert. Not affiliated
> with or endorsed by Loftie. No vendor firmware, dumps or keys are included in this repository.

## What's here

| Path | Purpose |
| ---- | ------- |
| `docs/deployment-runbook.md` | **Start here** — pre-flight checks, build, broker, flash, Home Assistant |
| `writeup-blog.md` | the full teardown story: header → dump → Ghidra → patch |
| `gen_certs.py` | mints the EC P-256 CA / clock / Home Assistant / broker chain, sized for the firmware slots |
| `may-firmware-dump/patch_this.py` | patches + re-signs + validates the app image (`ota_0.bin` → `fw_patched.bin`) |
| `may-firmware-dump/nvs_parse.py` | NVS decoder: `--alarms`, and the `--check-certs` pre-flash gate |
| `may-firmware-dump/partitions.csv` | the clock's partition table |
| `mosquitto/` | mutual-TLS broker config, per-identity ACL, Portainer/Docker compose |
| `home-assistant/loftie.yaml` | HA package: sensors, scripts, alarm sync |
| `docs/security-gaps.md` | what the stock firmware exposes and what this setup closes |
| `docs/mqtt-command-reference.md` | topics and JSON commands, decoded from the firmware |
| `docs/ghidra-import.md` | reproducible Ghidra import of the app image |
| `docs/display-graphics-feasibility.md` | notes on custom display graphics |
| `docs/trilium-loftie-local-control.md` | everything above as one document |

| `tests/` | synthetic-image tests for the patcher and NVS parser (`python3 tests/test_*.py`) |

Your own dumps, certificates and device notes stay local — see `.gitignore`.

## Firmware v0010_2.4.0

The unit dumped in May 2026 runs `Loftie_EVT` app version `0010_2.4.0` (esp-idf v5.1.1).
`patch_this.py` is written for that image: it recomputes the esp32 image checksum + appended
SHA-256 itself (esptool v5 changed its `image_info` output), asserts it is patching the expected
certificate slots (the image also bundles ~140 Mozilla CA roots that must not be touched), matches
every rewritten string exactly, and refuses to write an image that still references a vendor
endpoint. A different firmware build will be rejected rather than mis-patched.

### Reverse-engineering findings (this image)

- **Broker URI is a hardcoded literal** (`mqtts://[REDACTED]-ats.iot.us-east-1.amazonaws.com:8883`,
  file offset `0x16f10`), referenced exactly once. It is not stored in NVS, so redirecting it
  requires patching + re-signing the image — there is no NVS-only option.
- **Embedded TLS identity** sits before the Mozilla CA bundle:
  client cert `@0x120` (1223 B, `CN=AWS IoT Certificate`), client key `@0x5ed` (1678 B, RSA-2048),
  CA cert `@0xc81` (1187 B, `Amazon Root CA 1`). Replacements must fit these slots — use an
  **EC P-256 client key** (~230 B) and a **small CA cert** (EC, or RSA with a short CN) so the
  ~1187 B CA slot is not overrun. `patch_this.py` length-guards each slot and aborts on overflow.
- **NVS** (`python3 nvs_parse.py app_cfg.bin`): partition `app_cfg` (`0x10000`), namespace
  `storage` holds `key_wifi` (161 B), `key_user_perf` (256 B, timezone), `key_app` (28 B, device
  serial), `key_alarm` (480 B).

### Verified by decompilation (Ghidra, 2026-06)

Confirmed in the live image (`Xtensa:LE:32:default`, entry `0x400818e0`) — details in `docs/`:

- **MQTT/TLS wiring** (`FUN_400f3920`, builds `esp_mqtt_client_config_t`): the broker URI
  (`0x3f416f10`) is loaded as `broker.address.uri`; the CA slot (`0x3f400c81`) as the broker trust
  anchor and is **never overridden** → your CA is always honored. Client cert/key (`0x3f400120` /
  `0x3f4005ed`) are used **unless** a runtime flag (`0x3ffc6d40`) is set after `FUN_400f4020` loads
  provisioned certs from **NVS keys `download/Cert.dl` / `Key.dl`** (a claim-provisioning path).
  The dumped unit's NVS held **only WiFi creds, no `download` certs**, so it used the compiled-in
  (patched) client cert. Pairing with the vendor app pushes a cert over BLE, so the runbook checks
  **both** NVS partitions with `nvs_parse.py --check-certs` before every flash.
- **Command/state schema** (`AWS_receive_config_cb` `FUN_400f3a84` → `IOTGW_Json2State`
  `FUN_400fa850`; state from `IOTGW_State2Json` `FUN_400f9b7c`): the device subscribes to **both**
  `/devices/<id>/config` **and** `/devices/<id>/commands/#`, and inbound data on either goes to the
  **same** flat-JSON parser — the **subtopic is ignored**, the verb must be a JSON key. Scalar
  setters `nightLight`/`nightLightOn`/`volume` are handled inline; everything else (alarms[],
  `alarmControl` as a **string**, `setTime`, `restart`, …) by `IOTGW_Json2State`. The `/state` JSON
  has **no `rssi`** field. Full table in `docs/mqtt-command-reference.md`.
- **Endpoint sweep**: the only outbound URLs are the broker, OTA `.bin`, two vendor sdcard asset
  URLs and ip-api — **all neutralized by `patch_this.py`**. The only remaining external egress is
  **NTP** (`pool.ntp.org`, `time.google/cloudflare.com`) — benign time-sync, optionally repointable
  to a LAN NTP server.

### `key_alarm` encoding (decoded)

One 480-byte blob = 30 × 16-byte alarm records (`python3 nvs_parse.py app_cfg.bin --alarms`):

| byte | field |
| ---- | ----- |
| 0    | hour, 12-hour (1–12) |
| 1    | hour, 24-hour (0–23) |
| 2    | minute (0–59) |
| 3    | bit7 = isSet; bits0–6 = daysOfWeek (bit0=Sun … bit6=Sat; 0 = one-time) |
| 4–7  | boolean flags (alarmLight / wake-up / get-up; byte 5 is constant 1) |
| 8–12 | tone folder/file indices (constant `00 01 00 01 09` on the dumped unit) |

Example (illustrative values): `07 07 1e be` → 07:30, days 62 (Mon–Fri), isSet. Empty slots are
all-zero. Alarms are normally set over MQTT (see `docs/mqtt-command-reference.md`); this decode is
for inspection/verification.

## Deploying

Follow `docs/deployment-runbook.md`. In short:

1. **Pre-flight** — read both NVS partitions off the clock and run `nvs_parse.py --check-certs` on
   each; confirm the active app slot from the boot log.
2. `BROKER_IP=<host-ip> python3 gen_certs.py` — your CA, clock, Home Assistant and broker certs.
3. `cd may-firmware-dump && BROKER_IP=<host-ip> python3 patch_this.py` → `fw_patched.bin`.
4. Deploy `mosquitto/` (mutual TLS + ACL) on a host with a fixed LAN IP.
5. Flash the active slot, watch the serial log for a clean TLS handshake, keep the full dump for
   recovery (`esptool write_flash 0x0 loftie_full_dump.bin`).
6. Point Home Assistant at the broker with `ha.crt` / `ha.key` and load `home-assistant/loftie.yaml`.

> **WiFi without the Loftie app:** pairing/WiFi setup uses the vendor app over BLE. Keeping the
> `app_cfg` partition preserves the network the clock already joined, so no app is needed for an
> already-paired unit. Moving it to a new SSID (or provisioning a blank unit) without the app is not
> solved here yet — it needs either an NVS image or a small firmware change to read static creds.

## License

[MIT](LICENSE) — provided **as is, without warranty of any kind**. Flashing modified firmware can
brick your device or void its warranty; keep a full flash dump and proceed at your own risk.
Third-party names and trademarks (Loftie, AWS, Espressif, Home Assistant) belong to their owners.
