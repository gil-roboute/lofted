# Loftie local-control — deployment runbook

End-to-end steps to build the patched firmware and bring a clock up on your own broker + Home
Assistant. This is the operational checklist; the *why* behind each step is in `../README.md` (RE
findings), `mqtt-command-reference.md` (control surface), and `security-gaps.md`.

Examples use `lXXXXXXXXXXXX` for the device ID — yours is printed in the serial boot log as
`client_id=l<MAC>` (12 lowercase hex digits). Keep it in `../device-id.local.md` (gitignored).

---

## 0. Prerequisites

- **This repo**, plus your own `loftie_full_dump.bin` (the golden recovery image — confirm it is
  16,777,216 bytes) and the active app slot carved to `may-firmware-dump/ota_0.bin`. Dumps are
  gitignored: they contain WiFi credentials and the vendor's device key.
- **Python 3** with the `cryptography` package (used for cert gen + image validation — no `openssl`
  needed). `python3 -c "import cryptography"` should succeed.
- **esptool** — needed only to read/write flash (`pip install esptool`, or run it from an esp-idf
  shell). Not needed to *build* the image.
- **A serial/UART adapter** (3.3 V) wired to the debug header — see `../writeup-blog.md`
  ("Wiring the harness", "Entering and exiting the bootloader").
- **A Portainer/Docker host** on the LAN with a **static / DHCP-reserved IP** (Mosquitto will live
  here; that IP gets compiled into the firmware).
- A running **Home Assistant** with the MQTT integration available.

Pick your broker IP now and use it everywhere below as `BROKER_IP`. Example uses `192.168.1.50`.

---

## 1. Pre-flight checks (do not skip)

Enter the bootloader (hold **IO0→GND**, tap **EN→GND**, release EN, release IO0 — 3.3 V adapter,
clock wall-powered, common ground only) and read the clock's *current* state, not a stale dump:

```bash
esptool --chip esp32 -p /dev/ttyUSB0 read_flash 0x9000  0x4000 nvs.bin       # nvs
esptool --chip esp32 -p /dev/ttyUSB0 read_flash 0x10000 0x2000 app_cfg.bin   # app_cfg
python3 may-firmware-dump/nvs_parse.py nvs.bin     --check-certs
python3 may-firmware-dump/nvs_parse.py app_cfg.bin --check-certs
```

Both must print `CHECK OK`. A provisioned cert (`download/Cert.dl` / `Key.dl`) is presented
**instead of** the patched client cert, and your broker will reject it (see §8 for the fix). Pairing
with the vendor app writes a fresh cert + key to the clock over BLE, so re-check after any re-pair.

**Confirm the active slot.** A normal boot prints `Loaded app from partition at offset 0x…`. The
offset you flash in §5 must match it, and `ota_0.bin` must be carved from *that* slot of a dump
taken *after* the clock's last OTA update. `patch_this.py` refuses to run if the image layout
differs from the one it was written for.

---

## 2. Generate your TLS chain

From the repo root:

```bash
BROKER_IP=192.168.1.50 python3 gen_certs.py
```

This writes `certs/{ca,client,ha,server}.{crt,key}` (all EC P-256, gitignored, keys `0600`). It
asserts each firmware PEM fits its fixed slot and that every cert verifies under the CA. Roles:

- `ca.crt` — your CA; trust anchor compiled into the firmware **and** trusted by the broker.
  `ca.key` never leaves this machine.
- `client.crt` + `client.key` — the clock's identity (`CN=AlarmClock`), compiled into the firmware.
- `ha.crt` + `ha.key` — Home Assistant's identity (`CN=home-assistant`).
- `server.crt` + `server.key` — the broker's identity; `server.crt` carries `IP:<BROKER_IP>` as a
  SAN so the clock accepts it when connecting by IP.

The CNs are the broker usernames that `mosquitto/acl` keys on — don't change one without the other.

> Keep the same `BROKER_IP` for steps 2 and 3. Changing it later = re-run both (one minute).

---

## 3. Build the patched firmware

```bash
cd may-firmware-dump
BROKER_IP=192.168.1.50 python3 patch_this.py      # -> fw_patched.bin
```

Optional: `ASSET_HOST=<lan-host>` redirects the sound-download URLs to a LAN server that serves the
same `/sdcard/<file>` layout. The default, `assets.invalid`, fails closed (your sounds already live
on the SD card).

A clean run asserts the original AWS identity slots, rewrites the broker/OTA/ip-api/asset strings
(each must match exactly the expected number of times), swaps in your EC chain, refuses to continue
if any vendor endpoint is still referenced, re-signs, and **validates the image in pure Python**.
Expect:

```
broker URI -> mqtts://192.168.1.50:8883
OK: esp32 segment checksum valid, appended SHA-256 valid, length consistent.
```

If it refuses, it tells you why — do **not** flash an image it rejected.

---

## 4. Stand up Mosquitto on Portainer

The broker config, ACL and compose are in `../mosquitto/`.

1. Copy **only** `certs/ca.crt`, `certs/server.crt`, `certs/server.key` into `mosquitto/certs/` (or
   edit the bind paths). Never put `ca.key`, `client.key` or `ha.key` on the broker host.
2. The container runs mosquitto as uid 1883: `sudo chown 1883:1883 mosquitto/certs/server.key`.
   Mosquitto also warns about a world-readable ACL: `chmod 0640 mosquitto/acl` and
   `sudo chown 1883:1883 mosquitto/acl`.
3. In Portainer: **Stacks → Add stack**, paste `mosquitto/docker-compose.yml`, deploy.

The broker requires mutual TLS on `8883` (no anonymous, client cert mandatory) and applies the ACL:
the clock may only read its `config`/`commands` topics and write `state`; only Home Assistant may
send commands; any other cert signed by your CA gets no topics at all.

Sanity check from any LAN machine with mosquitto-clients:

```bash
mosquitto_sub -h 192.168.1.50 -p 8883 -t '/devices/lXXXXXXXXXXXX/#' \
  --cafile certs/ca.crt --cert certs/ha.crt --key certs/ha.key
```

---

## 5. Flash the clock

1. Enter the bootloader as in §1.
2. Flash the **active** slot you confirmed in §1 (`ota_0` = `0x420000`, `ota_1` = `0x820000`):
   ```bash
   esptool --chip esp32 -p /dev/ttyUSB0 write_flash 0x420000 fw_patched.bin
   ```
3. Leave both NVS partitions alone unless §1 flagged one (see §8). The clock's WiFi credentials
   live in `app_cfg` (`0x10000`).

**Recovery** (anytime): `esptool --chip esp32 -p /dev/ttyUSB0 write_flash 0x0 loftie_full_dump.bin`.

---

## 6. First boot — confirm the handshake

Watch the serial log. You want:

- `Loaded app from partition at offset 0x…` matching the slot you flashed,
- the clock rejoins your WiFi,
- the MQTT TLS handshake to your broker **succeeds** — i.e. **no** `mbedtls_ssl_handshake
  returned -0x...`,
- it prints `client_id=l<MAC>` and publishes to `/devices/l<MAC>/state`.

Your `mosquitto_sub` from §4 should start showing state JSON.

---

## 7. Home Assistant

1. Point the HA **MQTT integration** at `192.168.1.50:8883` with `ca.crt` + `ha.crt` + `ha.key`
   (mutual TLS).
2. Load `../home-assistant/loftie.yaml` as a package; replace every `lXXXXXXXXXXXX` with your device
   ID.
3. You get sensors (battery, charging, plugged-in, volume, night-light) and scripts
   (volume, night-light, snooze, dismiss, restart) plus an alarm-sync automation.

Set an alarm to confirm the round trip, then re-read `app_cfg` (§1) and run
`python3 may-firmware-dump/nvs_parse.py app_cfg.bin --alarms` to confirm persistence.

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `mbedtls_ssl_handshake returned -0x2700` (cert verify) | broker server cert SAN ≠ the IP the clock dials | regenerate `server.crt` with the right `BROKER_IP` (step 2), redeploy broker |
| `--check-certs` fails, or the handshake fails on a previously-paired unit | provisioned cert in NVS (`download/Cert.dl`) overrides the patched slot | erase **only** the partition that failed the check: `nvs` → `esptool erase_region 0x9000 0x4000`; `app_cfg` → `esptool erase_region 0x10000 0x2000` (this also wipes the stored WiFi creds, alarms and timezone). Re-run §1 |
| Clock never connects to WiFi | `app_cfg` erased / blank unit | app-free WiFi provisioning is an open item (see README); re-pairing with the vendor app re-installs an AWS cert (re-run §1 afterwards) |
| Broker rejects the client | wrong/missing client cert | clock presents `client.crt`, HA presents `ha.crt`, both signed by your `ca.crt` |
| Connected, but no state / commands ignored | ACL denies the topic | broker log shows `Denied PUBLISH` (add `log_type all` temporarily); CNs must be `AlarmClock` / `home-assistant` as in `mosquitto/acl` |
| Image won't build | a replacement PEM exceeds its slot, or the image differs from the expected layout | `gen_certs.py` already enforces EC sizes; don't hand-edit certs to RSA. A pattern/count/residue error means a different firmware build — re-verify offsets before adapting the script |

---

## Quick reference

```
Device ID     l<MAC>  (serial boot log: client_id=...)
Broker        mqtts://<BROKER_IP>:8883   (mutual TLS, your CA, ACL)
Pre-flight    nvs_parse.py {nvs,app_cfg}.bin --check-certs   (both must pass)
Active slot   from boot log (ota_0 = 0x420000, ota_1 = 0x820000)
Recovery      write_flash 0x0 loftie_full_dump.bin
Build         gen_certs.py  ->  may-firmware-dump/patch_this.py  ->  fw_patched.bin
```
