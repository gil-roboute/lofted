# Loftie Local Control — Full Deployment Guide & Reverse-Engineering Journey

*Single-document compilation for Trilium import. Covers (Part A) how we arrived at patched
firmware as the solution, and (Part B) the complete, current deployment runbook with Mosquitto /
MQTT and Home Assistant.*

> **Goal & guardrail.** Take a Loftie ESP32 alarm clock that I own and point it at **my own MQTT
> broker, with my own certificates on both ends**, so alarms are driven from Home Assistant with
> zero cloud dependence — keeping the stock firmware and its UI. This is local control of my own
> hardware. No cloud service is impersonated, no TLS validation is defeated, nothing is bypassed
> that wasn't paid for. It is also my mitigation for a real security issue in these clocks
> (public report: iank.org/posts/loftie-rce).

> **The dumped unit.** Firmware dumped May 2026 runs `Loftie_EVT` app version `0010_2.4.0` (ESP-IDF v5.1.1). It boots
> from the **`ota_0`** slot at `0x420000`. Examples use `lXXXXXXXXXXXX` for the device ID —
> substitute your own (boot-log `client_id`) and confirm your active slot (B.1).

---

# Part A — How we got to "patched firmware is the solution"

## A.0 The three options, and why #3

It's an ESP32, so three reasonable paths existed:

1. **Write firmware from scratch** — throws away the (genuinely nice) stock UI and alarm UX.
2. **ESPHome** — same problem; a rebuild.
3. **Patch the stock firmware** to talk to my local infrastructure instead of the cloud.

We chose **#3**: keep the pleasant stock interface and behaviour, and only redirect its messaging
and neutralize its cloud callbacks. The rest of Part A is the evidence that made #3 both possible
and *provably within spec*.

## A.1 Hardware access

- Module: **ESP32-WROVER-B** (dual-core Xtensa LX6, 16 MB flash).
- A 5-pin **Molex Picoblade** debug connector sits under the bottom cover (mating P/N Molex
  0151340500). Pinout, left→right (right = closest to the SD connector): **IO0, EN, TXD0, RXD0, GND**.

Wiring the harness:

| ESP32 pin | Connects to |
| --------- | ----------- |
| IO0 | momentary switch → GND (boot select) |
| EN  | momentary switch → GND (reset) |
| TXD0 | USB-serial **RX** |
| RXD0 | USB-serial **TX** |
| GND | USB-serial GND |

Hard-won notes:

- **TX/RX cross over** — device TXD0 (output) → adapter RX; RXD0 → adapter TX. Following the table
  literally already gives the crossover.
- **3.3 V logic only.** A 5 V line on the ESP32 RX can damage the module.
- **IO0 / EN are momentary, not tied low.** EN held low = permanent reset. IO0 is only *sampled at
  reset*: low → serial bootloader; high (default pull-up) → normal boot.
- **The front buttons are app GPIOs**, not IO0/EN — they can't trigger the bootloader. Jumper wires
  to GND work fine.
- **Power from the wall during work.** The WiFi radio's current spikes exceed a typical adapter's
  3.3 V pin → brownout resets. Use wall power, leave the adapter's 3.3 V **disconnected**, keep a
  **common ground**.

**Enter the bootloader:** hold IO0→GND; while holding, tap EN→GND and release (resets the chip);
the ESP32 samples IO0 low out of reset → serial bootloader; release IO0. **Exit:** remove the IO0
jumper, tap EN (or power-cycle).

## A.2 Full flash dump (the golden recovery image)

```bash
esptool.py --chip esp32 --port /dev/ttyUSB0 flash_id                 # confirm 16 MB (connection test)
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 460800 \
    read_flash 0x0 0x1000000 loftie_full_dump.bin                    # 0x1000000 = 16 MB
```

A healthy dump is **exactly 16,777,216 bytes**, has varied content (not mostly `0xFF`), and shows
`0xe9` at offset `0x1000` (second-stage bootloader magic). **Back it up off-machine — it's the
recovery image.** (460800 baud is slow but reliable; a slow good dump beats a fast corrupt one.)

## A.3 Partition table

Table lives at `0x8000`, length `0xC00`. Decoded layout:

| Name | Type | SubType | Offset | Size |
| ---- | ---- | ------- | ------ | ---- |
| nvs | data | nvs | 0x9000 | 16K |
| otadata | data | ota | 0xd000 | 8K |
| phy_init | data | phy | 0xf000 | 4K |
| app_cfg | data | nvs | 0x10000 | 8K |
| factory | app | factory | 0x20000 | 4M |
| ota_0 | app | ota_0 | 0x420000 | 4M |
| ota_1 | app | ota_1 | 0x820000 | 4M |

Gotchas learned here:
- `gen_esp32part.py` (from esp-idf, not standalone esptool) may fail with a **validation** error
  ("NVS must be ≥ 0x3000") — the table is fine, the firmware was built against an older esp-idf.
  Use `--no-verify`, or a zero-dependency 32-byte-entry parser (entries start with magic `0xAA 0x50`).
- `esptool image_info` on a *partition table* errors with "invalid magic 0xaa" — that `0xAA` is the
  partition magic. `image_info` is for **app images** (`0xE9`), not tables.

## A.4 Which slot is live

`otadata` first entry: `05 00 00 00 ...` → little-endian sequence **5**, active slot =
`(seq − 1) % ota_app_count` = `(5 − 1) % 2 = 0` → **`ota_0`**. So the running firmware is
`ota_0.bin` (carve from the *real* offset `0x420000`; verify first byte `0xE9` before trusting it).

## A.5 String analysis — what does it talk to?

A regex sweep of `ota_0.bin` for `https?://`, `mqtt*`, and `*.byloftie.com` revealed the entire
outbound surface. **The clock's control plane is AWS IoT Core over MQTT/TLS** (the Firebase traffic
in the companion app is the *app's* backend — a separate path). Exactly five URLs plus NTP:

| What | Value (file offset) |
| ---- | ------------------- |
| MQTT broker | `mqtts://[REDACTED]-ats.iot.us-east-1.amazonaws.com:8883` (`0x16f10`) |
| OTA firmware | `https://…byloftie.com/Loftie_EVT.bin` (`0x16578`) |
| Asset download (HTTP) | `http://…byloftie.com/sdcard/%s` (`0x1667c`) + https form (`0x1e970`) |
| Timezone-from-IP | `https://pro.ip-api.com/line?key=[REDACTED]&fields=timezone` (`0x174d4`) |
| NTP (benign) | `pool.ntp.org`, `time.google.com`, `time.cloudflare.com` |

A second sweep for topic structure showed a clean three-topic design built at runtime with `%s`
(the device ID): `publish_topic` (state), `subscribe_topic_config`, `subscribe_topic_command`,
plus `client_id=%s`. Standard **ESP-IDF esp-mqtt** client throughout.

## A.6 NVS — the configuration goldmine

`app_cfg` (`0x10000`) is an NVS key-value store. Namespace `storage` holds:

- `key_wifi` (161 B) — WiFi SSID + password, **plaintext** (NVS isn't encrypted by default).
- `key_user_perf` (256 B) — user prefs incl. POSIX timezone (e.g. `CET-1` = UTC+1; POSIX inverts
  the sign).
- `key_app` (28 B) — device serial/identity.
- `key_alarm` (480 B) — **the alarms, stored on-device**.

**The crucial discovery:** alarms live locally in NVS, not only in the cloud. That's what makes a
fully-local control path viable. (Decode alarms with `nvs_parse.py app_cfg.bin --alarms`; NVS blobs
are chunked via index/`blob_data` entries — a naive 32-byte walker misreads them.)

### `key_alarm` encoding (decoded, 30 × 16-byte records)

| byte | field |
| ---- | ----- |
| 0 | hour, 12-hour (1–12) |
| 1 | hour, 24-hour (0–23) |
| 2 | minute (0–59) |
| 3 | bit7 = isSet; bits0–6 = daysOfWeek (**bit0=Sun … bit6=Sat**; 0 = one-time) |
| 4–7 | flag bytes (alarmLight / wake-up / get-up; byte 5 constant `01`) |
| 8–12 | tone folder/file indices (constant `00 01 00 01 09` on this device) |

Verified against the companion-app log ("Rosetta Stone"): record `@0x50` = `07 07 1E BE` → 07:30,
`0xBE`=bit7 set + days `0111110` = Mon–Fri. Exactly the app's weekday alarm (times in this write-up are illustrative).

## A.7 Ghidra: is the broker really just a patchable string, and will my certs be honored?

Loaded `ota_0.bin` into Ghidra as **`Xtensa:LE:32:default`** (entry `0x400818e0`) with the 5-segment
map (use Ghidra ≥ 11's **built-in** Xtensa — it models the windowed ABI; skip the old community
forks). Findings that make the patch **provably within spec**:

- **Broker URI is a single hardcoded literal** at `0x16f10` → vaddr `0x3f416f10`, referenced once by
  the function (`FUN_400f3920`) that assembles `esp_mqtt_client_config_t` and calls
  `esp_mqtt_client_init`:
  ```c
  cfg.broker.address.uri       = "mqtts://…amazonaws.com:8883";  // the string we rewrite
  cfg.broker.verification.cert = CA_slot;                        // 0x3f400c81 — always the trust anchor
  cfg.credentials.auth.cert    = client_cert_slot;              // 0x3f400120
  cfg.credentials.auth.key     = client_key_slot;               // 0x3f4005ed
  ```
  It is **not** in NVS → redirection = "rewrite literal + re-sign". The **CA slot is written
  unconditionally and never overridden** → whatever CA I bake in is *always* the broker trust anchor.
  That's the clean, honest hook.

- **The cert-precedence rabbit hole.** The same function has a branch: if a runtime flag
  (`g_state+0x5c`, `0x3ffc6d40`) is set, it overrides the client cert/key from RAM instead of the
  compiled-in slots. The flag's only writer, `FUN_400f4020`, loads a **provisioned cert from NVS
  keys `download/Cert.dl` / `Key.dl`** (a claim-provisioning pattern) and sets the flag on success.
  **If that were populated, patching the compiled-in slot would do nothing** — the clock would keep
  presenting its old AWS cert and my own-CA broker would reject it. So I carved NVS: it held **only
  WiFi creds, no `download/Cert.dl`**. At dump time this unit held no downloaded cert → it uses the
  compiled-in slot → **patching is sufficient.** (For a previously-paired unit that *did* download
  one, the fix is to erase the NVS partition holding it so the bootstrap slot wins again — B.1
  checks both partitions before every flash.) Finding this *before* flashing
  saved a "valid image, dead handshake" debug session.

- **Command/state schema** (`AWS_receive_config_cb` `FUN_400f3a84` → `IOTGW_Json2State`
  `FUN_400fa850`; state from `IOTGW_State2Json` `FUN_400f9b7c`): device subscribes to **both**
  `/config` and `/commands/#`; inbound data on **either** goes to the **same** flat-JSON parser, and
  the **subtopic is ignored** — the verb is a **key in the JSON body**, not the topic suffix. Scalar
  setters `nightLight`/`nightLightOn`/`volume` handled inline; everything else via `IOTGW_Json2State`.
  Corrected an earlier wrong guess: `snooze`/`dismiss`/`mute`/`unmute` are **string values of
  `alarmControl`**, not their own topics. The `/state` JSON has **no `rssi`** field.

- **Endpoint sweep**: exactly the five URLs above; all five are neutralized by the patcher. Only
  remaining external egress is NTP — benign UDP time-sync, left intact.

## A.8 Minting my own trust (the cert-size trap)

Firmware cert slots are fixed-size: **client cert ≤ 1223 B, client key ≤ 1678 B, CA ≤ 1187 B**.
That CA ceiling is a trap — an **RSA-2048 CA is ~1.2 KB and won't fit**. The fix is **elliptic
curve**: a P-256 cert is ~550 B, a P-256 key ~230 B. `gen_certs.py` mints the whole chain with
Python `cryptography` (no `openssl`), all **EC P-256**, and asserts every PEM fits its slot and the
chain verifies before writing. Mine came out **530 / 546 / 241 bytes** — comfortably inside.

The server cert carries `subjectAltName = IP:<broker>` because the clock dials the broker **by IP**
(Mosquitto on a Portainer host), and an IP needs an IP SAN to validate.

## A.9 The patch, and verifying it independently

`patch_this.py` operates on the carved `ota_0.bin`: it **asserts the original slots really are the
AWS identity** (via `cryptography` → the wrong image aborts), rewrites the broker / OTA / ip-api /
asset strings in place (NUL-padded, length-guarded), drops in the EC chain, then **recomputes the
ESP32 segment checksum and the appended SHA-256 and re-validates them in pure Python** — refusing to
write an invalid image. Clean run:

```
broker URI -> mqtts://192.168.1.50:8883
OK: esp32 segment checksum valid, appended SHA-256 valid, length consistent.
```

Then an **independent** from-scratch pass over `fw_patched.bin` confirmed: broker IP present;
`amazonaws`/`byloftie`/`ip-api`/API key all **gone**; CA + client cert byte-for-byte matching the
generated PEMs; entry `0x400818e0` intact; checksum + SHA-256 + length valid. One scare — a
`BEGIN RSA PRIVATE KEY` string survived — turned out to be mbedTLS's PEM *delimiter constants*, not
a key. Only **0.15 %** of image bytes changed (the strings + three PEM slots).

**Conclusion:** #3 is not only viable, it's verified end-to-end. The broker is one patchable string,
my CA is always honored, the dumped unit had no provisioned-cert override, and the re-signed image
validates. Patched firmware is the solution.

## A.10 Security gaps this closes (defensive summary)

Findings from static analysis of stock `ota_0.bin`, with the local-control mitigation each gets:

| Gap | Severity | Closed by local setup? |
| --- | -------- | ---------------------- |
| **C1** Remote-controlled `otaURL` with no firmware signature (RCE delivery) | Critical | **Yes** — broker lockdown + OTA URL sinkholed to `https://ota.invalid/...` |
| **C2** No secure boot / signing / flash encryption | Critical | No (manufacture-time fuse) — only the *remote* path is removed; treat a stolen/returned unit as compromised |
| **C3** Embedded AWS IoT client cert **and RSA-2048 private key** in cleartext | Critical | **Yes on the patched unit** — all three slots replaced with your own EC material; rotate the *original* AWS cert upstream if you can |
| **H1** Plaintext-HTTP asset download w/ server-controlled filename (MITM / path traversal) | High | **Yes** — asset URLs repointed to `ASSET_HOST` (default `assets.invalid` sinkhole), path kept |
| **H2** Hardcoded ip-api Pro key (`[REDACTED]`) | High | **Yes** — URL/key sinkholed; TZ still works from NVS |
| **M1** WiFi creds plaintext in NVS + echoed to serial log | Medium | No (needs NVS encryption) — mitigate with an **isolated IoT VLAN**, don't share serial output |
| **M2** No app-layer command authz/validation | Medium | **Yes** — the local broker's mutual-TLS + per-identity ACL (`mosquitto/acl`) become the authz gate; keep `restoreToDefault` out of automations |
| **M3** BLE provisioning service stays active (unverified scope) | Medium | Partly — a re-provisioned cert fails closed against your CA; don't re-pair, re-run the NVS check |
| **L1** Residual NTP egress | Low/info | Left intact (benign) — optionally repoint to a LAN NTP server |

> **Cert-precedence caveat (repeat, important for deployment):** the CA slot is always honored, but
> the compiled-in client cert/key are used **only when the `download/Cert.dl` NVS override is
> absent**. The dumped unit had none. Run `nvs_parse.py --check-certs` on both NVS partitions
> before flashing (B.1); if one fails, erase only that partition (B.8). Re-pairing with the vendor
> app pushes a new cert over BLE, so re-check after any re-pair.

---

# Part B — Deployment runbook (current, MQTT / Mosquitto + Home Assistant)

End-to-end steps to take the **already-built, verified** patched firmware and bring the clock up on
your own broker + Home Assistant. The cert generation and image validation are **pure-Python**
(`cryptography`) — no `openssl` needed; `esptool` is needed only for the actual flash.

## B.0 Prerequisites

- **This repo**, plus your own `loftie_full_dump.bin` (the golden recovery image — confirm it is
  16,777,216 bytes) and the active app slot carved to `may-firmware-dump/ota_0.bin`. Dumps are
  gitignored: they contain WiFi credentials and the vendor's device key.
- **Python 3** with the `cryptography` package (used for cert gen + image validation — no `openssl`
  needed). `python3 -c "import cryptography"` should succeed.
- **esptool** — needed only to read/write flash (`pip install esptool`, or run it from an esp-idf
  shell). Not needed to *build* the image.
- **A serial/UART adapter** (3.3 V) wired to the debug header — see Part A.1.
- **A Portainer/Docker host** on the LAN with a **static / DHCP-reserved IP** (Mosquitto will live
  here; that IP gets compiled into the firmware).
- A running **Home Assistant** with the MQTT integration available.

Pick your broker IP now and use it everywhere below as `BROKER_IP`. Example uses `192.168.1.50`.

---

## B.1 Pre-flight checks (do not skip)

Enter the bootloader (hold **IO0→GND**, tap **EN→GND**, release EN, release IO0 — 3.3 V adapter,
clock wall-powered, common ground only) and read the clock's *current* state, not a stale dump:

```bash
esptool --chip esp32 -p /dev/ttyUSB0 read_flash 0x9000  0x4000 nvs.bin       # nvs
esptool --chip esp32 -p /dev/ttyUSB0 read_flash 0x10000 0x2000 app_cfg.bin   # app_cfg
python3 may-firmware-dump/nvs_parse.py nvs.bin     --check-certs
python3 may-firmware-dump/nvs_parse.py app_cfg.bin --check-certs
```

Both must print `CHECK OK`. A provisioned cert (`download/Cert.dl` / `Key.dl`) is presented
**instead of** the patched client cert, and your broker will reject it (see B.8 for the fix). Pairing
with the vendor app writes a fresh cert + key to the clock over BLE, so re-check after any re-pair.

**Confirm the active slot.** A normal boot prints `Loaded app from partition at offset 0x…`. The
offset you flash in B.5 must match it, and `ota_0.bin` must be carved from *that* slot of a dump
taken *after* the clock's last OTA update. `patch_this.py` refuses to run if the image layout
differs from the one it was written for.

---

## B.2 Generate your TLS chain

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

## B.3 Build the patched firmware

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

## B.4 Stand up Mosquitto on Portainer

The broker config, ACL and compose are in `mosquitto/`.

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

## B.5 Flash the clock

1. Enter the bootloader as in B.1.
2. Flash the **active** slot you confirmed in B.1 (`ota_0` = `0x420000`, `ota_1` = `0x820000`):
   ```bash
   esptool --chip esp32 -p /dev/ttyUSB0 write_flash 0x420000 fw_patched.bin
   ```
3. Leave both NVS partitions alone unless B.1 flagged one (see B.8). The clock's WiFi credentials
   live in `app_cfg` (`0x10000`).

**Recovery** (anytime): `esptool --chip esp32 -p /dev/ttyUSB0 write_flash 0x0 loftie_full_dump.bin`.

---

## B.6 First boot — confirm the handshake

Watch the serial log. You want:

- `Loaded app from partition at offset 0x…` matching the slot you flashed,
- the clock rejoins your WiFi,
- the MQTT TLS handshake to your broker **succeeds** — i.e. **no** `mbedtls_ssl_handshake
  returned -0x...`,
- it prints `client_id=l<MAC>` and publishes to `/devices/l<MAC>/state`.

Your `mosquitto_sub` from B.4 should start showing state JSON.

---

## B.7 Home Assistant

1. Point the HA **MQTT integration** at `192.168.1.50:8883` with `ca.crt` + `ha.crt` + `ha.key`
   (mutual TLS).
2. Load `home-assistant/loftie.yaml` as a package; replace every `lXXXXXXXXXXXX` with your device
   ID.
3. You get sensors (battery, charging, plugged-in, volume, night-light) and scripts
   (volume, night-light, snooze, dismiss, restart) plus an alarm-sync automation.

Set an alarm to confirm the round trip, then re-read `app_cfg` (B.1) and run
`python3 may-firmware-dump/nvs_parse.py app_cfg.bin --alarms` to confirm persistence.

---

## B.8 Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `mbedtls_ssl_handshake returned -0x2700` (cert verify) | broker server cert SAN ≠ the IP the clock dials | regenerate `server.crt` with the right `BROKER_IP` (B.2), redeploy broker |
| `--check-certs` fails, or the handshake fails on a previously-paired unit | provisioned cert in NVS (`download/Cert.dl`) overrides the patched slot | erase **only** the partition that failed the check: `nvs` → `esptool erase_region 0x9000 0x4000`; `app_cfg` → `esptool erase_region 0x10000 0x2000` (this also wipes the stored WiFi creds, alarms and timezone). Re-run B.1 |
| Clock never connects to WiFi | `app_cfg` erased / blank unit | app-free WiFi provisioning is an open item (see README); re-pairing with the vendor app re-installs an AWS cert (re-run B.1 afterwards) |
| Broker rejects the client | wrong/missing client cert | clock presents `client.crt`, HA presents `ha.crt`, both signed by your `ca.crt` |
| Connected, but no state / commands ignored | ACL denies the topic | broker log shows `Denied PUBLISH` (add `log_type all` temporarily); CNs must be `AlarmClock` / `home-assistant` as in `mosquitto/acl` |
| Image won't build | a replacement PEM exceeds its slot, or the image differs from the expected layout | `gen_certs.py` already enforces EC sizes; don't hand-edit certs to RSA. A pattern/count/residue error means a different firmware build — re-verify offsets before adapting the script |

---

# Part C — MQTT command & config reference

Drive the clock from the local broker / HA once repointed. All examples assume mutual TLS.

```bash
ID=lXXXXXXXXXXXX         # boot-log client_id / device MAC
H=192.168.1.50           # broker host IP (the patched mqtts:// target)
TLS="--cafile certs/ca.crt --cert certs/ha.crt --key certs/ha.key -p 8883"   # HA identity (ACL)
```

## Topic model

| Direction | Topic | Purpose |
| --------- | ----- | ------- |
| device → broker | `/devices/<id>/state` | telemetry / state report |
| broker → device | `/devices/<id>/config` | configuration (alarms, settings) |
| broker → device | `/devices/<id>/commands/#` | commands (wildcard) |

The device subscribes to **both** `/config` and `/commands/#`; inbound data on either goes to the
**same flat-JSON parser** — **subtopic ignored**, the verb is a **key in the JSON body**. So
`{"volume":7}` works published to `/config` *or* `/commands/anything`. We publish to
`/commands/<verb>` only for human readability.

## Set an alarm (config topic — proven end-to-end)

```bash
mosquitto_pub -h $H -t "/devices/$ID/config" $TLS -m '{"alarms":[{
  "alarmLight":false,"daysOfWeek":127,"getUpToneFileIdx":0,"isSet":true,
  "time":"10:00am","toneFolderIdx":0,"type":"alarm","volume":3,
  "wakeUpToneFileIdx":0,"getUpToneFolderIdx":0,"wakeUpToneFolderIdx":0}]}'
```

`daysOfWeek` is a bitmask, **bit0=Sun … bit6=Sat** (127 = every day, 62 = Mon–Fri). After
publishing, re-dump `app_cfg` and run `nvs_parse.py --alarms` to confirm it persisted into
`key_alarm`.

## Command verbs (proven by decompilation)

All verbs are **top-level keys in one flat JSON object**. Combine multiple keys in one publish.

| Verb / key | Payload | Notes |
| ---------- | ------- | ----- |
| `volume` | `{"volume": 3}` | scalar, inline; must be a number |
| `nightLight` | `{"nightLight": 6}` | scalar, inline; brightness level |
| `nightLightOn` | `{"nightLightOn": true}` | scalar, inline; bool |
| `alarmControl` | `{"alarmControl":"snooze"}` | string value: `snooze`/`dismiss`/`mute`/`unmute` |
| `remoteAudios` | `{"remoteAudios":{"folderIdx":0,"fileIdx":0,"<op>":"play"｜"stop"}}` | nested; select + play/stop |
| `setTime` | `{"setTime":"…"}` | string; parsed by `sscanf` (year−1900, month−1 internally) |
| `setTimeZone` | `{"setTimeZone":"<POSIX TZ>"}` | e.g. `CET-1CEST,M3.5.0,M10.5.0/3` |
| `timeZone` | `{"timeZone":"<3 bytes>"}` | raw TZ id bytes |
| `24HourMode` | `{"24HourMode": true}` | bool |
| `sleepTimerMins` | `{"sleepTimerMins": 30}` | number |
| `guiColorIdx` | `{"guiColorIdx": 0}` | 0,1 or 255 (custom → `guiColorCutomHex0..3`) |
| `restart` | `{"restart":1}` | reboot (value must be 1) |
| `restoreToDefault` | `{"restoreToDefault":1}` | ⚠ **factory reset (destructive)** |
| `alarms` | `{"alarms":[ {…} ]}` | array; see above |
| `alarmSettings` | `{"alarmSettings":{…}}` | nested (volume, alarmLight, snoozeTime, wakeUp*, getUp*) |
| `bedSignals` | `{"bedSignals":[ {"time":…,"isSet":…,"routines":[…]} ]}` | array |

**Excluded on purpose — do NOT wire to automations:** `otaURL` (`0x1dc14`) + `md5sum` (`0x1dc00`),
`remotelog` (`0x1dc08`) — the remote-OTA / log-exfil surface (Part A.10 C1). With the firmware
repointed only *you* can publish them, but there's no reason to expose them.

Examples:
```bash
mosquitto_pub -h $H -t "/devices/$ID/commands/volume"       $TLS -m '{"volume":3}'
mosquitto_pub -h $H -t "/devices/$ID/commands/alarmControl" $TLS -m '{"alarmControl":"dismiss"}'
```

## State topic (telemetry for HA)

`/devices/<id>/state` carries: `upTime`, `Ver`, `pluggedIn`, `BattCharge`, `battery`, `volume`,
`nightLight`, `nightLightOn`, `screenBrightness`, `24HourMode`, `sleepTimerMins`, `AP_MAC`, `MAC`,
`serialNumber`, `certVer`, `timeZone`/`timeZoneString`, `guiColorIdx`/`guiColorCutomHex0..3`,
`isAlarmMute`, SD-card status, `pairingCode*`, `beacon*`, `playlistInfos{}`, `audioPlayer{}`,
`bedSignals[]`, `alarms[]`, `alarmSettings{}`, `alarmLogs[]`, plus `feature*` flags. **No `rssi`** —
don't build a WiFi-signal sensor.

---

# Part D — Repo map & tooling

| Path | What |
| ---- | ---- |
| `gen_certs.py` | mint the EC P-256 CA/clock/HA/server chain, slot-size + chain asserted (pure Python) |
| `may-firmware-dump/patch_this.py` | patch + re-sign + validate `ota_0.bin` → `fw_patched.bin` |
| `may-firmware-dump/nvs_parse.py` | decode NVS / `--alarms` / `--check-certs` pre-flash gate |
| `may-firmware-dump/ota_0.bin` | carved active app image (analysis + patch input; yours, gitignored) |
| `loftie_full_dump.bin` | 16 MB golden recovery image (yours, gitignored) |
| `mosquitto/` | broker `mosquitto.conf` + `acl` + `docker-compose.yml` (Portainer stack) |
| `home-assistant/loftie.yaml` | HA MQTT package (sensors + scripts + alarm-sync) |
| `docs/` | `deployment-runbook.md`, `mqtt-command-reference.md`, `security-gaps.md`, `ghidra-import.md` |
| `device-id.local.md` | your device ID (gitignored) |

**Tooling:** esptool (flash only); `gen_esp32part.py` from esp-idf (or the self-contained parser);
Python 3 + `cryptography` (analysis, NVS extraction, TLS chain + image (re)validation — no
`openssl`); Ghidra ≥ 11 with **built-in Xtensa** (windowed ABI — skip community forks).
Environment: Bluefin (Universal Blue, immutable) — use `distrobox`/`brew`, don't touch the atomic base.

## Quick reference

```
Device ID     l<MAC>  (serial boot log: client_id=...)
Broker        mqtts://<BROKER_IP>:8883   (mutual TLS, your CA, ACL)
Pre-flight    nvs_parse.py {nvs,app_cfg}.bin --check-certs   (both must pass)
Active slot   from boot log (ota_0 = 0x420000, ota_1 = 0x820000)
Build         gen_certs.py  ->  may-firmware-dump/patch_this.py  ->  fw_patched.bin
Flash         esptool --chip esp32 -p /dev/ttyUSB0 write_flash 0x420000 fw_patched.bin
Recovery      esptool --chip esp32 -p /dev/ttyUSB0 write_flash 0x0 loftie_full_dump.bin
```

## Open items

- **WiFi without the vendor app** — pairing used BLE. Keeping `app_cfg` preserves the clock's network;
  a blank unit / new SSID needs an `nvs.net80211` image or a small firmware change. Not solved.
- **Secure boot / flash encryption** — manufacture-time fuse, not patchable. Physical flash access
  remains exposed; treat a returned/stolen unit as compromised.
- **NTP** — benign; optionally repoint to a LAN NTP server for a fully self-contained setup.
</content>
</invoke>
