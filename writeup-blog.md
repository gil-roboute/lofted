# Liberating a Loftie Clock: A Firmware Teardown and Local-Control Journey

*Reverse-engineering an ESP32-based smart alarm clock to free it from the cloud —
documenting the full process from debug header to firmware analysis.*

> **Ethics note up front:** This is about local control of a device I own. The goal is to
> point the clock at my own MQTT broker using my own certificates on both ends — not to
> impersonate any cloud service, defeat TLS validation, or bypass anything I haven't paid for.
> Everything below stays on the right side of that line.
>
> **Redaction note:** Device-specific secrets (WiFi credentials, device serial, account-specific
> cloud endpoints, and an embedded API key) have been replaced with `[REDACTED]` placeholders.
> If you do this on your own unit, those values will be unique to you — treat them as secrets.

## Background

The Loftie clock is a well-designed smart alarm clock. The hardware and on-device UX are
genuinely nice — but the alarm scheduling and configuration lean on cloud services. The aim of
this project: keep the stock firmware and its pleasant interface, but redirect its messaging to
a local broker so I can drive alarms from Home Assistant with zero cloud dependence.

This write-up covers the reverse-engineering process: hardware access, full flash dump,
partition analysis, active-slot identification, string analysis of the live firmware, and NVS
configuration extraction.

## The hardware

Cracking the bottom cover reveals the brains: an **ESP32-WROVER-B** module — the dual-core
Tensilica Xtensa LX6, 16 MB of flash. The ESP32 is one of the most thoroughly documented IoT
targets in existence, which makes this kind of work approachable.

There's a 5-pin **Molex Picoblade** debug connector on the board (mating part Molex 0151340500).
Pinout, left to right (right being closest to the SD connector):

| Position | Signal |
|----------|--------|
| left     | IO0    |
|          | EN     |
|          | TXD0   |
|          | RXD0   |
| right    | GND    |

### Wiring the harness

| ESP32 pin | Connects to |
|-----------|-------------|
| IO0       | momentary to GND (boot select) |
| EN        | momentary to GND (reset) |
| TXD0      | USB-serial RX |
| RXD0      | USB-serial TX |
| GND       | USB-serial GND |

A few hard-won notes:

- **TX/RX cross over.** The device's TXD0 (an output) goes to your adapter's RX (an input), and
  RXD0 goes to your adapter's TX. Never TX→TX. The pin labels are named from each device's own
  perspective, so following the table literally already gives you the crossover.
- **3.3V logic only.** A 5V FTDI on the ESP32's RX line can damage the module. Check for a jumper
  or use a 3.3V variant.
- **IO0 and EN are momentary, not tied to ground.** EN held low = permanent reset (dead chip).
  IO0 is only *sampled at reset* — low means "enter serial bootloader," high (default, internal
  pull-up) means "boot normally."
- **No momentary switches?** Jumper wires to GND work fine. The onboard buttons are NOT wired to
  IO0/EN — they're application GPIOs — so they can't trigger the bootloader.
- **Power from the wall during work.** The WROVER's WiFi radio draws current spikes well beyond
  what a typical USB-serial adapter's 3.3V pin can supply, causing brownout resets. Use wall power
  and leave the adapter's 3.3V disconnected — but keep the common GND. Single supply on the rail,
  shared ground for signals.

### Entering and exiting the bootloader

Entry (the timing dance):
1. Hold IO0 to GND.
2. While holding, tap EN to GND and release (this resets the chip).
3. The ESP32 samples IO0 low coming out of reset → enters serial bootloader.
4. Release IO0. esptool can now talk to it.

Exit: remove the IO0 jumper, tap EN to GND once (or power-cycle). Bootloader mode isn't a sticky
state — it's just "IO0 was low at reset." Remove that condition and reset, and the clock boots
normally.

## Dumping the flash

First, confirm the chip and flash size — this doubles as a connection test:

```bash
esptool.py --chip esp32 --port /dev/ttyUSB0 flash_id
```

This reported **16 MB**. Now dump the entire flash:

```bash
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 460800 \
    read_flash 0x0 0x1000000 loftie_full_dump.bin
```

`0x1000000` = 16 MB. At 460800 baud the full dump takes several minutes; 921600 is faster but more
error-prone — a slow successful dump beats a fast corrupted one, and this is your recovery image.

Verify it completed cleanly:

```bash
ls -l loftie_full_dump.bin   # expect exactly 16777216 bytes

python3 -c "
d=open('loftie_full_dump.bin','rb').read()
print('size', len(d))
print('0xFF bytes', d.count(0xff))
print('0x00 bytes', d.count(0x00))
print('byte @ 0x1000 (bootloader magic):', hex(d[0x1000]))
"
```

A healthy dump is exactly 16777216 bytes, has varied content (not mostly 0xFF), and shows `0xe9`
at offset 0x1000 (the second-stage bootloader's image magic). **Back this file up off-machine** —
it's the golden restore image.

## Reading the partition table

The partition table lives at offset `0x8000`, length `0xC00`. Carve it:

```bash
dd if=loftie_full_dump.bin of=partitions.bin bs=1 skip=$((0x8000)) count=$((0xC00))
```

The standard decoder is `gen_esp32part.py`, which ships with esp-idf (NOT with standalone esptool).
Fetch it if needed:

```bash
curl -O https://raw.githubusercontent.com/espressif/esp-idf/master/components/partition_table/gen_esp32part.py
python3 gen_esp32part.py partitions.bin
```

### Gotcha: the validator vs the data

On a current `master` version of the tool, conversion failed with:
Partition app_cfg invalid: 'app_cfg' partition of type 1 and subtype 2 of this size (0x2000)
must be flagged as 'readonly' (the size of read/write NVS has to be at least 0x3000)

This is a *validation* error, not a parse failure — the table is fine, but the firmware was built
against an older esp-idf that didn't enforce the newer "NVS must be ≥ 0x3000" rule. Two ways past it:

```bash
python3 gen_esp32part.py --no-verify partitions.bin partitions.csv
```

…or just use a zero-dependency parser (below), which does no validation.

### Gotcha: image_info is the wrong tool for a partition table

Pointing `esptool image_info` at the partition table gives:
A fatal error occurred: This is not a valid image (invalid magic number: 0xaa)

That `0xAA` is actually the partition-entry magic (`0xAA 0x50`) — confirmation the bytes are a
*valid partition table*. `image_info` expects an app image (magic `0xE9`), not a partition table.
Right tool, wrong file. Use `gen_esp32part.py` for tables; save `image_info` for app images.

### A self-contained partition parser

Useful on immutable distros where installing esp-idf tooling is a pain:

```python
import struct, sys

TYPES = {0x00: "app", 0x01: "data"}
APP_SUB = {0x00: "factory", 0x20: "test",
           **{0x10 + i: f"ota_{i}" for i in range(16)}}
DATA_SUB = {0x00: "ota", 0x01: "phy", 0x02: "nvs", 0x03: "coredump",
            0x04: "nvs_keys", 0x05: "efuse", 0x06: "undefined",
            0x80: "esphttpd", 0x81: "fat", 0x82: "spiffs", 0x83: "littlefs"}

data = open(sys.argv[1], "rb").read()
print(f"{'name':16} {'type':5} {'subtype':10} {'offset':>10} {'size':>10}")
for i in range(0, len(data), 32):
    entry = data[i:i+32]
    if entry[:2] != b"\xaa\x50":
        break
    ptype, subtype = entry[2], entry[3]
    offset, size = struct.unpack("<II", entry[4:12])
    label = entry[12:28].rstrip(b"\x00").decode("ascii", "replace")
    tname = TYPES.get(ptype, hex(ptype))
    sub = (APP_SUB if ptype == 0x00 else DATA_SUB).get(subtype, hex(subtype))
    print(f"{label:16} {tname:5} {sub:10} {offset:#10x} {size:#10x}")
```

### The layout

| Name     | Type | SubType | Offset    | Size |
|----------|------|---------|-----------|------|
| nvs      | data | nvs     | 0x9000    | 16K  |
| otadata  | data | ota     | 0xd000    | 8K   |
| phy_init | data | phy     | 0xf000    | 4K   |
| app_cfg  | data | nvs     | 0x10000   | 8K   |
| factory  | app  | factory | 0x20000   | 4M   |
| ota_0    | app  | ota_0   | 0x420000  | 4M   |
| ota_1    | app  | ota_1   | 0x820000  | 4M   |

Three app partitions: a `factory` image plus two OTA slots that updates swap between.

## Finding the active firmware slot

OTA-capable devices track which slot is live in the `otadata` partition. Read its first entry:

```bash
python3 -c "
d=open('loftie_full_dump.bin','rb').read()[0xd000:0xd000+0x2000]
print('otadata first 32 bytes:', d[:32].hex())
"
# -> 05000000ffffffff............[device-specific CRC]
```

Decoding: the first 4 bytes are a little-endian sequence number (`05000000` = **5**), and the
trailing 4 bytes are its CRC32. The active slot is `(sequence - 1) % ota_app_count`. With two OTA
slots:
(5 - 1) % 2 = 0  → ota_0 is active

So the running, post-July-update firmware lives in **ota_0**.

## Carving the app partitions

```bash
python3 -c "
d=open('loftie_full_dump.bin','rb').read()
for name,off,size in [('factory',0x20000,0x400000),
                       ('ota_0',0x420000,0x400000),
                       ('ota_1',0x820000,0x400000)]:
    open(name+'.bin','wb').write(d[off:off+size])
    tag = 'valid app image' if d[off]==0xE9 else 'empty/not-app'
    print(f'{name}: first byte {hex(d[off])}  ({tag})')
"
```

All three populated slots start with `0xE9` — valid app images. `ota_0.bin` is our analysis target.

> **Lesson learned:** my first carve attempt used guessed offsets (`0x10000` for the app) and
> produced "invalid magic" errors. `0x10000` is actually the `app_cfg` NVS partition. Always carve
> from the *real* offsets in your parsed partition table — verify the first byte is `0xE9` before
> trusting a carve.

## String analysis: what does the firmware talk to?

A targeted regex sweep of the app image for endpoints and protocol markers:

```python
import re
d=open('ota_0.bin','rb').read()
for pat in (rb'https?://[ -~]{6,}',
            rb'[a-z0-9.-]+\.googleapis\.com',
            rb'mqtt[ -~]*',
            rb'[a-z0-9.-]+\.byloftie\.com'):
    for m in re.finditer(pat, d):
        s=m.group().decode('ascii','replace')
        if len(s)<200:
            print(hex(m.start()), s)
```

Key findings (sensitive host/key values redacted):

- **The device's control plane is AWS IoT Core, not Firebase.** The firmware contains an AWS IoT
  ATS endpoint of the form `mqtts://[REDACTED]-ats.iot.us-east-1.amazonaws.com:8883` — MQTT over
  TLS. (The Firebase traffic visible in the companion app's logs is the *app's* backend; the
  *clock* speaks MQTT to AWS IoT. Two separate paths.)
- OTA firmware URL: `https://[REDACTED].byloftie.com/Loftie_EVT.bin` (EVT = engineering validation
  test hardware tag; the subdomain is an infra hostname).
- Asset/sound downloads: `https://[REDACTED].byloftie.com/sdcard/%s`.
- Timezone-from-IP lookup: `https://pro.ip-api.com/line?key=[REDACTED]&fields=timezone` (note: the
  firmware embeds an API key here — redacted).
- The MQTT function/log strings (`mqtt_client_set_uri`, `mqtt_set_config`, and related esp-mqtt
  names) confirm the standard **ESP-IDF esp-mqtt** client.

A second sweep for the topic structure:

```python
import re
d=open('ota_0.bin','rb').read()
for pat in (rb'client_id=%s', rb'[a-z_]*topic[ -~]{0,60}'):
    for m in re.finditer(pat, d):
        print(hex(m.start()), m.group().decode('ascii','replace'))
```

This revealed a clean three-topic design (strings built at runtime with `%s`, almost certainly
incorporating the device ID):

- `publish_topic:%s` — device → broker (state/telemetry)
- `subscribe_topic_config:%s` — broker → device (configuration)
- `subscribe_topic_command:%s` — broker → device (commands)
- `client_id=%s` — the MQTT client identifier

That `subscribe_topic_command` is the channel a broker uses to tell the clock to do things — the
natural place to send alarm set/unset commands.

## NVS: the configuration goldmine

The `app_cfg` partition is an NVS (non-volatile storage) key-value store. Carve and scan it:

```bash
python3 -c "
d=open('loftie_full_dump.bin','rb').read()[0x10000:0x10000+0x2000]
open('app_cfg.bin','wb').write(d)
import re
for m in re.finditer(rb'[ -~]{4,}', d):
    print(hex(m.start()), m.group().decode('ascii','replace'))
"
```

The NVS keys (namespace 1) tell the story (values redacted):

- `key_wifi` — WiFi credentials, stored in plaintext (SSID + password `[REDACTED]`). Worth
  internalizing: **NVS is not encrypted by default**, so anyone with a flash dump has your WiFi
  password. A good argument for NVS encryption on shipping products.
- `key_app` — device identity/serial (`[REDACTED]`).
- `key_user_perf` — user preferences, including the POSIX timezone string (e.g. `CET-1`, which is
  UTC+1 — note POSIX's inverted sign convention).
- `key_alarm` — **the alarms, stored locally as 480-byte blobs, ~10 slots**.

This is the crucial discovery: **the clock keeps its alarm configuration on-device in NVS**, not
solely in the cloud. That opens a fully-local control path.

### NVS structure note

NVS is a structured format — 4096-byte pages, each with a 32-byte header followed by 32-byte
entries (namespace, type, span, chunk index, CRC32, 16-byte key, 8 bytes of value-or-metadata).
Large values like the 480-byte alarm blobs aren't inline; they're stored as a `blob_idx` entry
plus separate chunked `blob_data` entries that must be reassembled by chunk index.

A naive 32-byte-entry walker will misread the blob payload regions as bogus entries (I hit exactly
this — phantom repeating entries that were really blob bytes being misinterpreted as headers). The
correct approach reassembles blobs via the index/chunk metadata, or uses esp-idf's own NVS tooling.
That decode is the next phase of the project.

## Loading the firmware into Ghidra

The ESP32 is **Xtensa**, little-endian, 32-bit. In Ghidra's language picker that's
`Xtensa:LE:32:default`.

Two caveats:

1. **Stock Ghidra's Xtensa support is limited.** You'll likely need a community Xtensa processor
   module (search "ghidra xtensa esp32"); some bundles also include an ESP32 firmware loader that
   auto-maps segments.
2. **Don't load the raw 16 MB blob.** Load the carved *app* image (`ota_0.bin`). Its `0xE9` header
   describes segments with individual load addresses. Get them with:

```bash
   esptool.py --chip esp32 image_info ota_0.bin
```

   (This is the correct use of `image_info` — on an app image, not a partition table.) Typical
   ESP32 mappings: IROM ~`0x400d0000` (flash-resident code), IRAM ~`0x40080000`, DROM ~`0x3f400000`
   (read-only data and strings — where the endpoint URLs live), DRAM ~`0x3ffb0000`. Recreate those
   memory blocks in Ghidra (or let the loader extension do it), set the entry point, and analyze.

## Where this leaves us

The picture is now clear enough to plan the clean local-control path:

- The clock's control plane is plain MQTT pub/sub via the standard esp-mqtt client, with the broker
  URI set at runtime.
- Alarms persist locally in NVS as decodable `key_alarm` blobs.
- The honest objective — keep stock firmware, point it at my own broker with my own certs on both
  ends — is well-supported by this architecture.

Three questions remained: *what exactly is the alarm format*, *is the broker really just a patchable
string*, and *will swapping the certs actually be honored at runtime*. The rest of this post answers
all three, then builds and verifies the real firmware.

## Cracking the alarm encoding

The companion app log was a Rosetta Stone. It listed this clock's alarms in plain language (e.g.
`7:30am / Mon–Fri (set)`, `8:30am / Sat` — real times changed here for privacy), while the NVS
`key_alarm` blob held 30 × 16-byte records. Lining the two up, the layout fell out fast:

| byte | meaning |
| ---- | ------- |
| 0 | hour (12-hour, 1–12) |
| 1 | hour (24-hour, 0–23) |
| 2 | minute |
| 3 | bit7 = isSet; bits0–6 = daysOfWeek (**bit0=Sun … bit6=Sat**) |
| 4–7 | flag bytes (alarmLight / wake / get-up; byte 5 constant `01`) |
| 8–12 | tone folder/file indices |

Record `@0x50` read `07 07 1E BE` (illustrative values): 07:30, and `0xBE = 1011_1110` → bit7 set (isSet) with days
`0111110` = Mon–Fri. Exactly the weekday alarm from the app. `nvs_parse.py --alarms` now
decodes the whole blob, and it round-trips against what Home Assistant later writes back.

## Into Ghidra: is the broker really just a string?

The broker URI `mqtts://[REDACTED]-ats.iot.us-east-1.amazonaws.com:8883` sat at file `0x16f10`.
Loaded into Ghidra with the five-segment map (`Xtensa:LE:32:default`, entry `0x400818e0`), it
resolved to vaddr `0x3f416f10` — and a cross-reference led straight to one function that assembled an
`esp_mqtt_client_config_t` (the 0xA8-byte struct esp-idf v5.1 uses) and handed it to
`esp_mqtt_client_init`:

```c
cfg.broker.address.uri        = "mqtts://...amazonaws.com:8883";  // <- our string
cfg.broker.verification.cert  = CA_slot;                          // 0x3f400c81
cfg.credentials.auth.cert     = client_cert_slot;                 // 0x3f400120
cfg.credentials.auth.key      = client_key_slot;                  // 0x3f4005ed
```

So redirection really is "rewrite the literal and re-sign" — no NVS option, but no obfuscation
either. Better still, the CA slot is written *unconditionally* and never overridden: whatever CA I
bake in is *always* the broker trust anchor. That's the clean, honest hook — point the device at my
own broker and have it verify my own CA.

## The rabbit hole: which cert does it *actually* use?

The same function had a branch I almost skimmed past:

```c
if (*(byte*)(g_state + 0x5c) == 1) {           // a runtime flag
    // override client cert/key from a RAM buffer instead of the compiled-in slots
}
```

Following the flag's only writer led to `FUN_400f4020`, which loads certificates from **NVS keys
`download/Cert.dl` / `Key.dl`** and, on success, sets that flag. This is a *claim-provisioning*
pattern: the cert compiled into the image is a bootstrap identity, and a paired device downloads a
per-device operational cert into NVS — which then takes precedence. If that were populated, swapping
the compiled-in slot would do nothing; the clock would keep presenting its old AWS cert, and my
own-CA broker would reject it.

So I carved the NVS partition out of the full dump and looked. It held WiFi credentials and nothing
else — **no `download/Cert.dl`**. Every certificate and key in the entire 16 MB image lives inside
the app partitions; the config partitions carry zero PEM data. At dump time this unit held no
downloaded cert, so it uses the compiled-in slot, and patching it is sufficient. That can change —
re-pairing with the vendor app pushes a fresh cert + key over BLE — so `nvs_parse.py --check-certs`
now gates every flash, run against *both* NVS partitions; if one fails, erase that partition and the
bootstrap slot wins again. Finding that branch *before* flashing saved a baffling
"valid image, dead handshake" debugging session.

## The command surface, decoded

The MQTT data callback (`AWS_receive_config_cb`) reassembles each message, `cJSON_Parse`s it, handles
three scalar setters inline (`nightLight`, `nightLightOn`, `volume` via a small handler table), then
passes the *same* object to `IOTGW_Json2State`, a flat parser that walks a long list of keys:
`alarms[]`, `alarmSettings{}`, `alarmControl` (a **string**: `snooze`/`dismiss`/`mute`/`unmute`),
`setTime`, `setTimeZone`, `restart`, `restoreToDefault`, `remoteAudios{}`, `bedSignals[]`, and more.

The event handler showed the clock subscribes to **both** `/devices/<id>/config` *and*
`/devices/<id>/commands/#`, and — the detail that fixes the Home Assistant wiring — inbound data on
either topic goes to the same parser with the **subtopic ignored**. The verb has to be a *key inside
the JSON body*, not the topic suffix. So `{"volume":7}` works published anywhere the device is
subscribed. (My earlier guess that `snooze`/`dismiss` were their own topics was wrong; they're string
*values* of `alarmControl`.) The state publisher, `IOTGW_State2Json`, enumerated the telemetry keys —
and notably has **no `rssi`** field, so I dropped that phantom sensor from the HA package.

## Closing every door: the endpoint sweep

Before trusting "it only talks to my LAN now", I enumerated every `://`, `mqtt`, and bare-hostname
literal in the image. Exactly five URLs: the broker, the OTA `.bin`, two `byloftie` asset URLs, and
the ip-api timezone call (which leaks a hardcoded Pro API key). The patcher neutralizes all five. The
only remaining outbound destinations are NTP servers (`pool.ntp.org`, `time.google/cloudflare.com`) —
unauthenticated time sync, not a control or exfil channel, so I left them (with a note on how to
repoint them to a LAN NTP server if you want zero internet).

## Minting my own trust

The firmware's cert slots are fixed-size: client cert ≤1223 B, client key ≤1678 B, CA ≤**1187 B**.
That CA ceiling is a trap — an RSA-2048 CA certificate is ~1.2 KB and *won't fit*. The fix is
elliptic curve: a P-256 cert is ~550 B. `gen_certs.py` mints the whole chain with `cryptography`
(no `openssl` needed), all EC P-256:

- a small CA → trust anchor, into the firmware **and** onto the broker,
- a client cert/key (`CN=AlarmClock`) → into the firmware,
- a second client cert/key (`CN=home-assistant`) → for Home Assistant,
- a server cert carrying `subjectAltName = IP:<broker>` → onto the broker, because the clock dials
  the broker by **IP** (Mosquitto on a Portainer host), and an IP needs an IP SAN to validate.

The script asserts every PEM fits its slot and that the chain verifies before writing anything. Mine
came out 530 / 546 / 241 bytes — comfortably inside every slot.

## The patch, in Python all the way down

`patch_this.py` does the surgery on the carved `ota_0.bin`: it asserts the original slots really are
the AWS identity (via `cryptography`, so the wrong image aborts the run), rewrites the broker / OTA /
ip-api / asset strings in place (NUL-padded, length-guarded), drops in my EC chain, then recomputes
the ESP32 segment checksum and the appended SHA-256 and **re-validates them in pure Python**. With no
`openssl` or `esptool` on this machine, making the build self-contained turned a missing-dependency
problem into a more robust tool — esptool, if present, is only an optional cross-check.

```
broker URI -> mqtts://192.168.1.50:8883
OK: esp32 segment checksum valid, appended SHA-256 valid, length consistent.
```

## Did it actually work?

Trust, but verify — independently of the script that made the file. A from-scratch pass over
`fw_patched.bin` confirmed: the broker IP present, `amazonaws`/`byloftie`/`ip-api`/the API key all
**gone**, my CA and client cert byte-for-byte matching the generated PEMs, entry point `0x400818e0`
intact, and checksum + SHA-256 + length all valid. One scare: a `BEGIN RSA PRIVATE KEY` string
survived. For a minute that looked like a second embedded key I'd missed — until I dumped the region
and found mbedTLS's PEM *delimiter constants* (`-----BEGIN/END RSA/EC/PRIVATE KEY-----`), the literal
strings its parser matches against. Not a key. The only real private key, the AWS RSA one, was fully
overwritten by my EC key. Only 0.15% of the image bytes changed — exactly the strings and three PEM
slots.

## Standing it up

A Mosquitto stack (`mosquitto/`, deployable straight into Portainer) enforces mutual TLS on 8883:
no anonymous clients, every connection must present a cert signed by my CA. The clock and Home
Assistant each have their own cert, and the cert CN doubles as the broker username for an ACL: the
clock may only read its command topics and publish state, only Home Assistant may send commands
(including the dangerous ones like `otaURL`), and any other cert gets nothing. The HA package wires battery / charging /
plugged-in / volume / night-light sensors and volume / night-light / snooze / dismiss / restart
scripts, plus an alarm-sync automation — all publishing flat JSON objects, exactly as the firmware
expects.

## What's left

- **WiFi without the vendor app.** Pairing used Loftie's app over BLE. Keeping the `app_cfg` partition
  preserves the network *this* clock already joined, so it needs no app — but provisioning a *blank*
  unit, or moving to a new SSID, isn't solved yet (it needs an `nvs.net80211` image or a small
  firmware change). A clean follow-up.
- **Secure boot / flash encryption.** Still absent — that's a manufacture-time fuse, not something a
  patch can add. The local-broker lockdown removes the *remote* attack path; physical flash access
  remains exposed, so a returned or stolen unit should be treated as compromised.
- **NTP.** Benign, but repointable to a LAN server for a fully self-contained setup.

The clock is now mine end to end: my broker, my certs, my Home Assistant — stock UI and behavior
untouched, and every cloud callback it used to make either redirected to my LAN or failed closed.

## Tooling appendix

- **esptool** — flash read/write, chip/image info, and the actual flash (the only step that needs
  it; the build is esptool-free)
- **gen_esp32part.py** (from esp-idf) — partition table decode; or the self-contained parser above
- **python3 + `cryptography`** — regex string analysis, NVS/blob extraction, byte carving, *and*
  the whole TLS chain + image (re)validation (no `openssl` required)
- **Ghidra ≥ 11** with its **built-in Xtensa** processor (models the windowed ABI esp-idf uses) —
  disassembly/decompilation. Skip the old community forks; they predate in-tree support and won't
  load on current Ghidra.
- **Repo scripts:** `gen_certs.py` (mint the EC chain), `may-firmware-dump/patch_this.py` (patch +
  re-sign + validate), `may-firmware-dump/nvs_parse.py` (decode NVS / alarms)
- **Environment:** Bluefin (Universal Blue, immutable). Use `distrobox` or `brew` for tooling
  rather than touching the atomic base; `gen_esp32part.py` isn't bundled with standalone esptool.

---

*All work performed on hardware I own, for personal local-control purposes, using my own broker and
certificates. No cloud services were impersonated and no security controls were defeated in the
making of this project.*
