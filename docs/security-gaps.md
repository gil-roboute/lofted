# Loftie firmware — security gaps (defensive catalog)

Findings from static analysis of the stock `ota_0.bin` (`Loftie_EVT 0010_2.4.0`, ESP-IDF v5.1.1),
framed for the project's defensive goal: closing the surface that Loftie, or a threat actor on the
home LAN, could use to reach the device or the network it sits on. Each item lists the evidence
offset and the **local-control mitigation** the patch + local-broker setup provides.

All offsets are file offsets into `ota_0.bin`. A DROM string's runtime address is
`file_offset + 0x3f400000`.

## Priority order

1. **Remote-OTA RCE chain** (C1 + C2)
2. **Embedded AWS IoT private key** (C3)
3. **Plaintext-HTTP asset path injection** (H1)
4. **Hardcoded ip-api key** (H2), **plaintext NVS creds + cred logging** (M1), **no command
   authz/validation** (M2), **BLE provisioning still active** (M3)

---

## C1 — Remote-controlled OTA URL with no firmware signature  *(Critical)*

The OTA update URL is **operator/remote-supplied** via the `otaURL` MQTT command key (`0x1dc14`,
"New OTA URL: %s" `0x1641d`) paired with `md5sum` (`0x1dc00`). The hardcoded default
`https://[REDACTED].byloftie.com/Loftie_EVT.bin` (`0x16578`) is only a fallback;
`OTA_CheckUpdate` / `ota_task` consume whatever URL arrives. The only validation strings present
are the **stock `esp_https_ota` image-header checks** ("image header verification failed"
`0x162c8`, "image is corrupted" `0x1639c`) — these check the ESP image *format*, **not a
cryptographic signature**. An `md5sum` is an integrity check, not authenticity.

This matches the public report at **iank.org/posts/loftie-rce**: anyone who can publish to the
device's command topic can point it at arbitrary firmware.

**Mitigation (this project):** repoint the broker at your own Mosquitto with mutual TLS
(`patch_this.py` + README), so only you can publish to `/devices/<id>/commands/#`; and the patch
rewrites the OTA URL to `https://ota.invalid/...` so even the default fetch fails closed. Do **not**
expose `otaURL` to Home Assistant (see `mqtt-command-reference.md`).

## C2 — No secure boot / no firmware signing / no flash encryption  *(Critical)*

The only secure-boot-related string is a negative: "Digital Signature not enabled for esp-tls in
menuconfig" (`0x868e1`). No `secure_boot`, `flash_encryption`, anti-rollback, or
`esp_image_verify` signature strings anywhere. Consequences:
- Unsigned OTA images are accepted → turns C1 from DoS into full **RCE**.
- The app image and NVS are **plaintext-readable** from any flash dump (this entire analysis is
  the proof — flash is not encrypted).

**Mitigation:** there is no patch-level fix (secure boot must be fused at manufacture). The
local-broker lockdown (C1) removes the *remote* delivery path. Residual risk: physical/flash
access remains fully exposed — treat a stolen/returned unit as fully compromised.

## C3 — Embedded AWS IoT client certificate AND private key in cleartext  *(Critical)*

The app image embeds the device's AWS IoT mTLS identity in plaintext:
- client certificate PEM at **`0x120`** (CN "AWS IoT Certificate", ~1223 B slot)
- **RSA-2048 private key** PEM at **`0x5ed`** (~1678 B slot)
- CA cert "Amazon Root CA 1" at **`0xc81`**
- broker `mqtts://[REDACTED]-ats.iot.us-east-1.amazonaws.com:8883` (`0x16f10`)

Anyone with a flash dump (or this OTA file) recovers a **usable AWS IoT credential** for Loftie's
cloud — fleet impersonation / spoofed telemetry. There is also a "Skip AWS_loadCert()" path
(`0x1d581`) and an `AWSKeyVerifier` (`0x1d5fc`), i.e. cert handling can be bypassed in some boot
states.

**Mitigation:** `patch_this.py` overwrites all three slots with **your own** mTLS material (EC
P-256 client key to fit the slot), so the patched unit carries no AWS credential. Residual risk:
the *original* key is still extractable from any pre-patch dump — if you control the relevant AWS
account, **rotate/deactivate that certificate**; otherwise treat it as burned.

> **Cert-precedence caveat (verified this session).** The MQTT config builder (`FUN_400f3920`)
> uses the compiled-in **CA** slot unconditionally (so your CA is always the trust anchor), but the
> compiled-in **client cert/key** are used only when a runtime flag (`0x3ffc6d40`) is clear. That
> flag is set when `FUN_400f4020` successfully loads a *provisioned* cert from NVS keys
> `download/Cert.dl` / `Key.dl` (a claim-provisioning path). On a unit that was paired and pulled a
> per-device cert, that NVS cert would be presented **instead of** your patched slot — and your
> own-CA broker would reject it. The dumped unit here had **no `download` certs in NVS** (only WiFi
> creds), so it uses the patched slot. Pairing with the vendor app pushes a fresh cert + key over
> BLE, so this can change: run `nvs_parse.py --check-certs` against **both** NVS partitions
> (`nvs` @ `0x9000`, `app_cfg` @ `0x10000`) before every flash, and if one fails erase only that
> partition (`app_cfg` also holds the WiFi creds). See `deployment-runbook.md` §1 / §8.

## H1 — Plaintext-HTTP asset download with server-controlled filename  *(High)*

Asset downloads use **HTTP** with an interpolated filename:
`http://[REDACTED].byloftie.com/sdcard/%s` (`0x1667c`; also an https form `0x1e970`).
The `%s` is a server/playlist-supplied name (playlist record `Name=%s, Path=%s, ... isDel=%d`
`0x1d714`) written to / deleted from the SD card with no visible sanitization → **MITM of the
plaintext channel** and **path traversal / arbitrary asset overwrite** on the SD card. No
`system()`/`popen` was found (not classic shell injection), but the download-URL + SD-path
construction is attacker-influenced.

**Mitigation:** `patch_this.py` rewrites both asset URLs (http and https) to `ASSET_HOST`, keeping
the `/sdcard/%s` path, so the device only ever fetches assets from a host you control. The default
is the `assets.invalid` sinkhole (fail closed); your `.mp3`s already live on the SD card, so
blocking re-downloads is low-impact. The filename itself is still unsanitized, so only point
`ASSET_HOST` at a server you trust.

## H2 — Hardcoded third-party API key  *(High)*

`https://pro.ip-api.com/line?key=[REDACTED]&fields=timezone` (`0x174d4`) embeds the
**ip-api.com Pro key `[REDACTED]`** in cleartext → vendor-billing abuse / key exfiltration.

**Mitigation:** `patch_this.py` rewrites this URL to a keyless sinkhole. Timezone still works from
the NVS-stored value (`key_user_perf`, e.g. `CET-1`); only the auto-from-IP refresh stops.

## M1 — WiFi credentials in plaintext NVS, and echoed to the serial log  *(Medium)*

NVS is unencrypted (C2), so `key_wifi` (`0x11484`) holds the SSID + password in cleartext —
anyone with a flash dump has your WiFi password. Worse, credentials are written to logs:
"PASSWORD:%s" (`0x10a70`), "Wi-Fi Password : %s" (`0x8814c`), "Password : %s" (`0x12a02`) — so the
serial/debug header leaks them at runtime too.

**Mitigation:** no patch-level fix without NVS encryption (a rebuild concern). Practically: put the
clock on an **isolated IoT VLAN** so a leaked credential exposes only that segment; don't share the
serial header output.

## M2 — Minimal command-payload validation / no app-layer authz  *(Medium)*

Inbound JSON validation is limited to type checks ("nl/vol is not a number!" `0x16fec`/`0x17018`,
"invalid sleepTimerMins=%d" `0x1dc1d`). There is **no authentication/authorization beyond MQTT
topic access** — any party able to publish to `/devices/<id>/commands/#` can issue `restart`,
`restoreToDefault`, `play`, etc. No schema/allowlist validation.

**Mitigation:** the local broker is the authz boundary. `mosquitto.conf` requires a client cert
signed by your CA (`require_certificate true`, no anonymous access) and `mosquitto/acl` grants
per-identity topics: only the `home-assistant` cert may publish to `/config` or `/commands/#`, the
clock's own cert may only read them and publish `/state`, and any other CA-signed cert gets no
topics at all. MQTT ACLs can't filter payloads, so whoever holds `ha.key` can still send `otaURL`
(C1); protect that key like a root credential. Keep destructive verbs (`restoreToDefault`) out of
any always-on automation.

## M3 — BLE provisioning service stays active  *(Medium, unverified)*

The vendor app pairs the clock over BLE through an ESP provisioning service (seven
characteristics; the app's own logs show it writing a WiFi config, an AWS IoT cert and private key,
and a device UUID, then a `0x01` "store credentials" command). Patching does not remove this
service. A provisioned cert lands in NVS and overrides the patched client cert (see the C3
caveat), so the failure mode is the clock dropping off your broker, not someone else taking control
of it — your CA stays the only trust anchor. Not yet verified: whether the service accepts writes
outside an explicit pairing mode (e.g. a button hold) and whether it can change the WiFi network.

**Mitigation:** don't re-pair with the vendor app after patching; re-run the §1 NVS check after any
pairing, factory reset, or unexplained disconnect.

---

## L1 — Residual external egress: NTP  *(Low / informational)*

After patching, an endpoint sweep (every `://`, `mqtt`, and bare hostname literal) shows the only
remaining outbound destinations are the **SNTP time servers** `pool.ntp.org`, `cn.pool.ntp.org`,
`time.cloudflare.com`, `time.google.com`. This is unauthenticated UDP time sync — **not** a control
or data-exfil channel — so it's left intact. If you want a fully self-contained LAN, repoint these
to a local NTP server (e.g. your router) by adding entries to `patch_this.py`'s `STRING_REWRITES`
(the device falls back across the list). Everything else (broker, OTA, both `byloftie` asset URLs,
ip-api) is already sinkholed/redirected.

## Summary: what the local-control setup actually closes

| Gap | Closed by local setup? |
| --- | ---------------------- |
| C1 remote-OTA RCE | **Yes** — broker lockdown + OTA URL sinkholed |
| C2 no secure boot/flash-enc | No (manufacture-time) — only the *remote* path is removed |
| C3 embedded AWS key | **Yes on the patched unit** — replaced with your own; rotate the original upstream. NB cert-precedence caveat above |
| H1 asset HTTP/path injection | **Yes** — asset URLs repointed to `ASSET_HOST` (default sinkhole) |
| H2 ip-api key | **Yes** — URL/key sinkholed |
| M1 plaintext NVS creds | No (needs rebuild) — mitigate with VLAN isolation |
| M2 command authz | **Yes** — broker mutual-TLS + per-identity ACL (`mosquitto/acl`) become the gate |
| M3 BLE provisioning | Partly — fails closed against your CA; avoid re-pairing, re-check NVS |
| L1 NTP egress | Left intact (benign time-sync) — optionally repoint to LAN NTP |
