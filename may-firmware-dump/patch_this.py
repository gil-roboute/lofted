#!/usr/bin/env python3
"""Patch the stock Loftie app image to point at local infrastructure.

Written for the Loftie_EVT v0010_2.4.0 app image (esp-idf v5.1.1). The approach
follows Ian Kilgore's original proof of concept
(https://github.com/iank/alarmclock-firmware), with these hardening changes:
  * operates on the carved active app image `ota_0.bin`
  * recomputes the esp32 image checksum + appended SHA-256 ourselves AND
    re-validates them in pure Python (verify_esp32_image), so NO esptool is
    needed on PATH to gate a flashable image (esptool, if present, is only an
    optional cross-check)
  * asserts the located cert/key slots are the expected AWS IoT identity material
    using `cryptography` (no openssl on PATH); the image also embeds a ~140-cert
    Mozilla CA bundle that must NOT be touched
  * length-guards every replacement against its fixed slot
  * matches whole C strings by pattern with an exact expected count, and refuses
    to write an image that still references any vendor endpoint
  * broker is reached by IP (Mosquitto on a Portainer host): set BROKER_IP below;
    it must match the IP baked into certs/server.crt's SAN by ../gen_certs.py

What it changes (all in place, lengths preserved, then re-signed):
  - MQTT broker URI  (hardcoded literal, single xref) -> your broker
  - OTA URL (vendor host)                             -> sinkhole
  - asset URLs (vendor host, http + https)            -> ASSET_HOST (path kept)
  - ip-api.com TZ URL (strips the embedded Pro key)   -> keyless sinkhole
  - client cert + client key + CA cert                -> your own mTLS material

Closes gaps C1/C2/H1/H2/M2 from docs/security-gaps.md (the remote-OTA RCE chain,
the plaintext-HTTP asset path injection, the hardcoded ip-api key, and moving the
authz boundary onto your own mTLS broker). C3 is handled by the cert/key swap.

Slots in this image (verified):
  client cert  file 0x120  size 1223 B  (CN=AWS IoT Certificate)
  client key   file 0x5ed  size 1678 B  (RSA-2048)        <- use EC P-256 to fit easily
  CA cert      file 0xc81  size 1187 B  (Amazon Root CA 1) <- keep small (EC / short CN)

Usage:
  1. Generate the EC TLS chain:  BROKER_IP=<host-ip> python3 ../gen_certs.py
     (writes ../certs/{ca,client,server}.{crt,key}; all sized to fit the slots).
  2. Set BROKER_IP below to the same IP (or export BROKER_IP=...); optionally
     export ASSET_HOST=<lan-host> (default assets.invalid = fail closed).
  3. python3 patch_this.py            -> fw_patched.bin (Python-validated, flashable)
  4. esptool --chip esp32 -p /dev/ttyUSB0 write_flash 0x420000 fw_patched.bin
     (only if your boot log shows ota_0 @ 0x420000 is the active slot -- see
      docs/deployment-runbook.md; recovery: write_flash 0x0 loftie_full_dump.bin.
      Run nvs_parse.py --check-certs on BOTH NVS partitions before flashing.)
"""
import os
import re
import struct
import hashlib
import subprocess
import sys

# ----------------------------- CONFIG ---------------------------------------
INPUT = "ota_0.bin"
OUTPUT = "fw_patched.bin"

# Broker the device connects to: Mosquitto on your Portainer host, reached by IP.
# This IP must match the one baked into certs/server.crt's SAN (see gen_certs.py),
# because the device validates the broker's server cert against your CA + IP.
# <<< EDIT to your real Portainer-host LAN IP (or export BROKER_IP=...), then
#     re-run `python3 ../gen_certs.py` and this script. The broker needs a
#     static / DHCP-reserved address since it is compiled into the image.
BROKER_IP = os.environ.get("BROKER_IP", "192.168.1.50")
BROKER_PORT = 8883
BROKER_URI = f"mqtts://{BROKER_IP}:{BROKER_PORT}".encode()

# String rewrites. Each entry matches one or more *whole* NUL-terminated C strings
# in the image by regex, so no vendor hostnames / API keys need to live in this
# repo, and a match can never be a prefix of some longer string. Each rewrite
# must fit the original string; it is written then NUL-padded over the slot.
# `count` is the exact number of matches expected -- anything else aborts.
#
# Each redirect below closes a specific gap from docs/security-gaps.md:
#   broker URI -> your broker      : moves the authz boundary onto your mTLS broker (C1/M2)
#   OTA URL    -> ota.invalid      : fails the remote-OTA fetch closed (C1/C2 RCE chain)
#   ip-api URL -> keyless sinkhole : strips the hardcoded ip-api Pro key (H2); TZ still
#                                    comes from NVS key_user_perf, only auto-from-IP stops
#   asset URLs -> ASSET_HOST       : closes the plaintext-HTTP asset channel + server-
#                                    controlled filename path injection (H1). The path
#                                    (`/sdcard/%s`) is kept; only the host changes.
#
# Set ASSET_HOST to a LAN host that serves the same /sdcard/<file> layout, or leave
# the default sinkhole to fail closed (your .mp3s already live on the SD card, so
# blocking re-downloads is low-impact).
ASSET_HOST = os.environ.get("ASSET_HOST", "assets.invalid").encode()

STRING_REWRITES = [
    ("broker URI",
     rb"mqtts://[a-z0-9]+-ats\.iot\.[a-z0-9-]+\.amazonaws\.com:8883",
     lambda m: BROKER_URI, 1),
    ("OTA URL",
     rb"https://[a-z0-9]+\.byloftie\.com/Loftie_EVT\.bin",
     lambda m: b"https://ota.invalid/Loftie_EVT.bin", 1),
    ("ip-api URL",
     rb"https?://pro\.ip-api\.com/line\?key=[A-Za-z0-9]+&fields=timezone",
     lambda m: b"https://tz.invalid/line?fields=timezone", 1),
    ("asset URL",
     rb"(https?://)[a-z0-9]+\.byloftie\.com(/sdcard/%s)",
     lambda m: m.group(1) + ASSET_HOST + m.group(2), 2),   # http + https forms
]
# After rewriting, none of these may remain anywhere in the image (fail closed).
FORBIDDEN_RESIDUE = [b"byloftie.com", b"amazonaws.com", b"ip-api.com"]

# TLS material (PEM files, generated by ../gen_certs.py into ../certs/).
# Set any to None to leave that slot unchanged.
CA_CERT = "../certs/ca.crt"
CLIENT_CERT = "../certs/client.crt"
CLIENT_KEY = "../certs/client.key"

# Identity guard: abort unless the located slots match these (this firmware).
EXPECT = {
    "client_cert": (0x120, 1223),
    "client_key":  (0x5ed, 1678),
    "ca_cert":     (0xc81, 1187),
}
VERIFY_SUBJECTS = True         # sanity-check the original slots' cert subjects
# ----------------------------------------------------------------------------


def die(msg):
    sys.exit(f"ERROR: {msg}")


def slot(buf, begin, end, occurrence=1):
    """Byte range [start, end) of the Nth begin..end PEM block."""
    pos = -1
    for _ in range(occurrence):
        s = buf.find(begin, pos + 1)
        if s == -1:
            return None
        e = buf.find(end, s)
        if e == -1:
            return None
        pos = s
    return s, e + len(end)


def overwrite(buf, start, end, replacement, what):
    span = end - start
    if len(replacement) > span:
        die(f"{what}: replacement {len(replacement)} B > slot {span} B "
            f"(shrink it: EC key / shorter CN)")
    buf[start:end] = replacement + b"\x00" * (span - len(replacement))


def patch_cstrings(buf, what, pattern, build, count):
    """Rewrite every whole C string matching `pattern` (preceded by a non-printable
    byte, followed by NUL). Aborts unless exactly `count` strings match."""
    rx = re.compile(rb"(?<![\x20-\x7e])" + pattern + rb"(?=\x00)")
    hits = list(rx.finditer(buf))
    if len(hits) != count:
        die(f"{what}: expected {count} match(es), found {len(hits)} -- firmware differs, "
            "refusing to patch")
    for m in hits:
        new = build(m)
        old_len = m.end() - m.start()
        if len(new) > old_len:
            die(f"{what}: replacement {new!r} longer than original slot ({old_len} B)")
        buf[m.start():m.end()] = new + b"\x00" * (old_len - len(new))
        print(f"  patched {what} @ {m.start():#x} -> {new.decode()}")


def openssl_subject(pem_bytes):
    """Return a cert's subject string. Uses `cryptography` (no openssl on PATH)."""
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(bytes(pem_bytes))
        return cert.subject.rfc4514_string()
    except Exception as e:  # noqa: BLE001
        return f"(parse failed: {e})"


def verify_esp32_image(image):
    """Independently re-validate the produced image the way `esptool image_info`
    does: walk the segment table, recompute the XOR checksum byte, and (if the
    header marks one) recompute the appended SHA-256. Returns (cksum_ok, sha_ok,
    size_ok) so we never need esptool on PATH to gate a flashable image."""
    if image[0] != 0xE9:
        die("verify: magic != 0xE9")
    seg_count = image[1]
    hash_appended = image[0x17] == 1
    off = 0x18
    cks = 0xEF
    for _ in range(seg_count):
        _load, length = struct.unpack_from("<II", image, off)
        ds = off + 8
        de = ds + length
        for b in image[ds:de]:
            cks ^= b
        off = de
    ck_pos = off + (15 - (off % 16))
    cks_ok = image[ck_pos] == cks
    if hash_appended:
        sha_pos = ck_pos + 1
        sha_ok = image[sha_pos:sha_pos + 32] == hashlib.sha256(image[:sha_pos]).digest()
        end = sha_pos + 32
    else:
        sha_ok = True
        end = ck_pos + 1
    return cks_ok, sha_ok, end == len(image)


def resign(buf):
    """Recompute esp32 checksum byte + appended SHA-256; return trimmed image."""
    if buf[0] != 0xE9:
        die("not an esp32 image (magic != 0xE9)")
    seg_count = buf[1]
    hash_appended = buf[0x17] == 1
    off = 0x18
    cks = 0xEF
    for _ in range(seg_count):
        load, length = struct.unpack_from("<II", buf, off)
        ds = off + 8
        de = ds + length
        for b in buf[ds:de]:
            cks ^= b
        off = de
    ck_pos = off + (15 - (off % 16))
    buf[ck_pos] = cks
    if hash_appended:
        sha_pos = ck_pos + 1
        buf[sha_pos:sha_pos + 32] = hashlib.sha256(buf[:sha_pos]).digest()
        return bytes(buf[:sha_pos + 32])
    return bytes(buf[:ck_pos + 1])


def main():
    buf = bytearray(open(INPUT, "rb").read())

    # locate + verify the TLS slots before touching anything
    cc = slot(buf, b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----", 1)
    ca = slot(buf, b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----", 2)
    ck = slot(buf, b"-----BEGIN RSA PRIVATE KEY-----", b"-----END RSA PRIVATE KEY-----", 1)
    for name, found, exp in (("client_cert", cc, EXPECT["client_cert"]),
                             ("ca_cert", ca, EXPECT["ca_cert"]),
                             ("client_key", ck, EXPECT["client_key"])):
        if not found:
            die(f"{name}: PEM slot not found")
        if (found[0], found[1] - found[0]) != exp:
            die(f"{name}: slot {found[0]:#x}/{found[1]-found[0]} != expected "
                f"{exp[0]:#x}/{exp[1]} -- firmware differs, refusing to patch")
    if VERIFY_SUBJECTS:
        cs = openssl_subject(buf[cc[0]:cc[1]])
        cas = openssl_subject(buf[ca[0]:ca[1]])
        print(f"client cert: {cs}\nCA cert    : {cas}")
        if "AWS IoT" not in cs or "Amazon Root CA" not in cas:
            die("slot subjects don't match expected AWS IoT identity -- refusing")

    print("Strings:")
    for what, pattern, build, count in STRING_REWRITES:
        patch_cstrings(buf, what, pattern, build, count)

    print("TLS material:")
    if CLIENT_CERT:
        overwrite(buf, cc[0], cc[1], open(CLIENT_CERT, "rb").read(), "client cert")
        print(f"  client cert <- {CLIENT_CERT}")
    if CLIENT_KEY:
        overwrite(buf, ck[0], ck[1], open(CLIENT_KEY, "rb").read(), "client key")
        print(f"  client key  <- {CLIENT_KEY}")
    if CA_CERT:
        overwrite(buf, ca[0], ca[1], open(CA_CERT, "rb").read(), "ca cert")
        print(f"  ca cert     <- {CA_CERT}")

    for token in FORBIDDEN_RESIDUE:
        if token in buf:
            die(f"vendor endpoint {token.decode()!r} still present at "
                f"{buf.find(token):#x} after patching -- refusing to write image")

    image = resign(buf)
    cks_ok, sha_ok, size_ok = verify_esp32_image(image)
    if not (cks_ok and sha_ok and size_ok):
        die(f"image self-check failed: checksum={cks_ok} sha256={sha_ok} "
            f"size={size_ok} -- do not flash")
    open(OUTPUT, "wb").write(image)
    print(f"\nwrote {OUTPUT} ({len(image)} B)")
    print(f"  broker URI -> {BROKER_URI.decode()}")
    print("OK: esp32 segment checksum valid, appended SHA-256 valid, length consistent.")

    # Optional belt-and-suspenders cross-check if esptool happens to be present.
    try:
        r = subprocess.run(["esptool", "--chip", "esp32", "image_info", OUTPUT],
                           capture_output=True, text=True)
        if "(valid)" in r.stdout:
            print("  (esptool image_info agrees: valid)")
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    main()
