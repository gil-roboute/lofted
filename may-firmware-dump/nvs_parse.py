#!/usr/bin/env python3
"""esp-idf NVS partition parser with correct blob reassembly.

A naive 32-byte entry walker misreads chunked blob regions (the data slots that
follow a BLOB_DATA/SZ header look like garbage "ghost" entries). This parser
honours the per-page entry-state bitmap and each item's `span`, so it only ever
decodes real headers, then reassembles BLOB_IDX + BLOB_DATA chunks into the
original value.

Usage:
    nvs_parse.py <partition.bin>                # list namespaces / keys / values
    nvs_parse.py <partition.bin> --dump KEY     # write reassembled blob(s) -> KEY[_n].bin
    nvs_parse.py <partition.bin> --hex  KEY     # hexdump reassembled blob(s)
    nvs_parse.py <partition.bin> --raw          # also show fixed-type raw values
    nvs_parse.py <partition.bin> --check-certs  # pre-flash gate: exit 1 if provisioned
                                                # certs (download/Cert.dl, Key.dl) or any
                                                # PEM material are present

Run --check-certs against BOTH NVS partitions (nvs @0x9000 and app_cfg @0x10000)
before flashing a patched image: a provisioned cert overrides the patched slot.

NVS on-flash layout (esp-idf, version 0xfe = v2):
    page  = 4096 B = 32 B header + 32 B entry-state bitmap + 126 * 32 B entries
    header: state(u32) seq(u32) version(u8) ...19B... crc32(u32)
    bitmap: 2 bits / entry, LSB-first: 0b11 empty, 0b10 written, 0b00 erased
    entry : ns(u8) type(u8) span(u8) chunk(u8) crc32(u32) key[16] meta[8]
            - fixed types store the value in meta[8]
            - SZ / BLOB_DATA: meta = {u16 size; u16 rsvd; u32 crc}, data in next span-1 slots
            - BLOB_IDX:       meta = {u32 size; u8 chunkCount; u8 chunkStart; u16 rsvd}

Decoded `key_alarm` layout (namespace "storage", single 480 B blob = 30 x 16 B records):
    [0] hour, 12-hour clock (1..12)
    [1] hour, 24-hour clock (0..23)        # == [0] for AM, [0]+12 for PM
    [2] minute (0..59)
    [3] bit7 = isSet/enabled; bits0..6 = daysOfWeek (bit0=Sun .. bit6=Sat, 0 = no repeat)
    [4..7] boolean flags (alarmLight / wake-up / get-up toggles; [5] is constant 1)
    [8..12] tone folder/file indices, constant 00 01 00 01 09 on this device
    [13..15] reserved (0)
Example (illustrative values): record 07 07 1e be -> 07:30, days=62 (Mon-Fri), isSet=1. Empty slots are all-zero. Times carry a 12/24h hour pair, no AM/PM byte.
"""
import re
import sys
import struct
import argparse
from collections import defaultdict

PAGE_SIZE = 4096
ENTRY_SIZE = 32
ENTRIES_PER_PAGE = 126
HEADER_SIZE = 32
BITMAP_SIZE = 32

PAGE_STATES = {
    0xFFFFFFFF: "UNINIT",
    0xFFFFFFFE: "ACTIVE",
    0xFFFFFFFC: "FULL",
    0xFFFFFFF8: "FREEING",
    0xFFFFFFF0: "CORRUPT",
}

T_U8, T_I8 = 0x01, 0x11
T_U16, T_I16 = 0x02, 0x12
T_U32, T_I32 = 0x04, 0x14
T_U64, T_I64 = 0x08, 0x18
T_SZ = 0x21
T_BLOB = 0x41          # legacy single-entry blob
T_BLOB_DATA = 0x42
T_BLOB_IDX = 0x48

TYPE_NAMES = {
    T_U8: "u8", T_I8: "i8", T_U16: "u16", T_I16: "i16",
    T_U32: "u32", T_I32: "i32", T_U64: "u64", T_I64: "i64",
    T_SZ: "str", T_BLOB: "blob", T_BLOB_DATA: "blob_data", T_BLOB_IDX: "blob_idx",
}

FIXED_FMT = {
    T_U8: "<B", T_I8: "<b", T_U16: "<H", T_I16: "<h",
    T_U32: "<I", T_I32: "<i", T_U64: "<Q", T_I64: "<q",
}

ES_EMPTY, ES_WRITTEN, ES_ERASED = 0b11, 0b10, 0b00


def parse_entries(data):
    """Return list of decoded header entries (written items only)."""
    entries = []
    n_pages = len(data) // PAGE_SIZE
    for p in range(n_pages):
        base = p * PAGE_SIZE
        state = struct.unpack_from("<I", data, base)[0]
        if state == 0xFFFFFFFF:           # uninitialized / blank page
            continue
        bitmap = data[base + HEADER_SIZE: base + HEADER_SIZE + BITMAP_SIZE]
        slot_state = []
        for i in range(ENTRIES_PER_PAGE):
            code = (bitmap[i // 4] >> ((i % 4) * 2)) & 0b11
            slot_state.append(code)
        ebase = base + HEADER_SIZE + BITMAP_SIZE
        i = 0
        while i < ENTRIES_PER_PAGE:
            if slot_state[i] != ES_WRITTEN:
                i += 1
                continue
            off = ebase + i * ENTRY_SIZE
            ns, typ, span, chunk = data[off:off + 4]
            crc = struct.unpack_from("<I", data, off + 4)[0]
            key = data[off + 8:off + 24].split(b"\x00")[0].decode("latin1", "replace")
            meta = data[off + 24:off + 32]
            span = span if span not in (0, 0xFF) else 1
            payload = data[off + ENTRY_SIZE: off + span * ENTRY_SIZE] if span > 1 else b""
            entries.append({
                "page": p, "slot": i, "ns": ns, "type": typ, "span": span,
                "chunk": chunk, "key": key, "meta": meta, "payload": payload,
            })
            i += span
    return entries


def ns_map(entries):
    """ns index -> name (registered as U8 items in namespace 0)."""
    names = {0: "(ns_registry)"}
    for e in entries:
        if e["ns"] == 0 and e["type"] == T_U8:
            names[e["meta"][0]] = e["key"]
    return names


def value_of(e):
    """Return (kind, value) for an entry. Blobs are resolved separately."""
    t = e["type"]
    if t in FIXED_FMT:
        return "fixed", struct.unpack_from(FIXED_FMT[t], e["meta"])[0]
    if t in (T_SZ, T_BLOB_DATA, T_BLOB):
        size = struct.unpack_from("<H", e["meta"], 0)[0]
        return "var", e["payload"][:size]
    if t == T_BLOB_IDX:
        size, cnt, start = struct.unpack_from("<IBB", e["meta"], 0)
        return "idx", (size, cnt, start)
    return "raw", e["meta"]


def reassemble_blobs(entries):
    """Return {(ns,key): bytes} for every blob (IDX+DATA) and legacy blob.

    NVS keeps a blob's data chunks numbered chunkStart + i, where chunkStart
    alternates between 0 and 128 on each rewrite. Only the chunks belonging to the
    live BLOB_IDX's [chunkStart, chunkStart + chunkCount) range are used, so a stale
    copy left behind by an interrupted rewrite is never spliced in."""
    idx = {}            # (ns,key) -> (total, count, start)
    chunks = defaultdict(dict)   # (ns,key) -> {chunk_index: bytes}
    legacy = {}         # (ns,key) -> bytes
    for e in entries:
        k = (e["ns"], e["key"])
        if e["type"] == T_BLOB_IDX:
            idx[k] = struct.unpack_from("<IBB", e["meta"], 0)
        elif e["type"] == T_BLOB_DATA:
            size = struct.unpack_from("<H", e["meta"], 0)[0]
            chunks[k][e["chunk"]] = e["payload"][:size]
        elif e["type"] == T_BLOB:
            size = struct.unpack_from("<H", e["meta"], 0)[0]
            legacy[k] = e["payload"][:size]
    out = {}
    for k, (total, cnt, start) in idx.items():
        want = range(start, start + cnt)
        missing = [c for c in want if c not in chunks[k]]
        if missing:
            print(f"warning: blob {k[1]!r} missing chunk(s) {missing}", file=sys.stderr)
        buf = b"".join(chunks[k][c] for c in want if c in chunks[k])
        if len(buf) != total:
            print(f"warning: blob {k[1]!r} reassembled {len(buf)} B, index says {total} B",
                  file=sys.stderr)
        out[k] = buf[:total]
    out.update(legacy)
    return out


def check_certs(data, entries, names):
    """Report anything that would override the patched compiled-in client cert.
    Returns True if the partition is clean."""
    problems = []
    for e in entries:
        ns_name = names.get(e["ns"], "?")
        if ns_name == "download" or e["key"].endswith(".dl"):
            problems.append(f"provisioned-cert entry {ns_name}/{e['key']}")
    for marker in (b"-----BEGIN", b"PRIVATE KEY"):
        if marker in data:
            problems.append(f"PEM marker {marker.decode()!r} at {data.find(marker):#x}")
    if problems:
        print("CHECK FAILED -- this partition holds provisioned TLS material that would be")
        print("presented instead of your patched client cert:")
        for p in sorted(set(problems)):
            print(f"  - {p}")
        return False
    print("CHECK OK -- no provisioned certs / PEM material in this partition.")
    return True


def safe_filename(key):
    return re.sub(r"[^A-Za-z0-9._-]", "_", key).lstrip(".") or "blob"


DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


def decode_alarms(blob):
    """Decode the key_alarm blob (30 x 16 B records). Returns list of dicts."""
    out = []
    for i in range(0, len(blob), 16):
        r = blob[i:i + 16]
        if len(r) < 16 or not any(r) or not (r[3] & 0x80):
            continue                      # empty / not-set slot
        days = r[3] & 0x7f
        out.append({
            "slot": i // 16,
            "h24": r[1], "minute": r[2],
            "isSet": bool(r[3] >> 7),
            "daysMask": days,
            "days": [d for n, d in enumerate(DAYS) if days & (1 << n)],
            "flags": list(r[4:8]),
            "tone": list(r[8:13]),
        })
    return out


def print_alarms(blob):
    alarms = decode_alarms(blob)
    print(f"{len(alarms)} alarm(s) set:")
    for a in alarms:
        dl = ",".join(a["days"]) if a["days"] else "(one-time)"
        print(f"  slot {a['slot']:>2}: {a['h24']:02d}:{a['minute']:02d}  "
              f"days={a['daysMask']:<3} [{dl}]  flags={a['flags']}")


def hexdump(b, width=16):
    lines = []
    for o in range(0, len(b), width):
        chunk = b[o:o + width]
        hexs = " ".join(f"{x:02x}" for x in chunk)
        text = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        lines.append(f"  {o:04x}: {hexs:<{width*3}} {text}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("partition")
    ap.add_argument("--dump", metavar="KEY", help="write reassembled blob(s) for KEY to file(s)")
    ap.add_argument("--hex", metavar="KEY", dest="hexkey", help="hexdump reassembled blob(s) for KEY")
    ap.add_argument("--raw", action="store_true", help="show fixed-type values")
    ap.add_argument("--alarms", action="store_true", help="decode the key_alarm blob")
    ap.add_argument("--check-certs", action="store_true",
                    help="exit 1 if provisioned certs / PEM material are present")
    args = ap.parse_args()

    data = open(args.partition, "rb").read()
    entries = parse_entries(data)
    names = ns_map(entries)
    blobs = reassemble_blobs(entries)

    # page summary
    for p in range(len(data) // PAGE_SIZE):
        st, seq = struct.unpack_from("<II", data, p * PAGE_SIZE)
        ver = data[p * PAGE_SIZE + 8]
        print(f"page {p}: state={PAGE_STATES.get(st, hex(st))} seq={seq} ver=0x{ver:02x}")
    print()

    by_ns = defaultdict(list)
    for e in entries:
        by_ns[e["ns"]].append(e)

    for ns in sorted(by_ns):
        print(f"namespace {ns} = {names.get(ns, '?')!r}")
        for e in by_ns[ns]:
            kind, val = value_of(e)
            tn = TYPE_NAMES.get(e["type"], hex(e["type"]))
            if e["type"] == T_BLOB_IDX:
                total, cnt, start = val
                reasm = blobs.get((e["ns"], e["key"]))
                got = len(reasm) if reasm is not None else 0
                print(f"  {e['key']:<18} {tn:<9} total={total} chunks={cnt} start={start} reassembled={got}B")
            elif e["type"] == T_BLOB_DATA:
                print(f"  {e['key']:<18} {tn:<9} chunk={e['chunk']} size={len(val)}")
            elif kind == "var":
                shown = val.decode("latin1", "replace").rstrip("\x00") if e["type"] == T_SZ else f"{len(val)}B"
                print(f"  {e['key']:<18} {tn:<9} {shown!r}")
            elif kind == "fixed":
                print(f"  {e['key']:<18} {tn:<9} {val}")
        print()

    if args.dump:
        matches = [(ns, k) for (ns, k) in blobs if k == args.dump]
        if not matches:
            print(f"no blob key {args.dump!r} found")
        for n, (ns, k) in enumerate(matches):
            base = safe_filename(k)
            fn = f"{base}.bin" if len(matches) == 1 else f"{base}_{n}.bin"
            open(fn, "wb").write(blobs[(ns, k)])
            print(f"wrote {fn} ({len(blobs[(ns, k)])} B)")

    if args.hexkey:
        for (ns, k), b in blobs.items():
            if k == args.hexkey:
                print(f"\n== blob ns={ns} key={k!r} ({len(b)} B) ==")
                print(hexdump(b))

    if args.alarms:
        found = [b for (ns, k), b in blobs.items() if k == "key_alarm"]
        if not found:
            print("no key_alarm blob found")
        for b in found:
            print()
            print_alarms(b)

    if args.check_certs:
        print()
        if not check_certs(data, entries, names):
            sys.exit(1)


if __name__ == "__main__":
    main()
