"""Exercise may-firmware-dump/nvs_parse.py against synthetic NVS partitions: a stale blob
version must not be spliced in, and --check-certs must flag provisioned certs.

    python3 tests/test_nvs_parse.py
"""
import os, struct, subprocess, sys, tempfile
P = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "may-firmware-dump", "nvs_parse.py")
os.chdir(tempfile.mkdtemp(prefix="lofted-nvs-"))
def entry(ns, typ, span, chunk, key, meta):
    return struct.pack("<BBBBI", ns, typ, span, chunk, 0) + key.encode().ljust(16, b"\0") + meta
def page(items):
    ents=[]; 
    for e, payload in items:
        ents.append(e)
        for i in range(0, len(payload), 32): ents.append(payload[i:i+32].ljust(32, b"\xff"))
    bitmap = bytearray(b"\xff"*32)
    for i in range(len(ents)): bitmap[i//4] &= ~(0b01 << ((i%4)*2)) & 0xff   # 0b10 = written
    hdr = struct.pack("<II", 0xFFFFFFFE, 0) + bytes([0xfe]) + b"\xff"*19 + b"\0"*4
    return (hdr + bytes(bitmap) + b"".join(ents)).ljust(4096, b"\xff")
def blob_data(ns, key, chunk, data):
    span = 1 + (len(data)+31)//32
    return entry(ns, 0x42, span, chunk, key, struct.pack("<HHI", len(data), 0, 0)), data
alarm_old = bytes([6,6,0x0f,0xbe]) + bytes(12)
alarm_new = bytes([7,7,0x1e,0xbe]) + bytes(12)
def part(with_cert, stale):
    items = [(entry(0, 0x01, 1, 0xff, "storage", bytes([1])+b"\xff"*7), b""),
             (entry(0, 0x01, 1, 0xff, "download", bytes([2])+b"\xff"*7), b"")]
    if stale: items.append(blob_data(1, "key_alarm", 0, alarm_old))      # stale v0 copy
    items.append(blob_data(1, "key_alarm", 128, alarm_new))                 # live v1
    items.append((entry(1, 0x48, 1, 0xff, "key_alarm", struct.pack("<IBBH", 16, 1, 128, 0xffff)), b""))
    if with_cert:
        items.append(blob_data(2, "Cert.dl", 0, b"-----BEGIN CERTIFICATE-----\nMIIB\n"))
    return page(items) + b"\xff"*4096
for name, wc, st in (("clean_stale.bin", False, True), ("withcert.bin", True, False)):
    open(name, "wb").write(part(wc, st))
r = subprocess.run([sys.executable, P, "clean_stale.bin", "--alarms", "--check-certs"], capture_output=True, text=True)
print(r.stdout[-400:], r.stderr, "rc", r.returncode)
assert r.returncode == 0 and "07:30" in r.stdout and "06:15" not in r.stdout
r = subprocess.run([sys.executable, P, "withcert.bin", "--check-certs"], capture_output=True, text=True)
print(r.stdout[-400:], "rc", r.returncode); assert r.returncode == 1 and "download/Cert.dl" in r.stdout
print("NVS TESTS PASSED")
