"""Exercise may-firmware-dump/patch_this.py against a synthetic esp32 app image laid out
like the real one (PEM slots, vendor URL strings, checksum + appended SHA-256).

    python3 tests/test_patch_this.py
"""
import os, sys, struct, hashlib, datetime, importlib, io, contextlib, shutil, subprocess, tempfile
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = tempfile.mkdtemp(prefix="lofted-test-")
os.makedirs(os.path.join(WORK, "fw"))
shutil.copy(os.path.join(REPO, "may-firmware-dump", "patch_this.py"), os.path.join(WORK, "fw"))
shutil.copy(os.path.join(REPO, "gen_certs.py"), WORK)
subprocess.run([sys.executable, os.path.join(WORK, "gen_certs.py")], check=True,
               env={**os.environ, "BROKER_IP": "192.168.1.50"}, stdout=subprocess.DEVNULL)
os.chdir(os.path.join(WORK, "fw"))
sys.path.insert(0, ".")
now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)


def mk(cn, issuer_cn, key, sign_key):
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=9000))
            .sign(sign_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM).rstrip(b"\n"))


cak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
clk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CA = mk("Amazon Root CA 1", "Amazon Root CA 1", cak, cak)
CC = mk("AWS IoT Certificate", "Amazon Web Services", clk, cak)
CK = clk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                       serialization.NoEncryption()).rstrip(b"\n")
STR = [b"mqtts://abcdefgh123456-ats.iot.us-east-1.amazonaws.com:8883",
       b"https://abcdefghij0123456789x.byloftie.com/Loftie_EVT.bin",
       b"http://abcdefghij0123456789x.byloftie.com/sdcard/%s",
       b"https://pro.ip-api.com/line?key=SECRETKEY123&fields=timezone",
       b"https://abcdefghij0123456789x.byloftie.com/sdcard/%s"]


def build(extra=b""):
    seg = bytearray(0x100) + CC + b"\n\x00"
    cc_off = 0x20 + 0x100
    ck_off = 0x20 + len(seg); seg += CK + b"\n\x00"
    ca_off = 0x20 + len(seg); seg += CA + b"\n\x00"
    for s in STR:
        seg += b"\x00" + s + b"\x00\x00\x00"
    seg += extra
    while len(seg) % 4:
        seg += b"\x00"
    hdr = bytearray(24); hdr[0] = 0xE9; hdr[1] = 1; hdr[0x17] = 1
    img = bytearray(hdr) + struct.pack("<II", 0x3f400020, len(seg)) + seg
    cks = 0xEF
    for b in seg:
        cks ^= b
    img += b"\x00" * (15 - (len(img) % 16)) + bytes([cks])
    img += hashlib.sha256(img).digest()
    img += b"\xff" * 4096                       # carved-partition padding
    open("ota_0.bin", "wb").write(img)
    return {"client_cert": (cc_off, len(CC)), "client_key": (ck_off, len(CK)),
            "ca_cert": (ca_off, len(CA))}


def run(extra=b"", env=None):
    exp = build(extra)
    if os.path.exists("fw_patched.bin"):
        os.remove("fw_patched.bin")
    os.environ.update(env or {})
    import patch_this
    importlib.reload(patch_this)
    patch_this.EXPECT = exp
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            patch_this.main()
        return 0, out.getvalue(), patch_this
    except SystemExit as e:
        return 1, str(e), patch_this


# 1. happy path
rc, out, pt = run(env={"BROKER_IP": "192.168.1.50", "ASSET_HOST": "assets.lan"})
assert rc == 0, out
img = open("fw_patched.bin", "rb").read()
assert pt.verify_esp32_image(img) == (True, True, True)
strs = [s for s in img.split(b"\x00") if b"://" in s]
print("strings:", strs)
assert b"http://assets.lan/sdcard/%s" in strs and b"https://assets.lan/sdcard/%s" in strs
assert b"mqtts://192.168.1.50:8883" in strs and b"https://ota.invalid/Loftie_EVT.bin" in strs
assert b"https://tz.invalid/line?fields=timezone" in strs
for t in (b"byloftie", b"amazonaws", b"ip-api", b"SECRETKEY"):
    assert t not in img, t
assert open("../certs/client.key", "rb").read() in img
assert open("../certs/client.crt", "rb").read() in img
assert open("../certs/ca.crt", "rb").read() in img
print("1 happy path: OK")

# 2. default ASSET_HOST fails closed
os.environ.pop("ASSET_HOST")
rc, out, pt = run()
assert rc == 0 and b"http://assets.invalid/sdcard/%s" in open("fw_patched.bin", "rb").read()
print("2 default asset sinkhole: OK")

# 3. duplicated broker string -> abort, no output written
rc, out, _ = run(extra=b"\x00" + STR[0] + b"\x00")
assert rc == 1 and "expected 1" in out and not os.path.exists("fw_patched.bin"), out
print("3 duplicate string abort:", out)

# 4. unknown vendor endpoint left over -> abort
rc, out, _ = run(extra=b"\x00https://other.byloftie.com/x\x00")
assert rc == 1 and "still present" in out and not os.path.exists("fw_patched.bin"), out
print("4 residue abort:", out)

# 5. a longer string that merely starts with a target must not be rewritten
rc, out, _ = run(extra=b"\x00" + STR[1] + b".bak\x00")
assert rc == 1 and not os.path.exists("fw_patched.bin"), out
print("5 prefix-of-longer-string not matched (residue abort):", out)

# 6. asset host too long for the slot
rc, out, _ = run(env={"ASSET_HOST": "x" * 60})
assert rc == 1 and "longer" in out, out
print("6 oversize host abort:", out)
shutil.rmtree(WORK)
print("ALL PATCHER TESTS PASSED")
