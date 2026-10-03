#!/usr/bin/env python3
"""Generate the local-control mutual-TLS chain for the Loftie firmware + broker.

Pure-Python (uses `cryptography`) so it needs no `openssl` on PATH. Produces one
internally-consistent chain under certs/:

  ca.crt  / ca.key       your own CA  -> goes INTO the firmware (broker trust anchor)
  client.crt / client.key  device id  -> goes INTO the firmware (CN=AlarmClock)
  ha.crt / ha.key          HA id      -> Home Assistant's MQTT client (CN=home-assistant)
  server.crt / server.key  broker id  -> installed on Mosquitto

The clock and Home Assistant get separate identities so mosquitto/acl can give
each only the topics it needs (the clock cannot publish commands to itself) and
either can be re-issued without touching the other. Private keys are written
0600; ca.key never needs to leave this machine.

Everything is EC P-256: small enough to fit the firmware's fixed PEM slots
(CA <= 1187 B, client cert <= 1223 B, client key <= 1678 B) with room to spare,
where an RSA CA cert would overflow the 1187 B CA slot.

The broker is reached by IP (Mosquitto on your Portainer host), so the SERVER cert
carries `subjectAltName = IP:<BROKER_IP>`. That satisfies mbedTLS server-identity
checking whether or not the firmware skips the CN check. Re-run with a different
BROKER_IP (one edit) to re-issue the server cert; the CA + client material is
IP-independent and need not change.

Usage:
  python3 gen_certs.py                 # uses the placeholder BROKER_IP below
  BROKER_IP=192.168.1.50 python3 gen_certs.py
"""
import os
import datetime
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ----------------------------- CONFIG ---------------------------------------
# Placeholder LAN IP of the Portainer host where Mosquitto publishes :8883.
# <<< EDIT (or pass BROKER_IP=... in the env) once you know the real host IP.
BROKER_IP = os.environ.get("BROKER_IP", "192.168.1.50")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

# Fixed validity window -> reproducible builds, and safely brackets any
# NTP-derived device clock.
NVB = datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc)
NVA = datetime.datetime(2035, 6, 1, tzinfo=datetime.timezone.utc)

# Firmware slot ceilings (bytes) from patch_this.py EXPECT — assert the fit here.
SLOT = {"ca.crt": 1187, "client.crt": 1223, "client.key": 1678}
# ----------------------------------------------------------------------------


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, mode)    # O_CREAT mode is ignored when the file already exists


def _key_pem(key):
    # PKCS#8 unencrypted PEM: mbedTLS + Mosquitto both accept it.
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def main():
    os.makedirs(OUT, exist_ok=True)
    ip = ipaddress.ip_address(BROKER_IP)

    # --- CA (self-signed, EC P-256, short CN so the cert stays small) ---------
    ca_key = _key()
    ca_name = _name("Loftie Local CA")
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NVB)
        .not_valid_after(NVA)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # --- Clients (clock + Home Assistant), signed by CA ---------------------
    def client_cert(cn):
        key = _key()
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NVB)
            .not_valid_after(NVA)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        return key, cert

    # CNs double as broker usernames (use_identity_as_username) -> must match mosquitto/acl
    cl_key, cl = client_cert("AlarmClock")
    ha_key, ha = client_cert("home-assistant")

    # --- Server (broker identity, IP SAN, signed by CA) -----------------------
    sv_key = _key()
    sv = (
        x509.CertificateBuilder()
        .subject_name(_name("loftie-broker"))
        .issuer_name(ca_name)
        .public_key(sv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NVB)
        .not_valid_after(NVA)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip)]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    files = {
        "ca.crt": ca.public_bytes(serialization.Encoding.PEM),
        "ca.key": _key_pem(ca_key),
        "client.crt": cl.public_bytes(serialization.Encoding.PEM),
        "client.key": _key_pem(cl_key),
        "ha.crt": ha.public_bytes(serialization.Encoding.PEM),
        "ha.key": _key_pem(ha_key),
        "server.crt": sv.public_bytes(serialization.Encoding.PEM),
        "server.key": _key_pem(sv_key),
    }
    for name, data in files.items():
        _write(os.path.join(OUT, name), data, 0o600 if name.endswith(".key") else 0o644)

    # --- Report + slot-fit assertions ----------------------------------------
    print(f"Broker IP baked into server cert SAN: {BROKER_IP}")
    print(f"Wrote chain to {OUT}/")
    ok = True
    for name, data in files.items():
        n = len(data)
        limit = SLOT.get(name)
        if limit is None:
            print(f"  {name:12s} {n:5d} B")
        else:
            fit = "OK" if n <= limit else "TOO BIG"
            if n > limit:
                ok = False
            print(f"  {name:12s} {n:5d} B  (firmware slot {limit} B: {fit})")
    # chain self-check: client/server verify under CA
    for leaf, who in ((cl, "client"), (ha, "home-assistant"), (sv, "server")):
        try:
            ca_key.public_key().verify(
                leaf.signature, leaf.tbs_certificate_bytes,
                ec.ECDSA(leaf.signature_hash_algorithm),
            )
            print(f"  chain: {who} cert verifies under CA  OK")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  chain: {who} cert FAILED CA verify: {e}")
    if not ok:
        raise SystemExit("ERROR: a cert exceeds its slot or failed chain verify")
    print("All certs fit their firmware slots and verify under the CA.")


if __name__ == "__main__":
    main()
