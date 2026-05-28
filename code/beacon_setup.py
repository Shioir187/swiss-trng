#!/usr/bin/env python3
"""
Einmalige Einrichtung fuer die NIST IR 8213 Beacon.
Erzeugt:
  - RSA-4096-Schluesselpaar (privat + public)
  - X.509 Self-Signed-Zertifikat
  - certificateId = SHA-512(PEM-cert) als hex

Aufruf:
  python3 beacon_setup.py
"""
import hashlib
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR    = "/home/iip/mountain-rng/beacon/"
PRIV_PATH   = os.path.join(BASE_DIR, "beacon_priv.pem")
CERT_PATH   = os.path.join(BASE_DIR, "beacon_cert.pem")
CERTID_PATH = os.path.join(BASE_DIR, "certificateId.txt")


def main():
    os.makedirs(BASE_DIR, exist_ok=True)

    print("Erzeuge RSA-4096 Schluessel...")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    print("Erzeuge Self-Signed X.509 Zertifikat...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,              "CH"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,         "Mountain RNG"),
        x509.NameAttribute(NameOID.COMMON_NAME,               "beacon.local"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .sign(priv, hashes.SHA512()))

    # Privater Schluessel als PEM (unverschluesselt - Studienprojekt!)
    with open(PRIV_PATH, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    os.chmod(PRIV_PATH, 0o600)

    # Zertifikat als PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(CERT_PATH, "wb") as f:
        f.write(cert_pem)

    # certificateId = SHA-512 ueber den PEM-Inhalt (gem. IR 8213)
    cert_id = hashlib.sha512(cert_pem).hexdigest().upper()
    with open(CERTID_PATH, "w") as f:
        f.write(cert_id + "\n")

    print(f"\nFertig!")
    print(f"  Privater Schluessel: {PRIV_PATH}")
    print(f"  Zertifikat:          {CERT_PATH}")
    print(f"  certificateId:       {cert_id[:32]}...")


if __name__ == "__main__":
    main()
