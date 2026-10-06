"""Create a short-lived self-signed certificate for local development only.

It is written in certbot's directory layout (``letsencrypt/live/<domain>/``) so the gateway
loads local and production certificates the same way. Production certificates come from
certbot; never use this script there.

Usage:  uv run python scripts/dev_cert.py [--domain localhost]
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", default="localhost")
    parser.add_argument("--dir", type=Path, default=ROOT / "letsencrypt")
    args = parser.parse_args()

    now = dt.datetime.now(dt.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.domain)])
    sans: list[x509.GeneralName] = [x509.DNSName(args.domain)]
    if args.domain == "localhost":
        sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    live = args.dir / "live" / args.domain
    live.mkdir(parents=True, exist_ok=True)
    (live / "fullchain.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    privkey = live / "privkey.pem"
    privkey.touch(mode=0o600, exist_ok=True)
    privkey.chmod(0o600)
    privkey.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    print(f"Self-signed dev certificate for {args.domain} written to {live} (valid 30 days)")


if __name__ == "__main__":
    main()
