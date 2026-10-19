"""Creates: a private CA, broker/connector/device certs, a ROGUE CA (for attack tests),
users with PBKDF2 password hashes, and the JWT signing key. Needs `openssl`."""
import hashlib, json, secrets, subprocess
from pathlib import Path

C = Path(__file__).parent / "certs"
C.mkdir(exist_ok=True)


def sh(*a):
    subprocess.run(a, check=True, capture_output=True)


def make_ca(name):
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
       "-keyout", f"{C}/{name}.key", "-out", f"{C}/{name}.crt", "-subj", f"/CN={name}",
       "-addext", "basicConstraints=critical,CA:TRUE",
       "-addext", "keyUsage=critical,keyCertSign,cRLSign",
       "-addext", "subjectKeyIdentifier=hash")


def make_leaf(file, cn, ca, eku, san=None):
    sh("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
       "-keyout", f"{C}/{file}.key", "-out", f"{C}/{file}.csr", "-subj", f"/CN={cn}")
    ext = ["basicConstraints=CA:FALSE", "keyUsage=critical,digitalSignature",
           f"extendedKeyUsage={eku}", "subjectKeyIdentifier=hash",
           "authorityKeyIdentifier=keyid"]
    if san:
        ext.append(f"subjectAltName={san}")
    (C / f"{file}.ext").write_text("\n".join(ext) + "\n")
    sh("openssl", "x509", "-req", "-in", f"{C}/{file}.csr", "-CA", f"{C}/{ca}.crt",
       "-CAkey", f"{C}/{ca}.key", "-CAcreateserial", "-out", f"{C}/{file}.crt",
       "-days", "90", "-extfile", f"{C}/{file}.ext")


def pw_hash(pw):
    salt = secrets.token_bytes(16)
    return {"salt": salt.hex(), "hash": hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()}


make_ca("ca")
make_ca("rogue-ca")
make_leaf("broker", "broker", "ca", "serverAuth", "DNS:localhost,IP:127.0.0.1")
for c in ("connector-1", "connector-2"):
    make_leaf(c, c, "ca", "clientAuth")
for d in ("device-laptop-1", "device-laptop-2"):
    make_leaf(d, d, "ca", "clientAuth")
# attacker: same CN as a real device, but signed by a CA the broker does not trust
make_leaf("rogue-device", "device-laptop-1", "rogue-ca", "clientAuth")

users = {"alice": {"role": "intern", **pw_hash("alice-pw")},
         "bob": {"role": "finance", **pw_hash("bob-pw")}}
(C / "users.json").write_text(json.dumps(users, indent=2))
(C / "jwt.key").write_bytes(secrets.token_bytes(32))
print("certs, users and keys written to ./certs  (alice/alice-pw=intern, bob/bob-pw=finance)")
