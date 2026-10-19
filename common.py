"""Shared helpers: TLS contexts, JWT (HS256, stdlib only), line-JSON framing, byte pipe."""
import asyncio, base64, hashlib, hmac, json, ssl, time
from pathlib import Path

ROOT = Path(__file__).parent
CERTS = ROOT / "certs"
HOST, CLIENT_PORT, CONNECTOR_PORT = "127.0.0.1", 9000, 9001


# ---------- TLS / mTLS ----------
def server_ctx(name):
    """Server side: present our cert AND require a client cert signed by our CA."""
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=CERTS / "ca.crt")
    ctx.load_cert_chain(CERTS / f"{name}.crt", CERTS / f"{name}.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def client_ctx(name=None):
    """Client side: trust only our CA; present cert `name` (None = no client cert)."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CERTS / "ca.crt")
    if name:
        ctx.load_cert_chain(CERTS / f"{name}.crt", CERTS / f"{name}.key")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def peer_fp(writer):
    """SHA-256 fingerprint of the peer's certificate (used to bind tokens to devices)."""
    der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


def peer_cn(writer):
    cert = writer.get_extra_info("ssl_object").getpeercert()
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return ""


# ---------- JWT (HS256) ----------
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_jwt(claims: dict, key: bytes) -> str:
    h = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64(json.dumps(claims).encode())
    sig = _b64(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def verify_jwt(token: str, key: bytes) -> dict:
    try:
        h, p, s = token.split(".")
        header = json.loads(_unb64(h))
    except Exception:
        raise ValueError("malformed token")
    if header.get("alg") != "HS256":  # blocks the classic alg=none attack
        raise ValueError("unexpected algorithm")
    good = _b64(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(good, s):
        raise ValueError("bad signature")
    claims = json.loads(_unb64(p))
    if claims.get("exp", 0) < time.time():
        raise ValueError("token expired")
    return claims


# ---------- framing + piping ----------
async def send(w, obj):
    w.write((json.dumps(obj) + "\n").encode())
    await w.drain()


async def recv(r, timeout=10):
    line = await asyncio.wait_for(r.readline(), timeout)
    if not line:
        raise ConnectionError("peer closed")
    return json.loads(line)


async def _pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def splice(r1, w1, r2, w2):
    """Copy bytes both ways until either side closes."""
    await asyncio.gather(_pipe(r1, w2), _pipe(r2, w1))
