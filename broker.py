"""Broker (the 'Zero Trust Exchange'). Two mTLS listeners:
  :9000 clients (devices)  -> login, then connect-to-app requests
  :9001 connectors         -> register apps, then supply per-session data tunnels
Every request is verified: device cert -> token -> device binding -> policy (default deny)."""
import asyncio, hashlib, hmac, json, secrets, time
from common import *

TOKEN_TTL = 300
AUDIT = ROOT / "audit.log"
POLICY = ROOT / "policy.json"


class Deny(Exception):
    pass


def audit(event, **kw):
    with open(AUDIT, "a") as f:
        f.write(json.dumps({"ts": round(time.time(), 2), "event": event, **kw}) + "\n")


def decide(claims, posture, app):
    """Policy engine. Re-reads policy.json every call: policy is data, edits apply instantly."""
    policy = json.loads(POLICY.read_text())
    for rule in policy["rules"]:
        if rule["role"] == claims["role"] and app in rule["apps"]:
            for k, v in rule.get("posture", {}).items():
                if posture.get(k) != v:
                    return False, f"posture check failed: {k}"
            return True, "policy allow"
    return False, "no matching rule (default deny)"


class Broker:
    def __init__(self):
        self.key = (CERTS / "jwt.key").read_bytes()
        self.users = json.loads((CERTS / "users.json").read_text())
        self.controls = {}   # app -> (control writer, connector cn)
        self.pending = {}    # session id -> (future, connector cn, done event)

    # ---------- client side ----------
    async def on_client(self, r, w):
        dev, fp = peer_cn(w), peer_fp(w)
        try:
            if not dev.startswith("device-"):
                raise Deny("certificate is not a device certificate")
            msg = await recv(r)
            if msg.get("type") == "login":
                await self.login(msg, w, dev, fp)
            elif msg.get("type") == "connect":
                await self.connect(msg, r, w, dev, fp)
            else:
                raise Deny("bad request")
        except Deny as e:
            audit("deny", device=dev, reason=str(e))
            await send(w, {"ok": False, "reason": str(e)})
        except Exception as e:
            audit("error", device=dev, error=repr(e))
        finally:
            w.close()

    async def login(self, msg, w, dev, fp):
        u = self.users.get(msg.get("user", ""))
        # always hash, even for unknown users, so timing doesn't reveal which users exist
        salt = bytes.fromhex(u["salt"]) if u else b"\0" * 16
        h = hashlib.pbkdf2_hmac("sha256", msg.get("password", "").encode(), salt, 200_000).hex()
        if not u or not hmac.compare_digest(h, u["hash"]):
            raise Deny("invalid credentials")
        now = int(time.time())
        token = sign_jwt({"sub": msg["user"], "role": u["role"], "iat": now,
                          "exp": now + TOKEN_TTL, "cnf": fp}, self.key)  # cnf = device binding
        audit("login", user=msg["user"], device=dev)
        await send(w, {"ok": True, "token": token})

    async def connect(self, msg, r, w, dev, fp):
        try:
            claims = verify_jwt(msg.get("token", ""), self.key)
        except ValueError as e:
            raise Deny(f"token rejected: {e}")
        if claims.get("cnf") != fp:
            raise Deny("token not bound to this device")
        app = msg.get("app", "")
        ok, reason = decide(claims, msg.get("posture", {}), app)
        if not ok:
            raise Deny(f"{reason} (user={claims['sub']} app={app})")
        ctl = self.controls.get(app)
        if not ctl:
            raise Deny("no connector online for app")
        cw, cname = ctl
        sid = secrets.token_hex(8)
        fut, done = asyncio.get_running_loop().create_future(), asyncio.Event()
        self.pending[sid] = (fut, cname, done)
        await send(cw, {"type": "open", "session": sid, "app": app})
        try:
            dr, dw = await asyncio.wait_for(fut, 5)
        except asyncio.TimeoutError:
            self.pending.pop(sid, None)
            raise Deny("connector did not answer")
        audit("allow", user=claims["sub"], device=dev, app=app, connector=cname, session=sid)
        await send(w, {"ok": True})
        await splice(r, w, dr, dw)
        done.set()
        audit("close", session=sid)

    # ---------- connector side ----------
    async def on_connector(self, r, w):
        cn = peer_cn(w)
        try:
            if not cn.startswith("connector-"):
                raise Deny("certificate is not a connector certificate")
            msg = await recv(r)
            if msg.get("type") == "register":
                allowed = json.loads(POLICY.read_text())["connectors"].get(cn, [])
                bad = [a for a in msg.get("apps", []) if a not in allowed]
                if bad:
                    raise Deny(f"{cn} not authorised for apps {bad}")
                apps = msg["apps"]
                for a in apps:
                    self.controls[a] = (w, cn)
                audit("connector_up", connector=cn, apps=apps)
                await send(w, {"ok": True})
                while await r.read(1024):   # hold control channel open until it drops
                    pass
                for a in apps:
                    if self.controls.get(a, (None,))[0] is w:
                        del self.controls[a]
                audit("connector_down", connector=cn)
            elif msg.get("type") == "data":
                entry = self.pending.pop(msg.get("session"), None)
                if not entry or entry[1] != cn:
                    raise Deny("unknown session")
                entry[0].set_result((r, w))
                await entry[2].wait()       # keep this connection alive while spliced
            else:
                raise Deny("bad request")
        except Deny as e:
            audit("deny", connector=cn, reason=str(e))
            try:
                await send(w, {"ok": False, "reason": str(e)})
            except Exception:
                pass
        except Exception:
            pass
        finally:
            w.close()


async def main():
    b, ctx = Broker(), server_ctx("broker")
    s1 = await asyncio.start_server(b.on_client, HOST, CLIENT_PORT, ssl=ctx)
    s2 = await asyncio.start_server(b.on_connector, HOST, CONNECTOR_PORT, ssl=ctx)
    print(f"broker: clients :{CLIENT_PORT}  connectors :{CONNECTOR_PORT}")
    async with s1, s2:
        await asyncio.gather(s1.serve_forever(), s2.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
