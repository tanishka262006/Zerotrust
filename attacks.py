"""Attack suite: tries to break the system. Every attack must be BLOCKED; the control must succeed.
Run with the stack up (see run_demo.sh). Prints a table: attack -> result -> why."""
import asyncio, json, sys
from client import GOOD, connect, http_get, login, _open
from common import *
from common import _b64

rows = []


def record(name, blocked, detail):
    rows.append((name, "BLOCKED" if blocked else "!! SUCCEEDED !!", detail))


async def try_raw(ctxname):
    """Open a TLS session with the given cert (or none) and try to talk to the broker."""
    try:
        r, w = await asyncio.open_connection(
            HOST, CLIENT_PORT, ssl=client_ctx(ctxname), server_hostname="localhost")
        await send(w, {"type": "login", "user": "alice", "password": "alice-pw"})
        resp = await recv(r)
        return resp.get("ok") is not True, "broker refused" if not resp.get("ok") else "got token"
    except Exception as e:
        return True, f"TLS/connection failed ({type(e).__name__})"


async def main():
    # control: the legitimate path must work, otherwise "blocked" proves nothing
    lg = await login("device-laptop-1", "alice", "alice-pw")
    resp, r, w = await connect("device-laptop-1", lg["token"], "hr")
    body = await http_get(r, w) if resp["ok"] else ""
    ok = resp["ok"] and "HR" in body
    rows.append(("CONTROL: alice -> hr, healthy device", "ALLOWED" if ok else "!! BROKEN !!", body.strip()))

    b, d = await try_raw(None);            record("No client certificate", b, d)
    b, d = await try_raw("rogue-device");  record("Cert from a rogue CA", b, d)

    resp = await login("device-laptop-1", "alice", "wrong")
    record("Wrong password", not resp["ok"], resp.get("reason", ""))

    resp, *_ = await connect("device-laptop-2", lg["token"], "hr")   # token stolen from laptop-1
    record("Stolen token replayed from another device", not resp["ok"], resp.get("reason", ""))

    h, p, s = lg["token"].split(".")
    forged = json.loads(base64_decode(p)); forged["role"] = "finance"
    resp, *_ = await connect("device-laptop-1", f"{h}.{_b64(json.dumps(forged).encode())}.{s}", "finance")
    record("Tampered token (role -> finance)", not resp["ok"], resp.get("reason", ""))

    none_tok = f"{_b64(b'{\"alg\":\"none\"}')}.{p}."
    resp, *_ = await connect("device-laptop-1", none_tok, "hr")
    record("JWT alg=none", not resp["ok"], resp.get("reason", ""))

    resp, *_ = await connect("device-laptop-1", lg["token"], "finance")
    record("Lateral movement: intern -> finance app", not resp["ok"], resp.get("reason", ""))

    resp, *_ = await connect("device-laptop-1", lg["token"], "hr", {**GOOD, "firewall": False})
    record("Non-compliant device (firewall off)", not resp["ok"], resp.get("reason", ""))

    for label, cert in (("Device cert used as a connector", "device-laptop-1"),
                        ("Rogue connector claims 'hr'", "connector-2")):
        try:
            r, w = await asyncio.open_connection(HOST, CONNECTOR_PORT, ssl=client_ctx(cert),
                                                 server_hostname="localhost")
            await send(w, {"type": "register", "apps": ["hr"]})
            resp = await recv(r)
            record(label, not resp.get("ok"), resp.get("reason", ""))
        except Exception as e:
            record(label, True, f"connection failed ({type(e).__name__})")

    wid = max(len(x[0]) for x in rows)
    print(f"\n{'ATTACK'.ljust(wid)}  {'RESULT':<16}  DETAIL")
    for n, res, det in rows:
        print(f"{n.ljust(wid)}  {res:<16}  {det}")
    bad = [x for x in rows if "!!" in x[1]]
    print("\nALL ATTACKS BLOCKED" if not bad else f"\n{len(bad)} PROBLEM(S)")
    sys.exit(1 if bad else 0)


def base64_decode(s):
    from common import _unb64
    return _unb64(s)


asyncio.run(main())
