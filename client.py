"""Client agent: reports device posture, logs in, asks the broker for ONE app."""
import argparse, asyncio
from common import *

GOOD = {"os_patched": True, "disk_encrypted": True, "firewall": True}


async def _open(device):
    return await asyncio.open_connection(HOST, CLIENT_PORT, ssl=client_ctx(device),
                                         server_hostname="localhost")


async def login(device, user, password):
    r, w = await _open(device)
    await send(w, {"type": "login", "user": user, "password": password})
    resp = await recv(r)
    w.close()
    return resp


async def connect(device, token, app, posture=GOOD):
    r, w = await _open(device)
    await send(w, {"type": "connect", "token": token, "app": app, "posture": posture})
    return await recv(r), r, w


async def http_get(r, w, path="/"):
    w.write(f"GET {path} HTTP/1.1\r\nHost: app\r\nConnection: close\r\n\r\n".encode())
    await w.drain()
    data = await r.read()
    return data.decode(errors="replace").split("\r\n\r\n", 1)[-1]


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default="device-laptop-1")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--app", required=True)
    ap.add_argument("--path", default="/")
    ap.add_argument("--bad-posture", action="store_true", help="simulate firewall off")
    a = ap.parse_args()
    resp = await login(a.device, a.user, a.password)
    if not resp["ok"]:
        return print("login denied:", resp["reason"])
    posture = {**GOOD, "firewall": False} if a.bad_posture else GOOD
    resp, r, w = await connect(a.device, resp["token"], a.app, posture)
    if not resp["ok"]:
        return print("DENIED:", resp["reason"])
    print(await http_get(r, w, a.path), end="")


if __name__ == "__main__":
    asyncio.run(main())
