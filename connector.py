"""App connector. Sits next to the private apps and ONLY dials OUT to the broker.
No inbound port is opened for the apps, so there is nothing for an attacker to scan."""
import asyncio, sys
from common import *

APPS = {"hr": ("127.0.0.1", 8081), "finance": ("127.0.0.1", 8082)}
tasks = set()


async def open_session(name, sid, app):
    try:
        ar, aw = await asyncio.open_connection(*APPS[app])
        r, w = await asyncio.open_connection(HOST, CONNECTOR_PORT, ssl=client_ctx(name),
                                             server_hostname="localhost")
        await send(w, {"type": "data", "session": sid})
        await splice(r, w, ar, aw)
    except Exception as e:
        print("session error:", repr(e))


async def serve(name, apps):
    while True:
        try:
            r, w = await asyncio.open_connection(HOST, CONNECTOR_PORT, ssl=client_ctx(name),
                                                 server_hostname="localhost")
            await send(w, {"type": "register", "apps": apps})
            ack = await recv(r)
            if not ack.get("ok"):
                print("registration refused:", ack.get("reason"))
                return
            print(f"{name} registered apps {apps}")
            while True:
                msg = await recv(r, timeout=None)
                if msg.get("type") == "open" and msg["app"] in APPS:
                    t = asyncio.create_task(open_session(name, msg["session"], msg["app"]))
                    tasks.add(t); t.add_done_callback(tasks.discard)
        except (OSError, ConnectionError):
            await asyncio.sleep(2)   # broker down: retry (outbound only)


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "connector-1"
    asyncio.run(serve(name, list(APPS)))
