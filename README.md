# Mini ZTNA: Zero Trust Network Access prototype

A learning prototype of the architecture behind products like Zscaler Private Access (ZPA).
Private apps have **no inbound exposure**; every request is verified on device certificate,
user token, token-to-device binding, device posture and policy (**default deny**).

```
 device (client.py) --mTLS--> BROKER <--mTLS (outbound only)-- connector.py --> private apps
   cert + token + posture      :9000 / :9001                    (127.0.0.1 only)
```

| This project | Zscaler equivalent |
|---|---|
| client.py | Zscaler Client Connector |
| broker.py | Zero Trust Exchange |
| connector.py | ZPA App Connector |
| policy.json | Access policy |
| audit.log | Logs / analytics |

## Run it (Python 3.10+, `openssl`, no pip packages)

```bash
python3 setup.py     # CA, certs, users, signing key (written to ./certs)
./run_demo.sh        # starts everything, runs the attack suite, prints the audit log
```

Manual use: start `apps/private_app.py hr 8081`, `apps/private_app.py finance 8082`, `broker.py`,
`connector.py connector-1`, then:

```bash
python3 client.py --user alice --password alice-pw --app hr
python3 client.py --user alice --password alice-pw --app finance   # DENIED
python3 client.py --user alice --password alice-pw --app hr --bad-posture   # DENIED
```
Edit `policy.json` while the broker runs and the change applies on the next request.

## Attack suite results

| Attack | Blocked by |
|---|---|
| No client certificate / cert from rogue CA | mTLS handshake |
| Wrong password | PBKDF2 check |
| Stolen token used from another device | token bound to device cert fingerprint (`cnf` claim) |
| Tampered token / `alg=none` | HS256 signature + algorithm pinning |
| Intern requests finance app (lateral movement) | per-app policy, default deny |
| Device with firewall off | posture check |
| Device cert used as connector | certificate role check |
| Rogue connector claims the `hr` app | per-connector app allow-list |

## Limitations (deliberate, see DESIGN.md)
Single broker (no HA), posture is self-reported by the client, no TOTP MFA, no token revocation,
no TLS inspection, HS256 shared secret instead of asymmetric signing, no rate limiting.

## Next steps
Docker Compose, TOTP, revocation + continuous verification, benchmarks, rewrite the connector data path in C++ (epoll).
