# Design notes

## Threat model
| Threat | Mitigation | Where |
|---|---|---|
| Attacker on the network scans for apps | Apps bind 127.0.0.1; connector dials out only | connector.py |
| Stolen password | PBKDF2 (200k), constant-time compare, short-lived tokens | broker.login |
| Stolen token | Token carries `cnf` = SHA-256 of device cert; checked against the live mTLS cert | broker.connect |
| Forged / tampered token | HS256 signature, algorithm pinned | common.verify_jwt |
| Compromised user moves laterally | Per-app policy, default deny | broker.decide |
| Unhealthy device | Posture required by policy | broker.decide |
| Rogue connector hijacks an app | Per-connector allow-list; sessions bound to the connector that registered | broker.on_connector |
| Untrusted client or connector | mTLS against a private CA, TLS 1.3 only | common.server_ctx |
| Repudiation | JSON audit log of every decision | broker.audit |

## Key decisions
- **Outbound-only connector:** broker sends `open` over the connector's control channel; the connector then
  dials a *new* outbound data connection per session. No inbound firewall holes, works behind NAT.
- **Token binding (RFC 8705 idea):** a stolen JWT is useless without the device's private key.
- **Policy as data, re-read per request:** simple and demonstrable; production would cache with invalidation.
- **Stdlib-only JWT:** to understand the format. Production should use a vetted library.
- **Line-delimited JSON control protocol, then raw byte splice:** simple to debug.

## Limitations / what I'd do next
1. Posture is self-reported; real systems use an attested agent or MDM signal.
2. No revocation: a token lives up to 5 minutes. Fix: session registry + push-based kill.
3. Single broker: stateless brokers behind a load balancer, shared session store.
4. Add TOTP MFA and rate limiting on login.
5. Benchmarks: per-request latency and throughput; likely bottleneck is per-session TLS setup on the connector.
6. Rewrite the connector data path in C++ with epoll.
