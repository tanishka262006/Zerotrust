#!/usr/bin/env bash
# Starts apps + broker + connector, runs the attack suite, prints the audit log, cleans up.
set -e
cd "$(dirname "$0")"
[ -d certs ] || python3 setup.py
rm -f audit.log
python3 apps/private_app.py hr 8081 & python3 apps/private_app.py finance 8082 &
python3 broker.py & sleep 1
python3 connector.py connector-1 & sleep 1
trap 'kill $(jobs -p) 2>/dev/null' EXIT
python3 attacks.py
echo; echo "--- audit.log (last 12) ---"; tail -n 12 audit.log
