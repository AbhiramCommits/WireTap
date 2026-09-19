#!/usr/bin/env bash
# WireTap demo: brings up the whole stack (feed generator with packet drops,
# retransmission server, handler with archive + recovery, dashboard) and opens
# the browser. Runs a 5-minute synthetic feed by default.
#
#   ./scripts/demo.sh                 # 5-minute feed at 100k msgs/s
#   WIRETAP_DURATION=30 ./scripts/demo.sh   # quick 30-second run
#   WIRETAP_RATE=200000 ./scripts/demo.sh   # faster feed
#   WIRETAP_IFACE=eth0 ./scripts/demo.sh    # real multicast interface
#
# Environment (see docker-compose.yml):
#   WIRETAP_DURATION  seconds to feed (default 300)
#   WIRETAP_RATE      messages/sec (default 100000)
#   WIRETAP_SEED      deterministic feed seed (default 7)
#   WIRETAP_DROP_RATE fraction of packets dropped (default 0.1, exercises
#                     gap detection + recovery)
#   WIRETAP_IFACE     multicast interface (default lo)
set -euo pipefail

cd "$(dirname "$0")/.."
export WIRETAP_DURATION="${WIRETAP_DURATION:-300}"
export WIRETAP_RATE="${WIRETAP_RATE:-100000}"
export WIRETAP_SEED="${WIRETAP_SEED:-7}"
export WIRETAP_DROP_RATE="${WIRETAP_DROP_RATE:-0.1}"
export WIRETAP_IFACE="${WIRETAP_IFACE:-lo}"

echo "== wiretap demo =="
echo "   duration=${WIRETAP_DURATION}s rate=${WIRETAP_RATE} msgs/s"
echo "   drop-rate=${WIRETAP_DROP_RATE} iface=${WIRETAP_IFACE} seed=${WIRETAP_SEED}"

echo "== building images (handler, dashboard) =="
docker compose build handler dashboard

echo "== generating reference capture (zero-drop, same seed) =="
docker compose run --rm demo-init

echo "== starting the stack =="
docker compose up -d retransmit handler feedgen dashboard

URL="http://localhost:8088"
echo
echo "== dashboard: ${URL} =="
echo "   (feed runs for ${WIRETAP_DURATION}s; Ctrl-C here does not stop the"
echo "    stack - use: docker compose down)"
echo

# Open a browser (macOS / Linux with xdg-open).
if command -v open >/dev/null 2>&1; then
    open "${URL}"
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${URL}"
fi

docker compose logs -f handler
