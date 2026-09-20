#!/usr/bin/env bash
# SO_BUSY_POLL / busy_read / rmem_max sweep. Requires root and a real Linux
# kernel that exposes these sysctls (bare metal, or a container runtime that
# allows them - Docker Desktop's VM does NOT).
#
#   sudo ./bench/run_tuning.sh --rate 500000 --repeats 5
#
# Outputs bench/results/tuning-<ts>/<setting>/rep<N>/ histograms; compare with
# bench/analyze.py after copying the run into bench/results/.
set -euo pipefail

cd "$(dirname "$0")/.."

RATE=500000
REPEATS=5
MEASURE=10
WARMUP=3
IFACE=lo
GROUP=239.1.1.1
PORT=31337
BIN="${WIRETAP_BIN:-./build/wiretap_recv}"
OUT="bench/results/tuning-$(date +%Y%m%d-%H%M%S)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rate) RATE="$2"; shift ;;
    --repeats) REPEATS="$2"; shift ;;
    --measure) MEASURE="$2"; shift ;;
    --iface) IFACE="$2"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root (sysctls require it)" >&2
  exit 2
fi

mkdir -p "$OUT"
echo "tuning sweep: $OUT"

# Settings: name, busy_poll (us), busy_read (us), rmem_max (bytes)
SETTINGS=(
  "baseline 0 0 212992"
  "busypoll50 50 0 212992"
  "busypoll200 200 0 212992"
  "busyread200 0 200 212992"
  "rmem64m 0 0 67108864"
)

restore() {
  sysctl -qw net.core.busy_poll=0 net.core.busy_read=0 \
    net.core.rmem_max=212992 || true
}
trap restore EXIT

for setting in "${SETTINGS[@]}"; do
  read -r name busy_poll busy_read rmem_max <<<"$setting"
  sysctl -qw net.core.busy_poll="$busy_poll" net.core.busy_read="$busy_read" \
    net.core.rmem_max="$rmem_max"
  echo "== $name (busy_poll=$busy_poll busy_read=$busy_read rmem_max=$rmem_max) =="
  CELL_DIR="$OUT/$name"
  mkdir -p "$CELL_DIR"
  for rep in $(seq 1 "$REPEATS"); do
    REP_DIR="$CELL_DIR/rep$rep"
    mkdir -p "$REP_DIR"
    "$BIN" --group "$GROUP" --port "$PORT" --iface "$IFACE" --mode busy \
      --batch 32 --warmup "$WARMUP" --duration $((WARMUP + MEASURE)) \
      --latency-dir "$REP_DIR" --latency-prefix wiretap \
      >"$REP_DIR/wiretap_recv.log" 2>&1 &
    RECV_PID=$!
    sleep 0.5
    python3 tools/feedgen.py --mode udp --group "$GROUP" --port "$PORT" \
      --iface "$IFACE" --seed 20240919 --rate "$RATE" \
      --duration $((WARMUP + MEASURE + 1)) >/dev/null 2>&1 || true
    wait "$RECV_PID" || true
    grep -E '^summary:' "$REP_DIR/wiretap_recv.log" > "$REP_DIR/summary.txt" || true
    sleep 0.3
  done
done
restore
echo "done: $OUT"
