#!/usr/bin/env bash
# WireTap benchmark matrix.
#
# Axes:  receive mode (busy-poll / epoll)
#        recvmmsg batch size (1, 8, 32, 128)
#        CPU pinning (on / off)
#        SO_RCVBUF (default / 64 MB)
#        message rate (100k, 500k, 1M msgs/sec)
#
# Each cell: fixed duration per repeat, a warmup window whose latency samples
# are discarded (--warmup), 5 repeats. Every repeat emits per-stage .hgrm
# histograms + a JSON summary into bench/results/<run>/<cell>/rep<N>/.
#
# The FULL matrix is 2*4*2*2*3 = 96 cells (~4 hours at 10 s repeats). The
# default subset covers the latency-critical comparisons (~25 minutes):
#   busy @500k: batch 1/8/32/128 x pin on/off
#   epoll @500k: batch 32 x pin on/off
#   busy batch32 pin: rcvbuf 64MB, rates 100k and 1M
#   epoll batch32 pin: rcvbuf 64MB
#
# Requirements: built wiretap_recv (../build/wiretap_recv), python3, taskset
# for pinning, root for 64 MB SO_RCVBUF (unprivileged kernels cap rmem_max).
#
#   ./bench/run_bench.sh                     # default subset
#   ./bench/run_bench.sh --full              # all 96 cells
#   ./bench/run_bench.sh --repeats 3 --measure 5 --rate 500000
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="${WIRETAP_BIN:-./build/wiretap_recv}"
FEEDGEN=(python3 tools/feedgen.py)
GROUP="${WIRETAP_GROUP:-239.1.1.1}"
PORT="${WIRETAP_PORT:-31337}"
IFACE="${WIRETAP_IFACE:-lo}"
SEED=20240919

REPEATS=5
MEASURE=10
WARMUP=3
FULL=0
OUT="bench/results/$(date +%Y%m%d-%H%M%S)"
RATES_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --full) FULL=1 ;;
    --repeats) REPEATS="$2"; shift ;;
    --measure) MEASURE="$2"; shift ;;
    --warmup) WARMUP="$2"; shift ;;
    --out) OUT="$2"; shift ;;
    --rate) RATES_ARG="$2"; shift ;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

RATES=()
if [[ -n "$RATES_ARG" ]]; then
  RATES=("$RATES_ARG")
else
  RATES=(100000 500000 1000000)
fi

mkdir -p "$OUT"
echo "benchmark run: $OUT (repeats=$REPEATS measure=${MEASURE}s warmup=${WARMUP}s)"
echo "binary: $BIN"

if ! nproc >/dev/null 2>&1; then nproc() { sysctl -n hw.ncpu; }; fi
NCPU=$(nproc)
RX_CORE=1
DECODE_CORE=2
if [[ $NCPU -lt 3 ]]; then
  RX_CORE=0
  DECODE_CORE=$((NCPU > 1 ? 1 : 0))
fi
PIN="--rx-core $RX_CORE --decode-core $DECODE_CORE"

CELLS=()

add_cell() {  # mode batch pin rcvbuf rate
  local mode="$1" batch="$2" pin="$3" rcvbuf="$4" rate="$5"
  local pinflag="pinon"
  [[ "$pin" == "0" ]] && pinflag="pinoff"
  local rbuf="rbuf0"
  [[ "$rcvbuf" == "67108864" ]] && rbuf="rbuf64m"
  CELLS+=("$mode|$batch|$pinflag|$rbuf|$rate|$pin|$rcvbuf")
}

if [[ $FULL == 1 ]]; then
  for mode in busy epoll; do
    for batch in 1 8 32 128; do
      for pin in 1 0; do
        for rcvbuf in 0 67108864; do
          for rate in "${RATES[@]}"; do
            add_cell "$mode" "$batch" "$pin" "$rcvbuf" "$rate"
          done
        done
      done
    done
  done
else
  for batch in 1 8 32 128; do
    for pin in 1 0; do
      add_cell busy "$batch" "$pin" 0 500000
    done
  done
  for pin in 1 0; do
    add_cell epoll 32 "$pin" 0 500000
  done
  add_cell busy 32 1 67108864 500000
  add_cell epoll 32 1 67108864 500000
  add_cell busy 32 1 0 100000
  add_cell busy 32 1 0 1000000
fi

echo "cells: ${#CELLS[@]} (est. $(( ${#CELLS[@]} * REPEATS * (MEASURE + WARMUP + 4) / 60 )) minutes)"

declare -A TASKSET
if command -v taskset >/dev/null 2>&1; then
  TASKSET[1]="taskset -c $RX_CORE,$DECODE_CORE"
  TASKSET[0]=""
else
  echo "warning: taskset not found; CPU pinning will be unavailable" >&2
  TASKSET[1]=""
  TASKSET[0]=""
fi

CELL_INDEX=0
for cell in "${CELLS[@]}"; do
  IFS='|' read -r mode batch pinflag rbuf rate pin rcvbuf <<<"$cell"
  CELL_INDEX=$((CELL_INDEX + 1))
  CELL_ID="m${mode}_b${batch}_${pinflag}_${rbuf}_r${rate}"
  CELL_DIR="$OUT/$CELL_ID"
  mkdir -p "$CELL_DIR"
  echo "[$CELL_INDEX/${#CELLS[@]}] $CELL_ID"

  for rep in $(seq 1 "$REPEATS"); do
    REP_DIR="$CELL_DIR/rep$rep"
    mkdir -p "$REP_DIR"
    RECV_LOG="$REP_DIR/wiretap_recv.log"

    ARGS=(--group "$GROUP" --port "$PORT" --iface "$IFACE"
          --mode "$mode" --batch "$batch"
          --ring-size 8192
          --warmup "$WARMUP" --duration $((WARMUP + MEASURE))
          --latency-dir "$REP_DIR" --latency-prefix wiretap)
    [[ "$pin" == "1" ]] && ARGS+=(--rx-core "$RX_CORE" --decode-core "$DECODE_CORE")
    [[ "$rcvbuf" != "0" ]] && ARGS+=(--rcvbuf "$rcvbuf")

    # shellcheck disable=SC2086
    ${TASKSET[$pin]} "$BIN" "${ARGS[@]}" >"$RECV_LOG" 2>&1 &
    RECV_PID=$!

    sleep 0.5
    # Feed covers the receiver's whole window plus a tail margin; same seed
    # every repeat makes the stream content identical across repeats.
    "${FEEDGEN[@]}" --mode udp --group "$GROUP" --port "$PORT" --iface "$IFACE" \
      --seed "$SEED" --rate "$rate" --duration $((WARMUP + MEASURE + 1)) \
      >/dev/null 2>&1 || true
    wait "$RECV_PID" || true
    sleep 0.3

    # Parse the summary line into a per-rep summary file.
    grep -E '^summary:' "$RECV_LOG" > "$REP_DIR/summary.txt" || true
  done
done

# Cell metadata for analyze.py.
python3 - <<PYEOF
import json, os
out = "$OUT"
cells = []
for d in sorted(os.listdir(out)):
    p = os.path.join(out, d)
    if not os.path.isdir(p):
        continue
    parts = d.split("_")
    mode = parts[0][1:]
    batch = int(parts[1][1:])
    pinflag = parts[2]
    rbuf = parts[3]
    rate = int(parts[4][1:])
    cells.append({
        "id": d,
        "mode": mode,
        "batch": batch,
        "pinned": pinflag == "pinon",
        "rcvbuf": 67108864 if rbuf == "rbuf64m" else 0,
        "rate": rate,
        "repeats": len([r for r in os.listdir(p) if r.startswith("rep")]),
    })
with open(os.path.join(out, "cells.json"), "w") as f:
    json.dump({"measure_s": $MEASURE, "warmup_s": $WARMUP,
               "cells": cells}, f, indent=2)
print("metadata written")
PYEOF

echo "done: $OUT"
echo "analyze with: python3 bench/analyze.py --results $OUT"
