#!/usr/bin/env bash
# Profile wiretap_recv and commit a flamegraph of a representative run to
# docs/. Linux only.
#
# Two modes:
#   1. perf (preferred): hardware counters + perf-record flamegraph.
#      Needs `perf` matching the running kernel and kernel.perf_event_paranoid
#      <= 1 (or CAP_PERFMON). Use --privileged for container runs.
#   2. gprof fallback: builds wiretap_recv with -pg, runs it against the feed,
#      and renders the call graph as a flamegraph. Userspace-only (works in
#      VMs/containers where perf is unavailable, e.g. Docker Desktop).
#      Kernel-level counters are then reported from /proc/<pid> only
#      (context switches, CPU time) - no cycles/instructions/cache-misses.
#
#   ./scripts/profile.sh                    # 20 s feed at 500k msgs/s
#   ./scripts/profile.sh --duration 10 --rate 1000000
#
# Outputs:
#   docs/perf-stat.txt            perf stat, or /proc-derived counters
#   docs/perf-report.txt          perf report --stdio (perf mode only)
#   docs/flamegraph-wiretap.svg   flamegraph of the recorded run
set -euo pipefail

cd "$(dirname "$0")/.."

DURATION=20
RATE=500000
GROUP=239.1.1.1
PORT=31337
IFACE=lo
BIN="${WIRETAP_BIN:-./build/wiretap_recv}"
PROFILE_DIR="$(mktemp -d)"
trap 'rm -rf "$PROFILE_DIR"' EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift ;;
    --rate) RATE="$2"; shift ;;
    --iface) IFACE="$2"; shift ;;
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p docs
WARMUP=3

have_perf() {
  command -v perf >/dev/null 2>&1 && perf stat -e cycles true >/dev/null 2>&1
}

if have_perf; then
  echo "== perf mode =="
  python3 tools/feedgen.py --mode udp --group "$GROUP" --port "$PORT" --iface "$IFACE" \
    --seed 20240919 --rate "$RATE" --duration $((DURATION + 5)) >/dev/null 2>&1 &
  FEED_PID=$!
  sleep 0.5
  set +e
  perf stat -e cycles,instructions,cache-misses,cache-references,branch-misses,context-switches \
    "$BIN" --group "$GROUP" --port "$PORT" --iface "$IFACE" --mode busy --batch 32 \
    --warmup "$WARMUP" --duration "$DURATION" \
    --rx-core 1 --decode-core 2 >"$PROFILE_DIR/stat.out" 2>"$PROFILE_DIR/stat.log"
  set -e
  kill "$FEED_PID" 2>/dev/null || true
  wait "$FEED_PID" 2>/dev/null || true
  { echo "# perf stat: ${DURATION}s feed at ${RATE} msgs/s (busy-poll, batch 32, pinned)";
    cat "$PROFILE_DIR/stat.log";
    grep -E 'summary|timestamps' "$PROFILE_DIR/stat.out"; } > docs/perf-stat.txt
  echo "perf stat written to docs/perf-stat.txt"

  python3 tools/feedgen.py --mode udp --group "$GROUP" --port "$PORT" --iface "$IFACE" \
    --seed 20240919 --rate "$RATE" --duration $((DURATION + 5)) >/dev/null 2>&1 &
  FEED_PID=$!
  sleep 0.5
  set +e
  perf record -F 199 -g -o "$PROFILE_DIR/perf.data" -- \
    "$BIN" --group "$GROUP" --port "$PORT" --iface "$IFACE" --mode busy --batch 32 \
    --warmup "$WARMUP" --duration "$DURATION" --rx-core 1 --decode-core 2 >/dev/null 2>&1
  set -e
  kill "$FEED_PID" 2>/dev/null || true
  wait "$FEED_PID" 2>/dev/null || true
  perf report --stdio -i "$PROFILE_DIR/perf.data" > docs/perf-report.txt 2>/dev/null || true
  echo "perf report written to docs/perf-report.txt"

  FLAMEGRAPH_DIR="${FLAMEGRAPH_DIR:-/tmp/FlameGraph}"
  if [[ ! -f "$FLAMEGRAPH_DIR/stackcollapse-perf.pl" ]]; then
    git clone --depth 1 https://github.com/brendangregg/FlameGraph.git "$FLAMEGRAPH_DIR"
  fi
  perf script -i "$PROFILE_DIR/perf.data" \
    | perl "$FLAMEGRAPH_DIR/stackcollapse-perf.pl" \
    | perl "$FLAMEGRAPH_DIR/flamegraph.pl" > docs/flamegraph-wiretap.svg
  echo "flamegraph written to docs/flamegraph-wiretap.svg (perf)"

else
  echo "== gprof fallback mode (perf unavailable for this kernel) =="
  GPROF_BUILD="$PROFILE_DIR/build-gprof"
  cmake -S . -B "$GPROF_BUILD" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DWIRETAP_GPROF=ON -DWIRETAP_BUILD_TESTS=OFF >/dev/null
  cmake --build "$GPROF_BUILD" -j"$(nproc)" >/dev/null

  # /proc-derived counters for the measured window. Run from PROFILE_DIR so
  # gmon.out lands next to the log.
  ( cd "$PROFILE_DIR" && "$GPROF_BUILD/wiretap_recv" --group "$GROUP" \
      --port "$PORT" --iface "$IFACE" --mode busy --batch 32 \
      --warmup "$WARMUP" --duration "$DURATION" \
      --rx-core 1 --decode-core 2 >"$PROFILE_DIR/out.log" 2>&1 ) &
  RECV_PID=$!
  sleep 0.5
  python3 tools/feedgen.py --mode udp --group "$GROUP" --port "$PORT" --iface "$IFACE" \
    --seed 20240919 --rate "$RATE" --duration $((DURATION + 5)) >/dev/null 2>&1 &
  FEED_PID=$!

  # Sample /proc while the run is live: per-thread CPU time and context
  # switches (voluntary = ring empty yields, involuntary = preemption).
  PROC_LOG="$PROFILE_DIR/proc.log"
  echo "# t=seconds tid utime_s stime_s vol_cs invol_cs (main + rx + decode threads)" > "$PROC_LOG"
  START=$(date +%s)
  while kill -0 "$RECV_PID" 2>/dev/null; do
    NOW=$(date +%s)
    for tid in $(ls /proc/"$RECV_PID"/task 2>/dev/null); do
      STAT=$(awk '{print $14" "$15}' /proc/"$RECV_PID"/task/"$tid"/stat 2>/dev/null) || true
      CS=$(grep -E 'voluntary_ctxt|nonvoluntary_ctxt' /proc/"$RECV_PID"/task/"$tid"/status 2>/dev/null \
        | awk '{print $2}' | paste -sd' ' -) || true
      if [[ -n "$STAT$CS" ]]; then
        echo "$((NOW - START)) $tid ${STAT%% *} ${STAT##* } ${CS%% *} ${CS##* }" >> "$PROC_LOG"
      fi
    done
    sleep 1
  done
  kill "$FEED_PID" 2>/dev/null || true
  wait "$RECV_PID" 2>/dev/null || true
  wait "$FEED_PID" 2>/dev/null || true

  {
    echo "# gprof fallback profile: ${DURATION}s feed at ${RATE} msgs/s"
    echo "# (busy-poll, batch 32, pinned). perf unavailable for this kernel;"
    echo "# hardware counters (cycles/instructions/cache-misses) are NOT reported."
    echo
    grep -E 'summary|timestamps|gaps' "$PROFILE_DIR/out.log"
    echo
    echo "# per-thread CPU time (utime/stime seconds) and context switches"
    echo "# (columns: elapsed_s tid utime_s stime_s voluntary_cs involuntary_cs)"
    echo "# the rx thread is the busy-polling one (high utime, ~0 voluntary cs)"
    cat "$PROC_LOG"
  } > docs/perf-stat.txt
  echo "proc counters written to docs/perf-stat.txt"

  # Flamegraph from the gprof call graph (bench/stackcollapse_gprof.py
  # folds gprof -b output; FlameGraph renders it).
  FLAMEGRAPH_DIR="${FLAMEGRAPH_DIR:-/tmp/FlameGraph}"
  if [[ ! -f "$FLAMEGRAPH_DIR/flamegraph.pl" ]]; then
    git clone --depth 1 https://github.com/brendangregg/FlameGraph.git "$FLAMEGRAPH_DIR"
  fi
  ( cd "$PROFILE_DIR" && gprof -b "$GPROF_BUILD/wiretap_recv" gmon.out ) \
    | tee docs/gprof-raw.txt \
    | python3 bench/stackcollapse_gprof.py \
    | perl "$FLAMEGRAPH_DIR/flamegraph.pl" --title "wiretap_recv busy-poll decode (gprof)" \
    > docs/flamegraph-wiretap.svg
  echo "flamegraph written to docs/flamegraph-wiretap.svg (gprof)"
fi
