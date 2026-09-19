# WireTap

Low-latency UDP multicast market-data feed handler. C++17 core that decodes a
simplified NASDAQ TotalView-ITCH 5.0 subset (MoldUDP64 framing) into normalized
book updates and maintains a per-symbol limit order book, plus a Python
tooling layer for feed generation and analysis.

Current milestone: wire format + feed generator + bounds-checked decoder +
lock-free receive path (SPSC ring, busy-poll/epoll UDP multicast receiver,
book builder) + kernel/hardware timestamping, per-stage latency histograms,
and TCP gap recovery with a reorder window. Next up: analysis tooling.

## Layout

```
CMakeLists.txt            # C++17, -O2 -march=native, Release+RelWithDebInfo, GoogleTest
include/wiretap/          # public headers: itch.hpp, book.hpp, spsc_ring.hpp
src/                      # decoder, receiver, book_builder, time_base, latency,
                          # gap_tracker, recovery_client + wiretap_recv/wiretap-dump
tests/                    # GoogleTest unit tests + committed capture fixtures
tools/                    # Python: feedgen.py, bookref.py, retransmit_server.py,
                          #        check_nic_timestamping.sh
docs/wire-format.md       # framing + message field tables
.github/workflows/ci.yml  # ubuntu-latest: build, ctest (incl. ASan), python lint
```

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

GoogleTest is fetched automatically via FetchContent. An ASan+UBSan build for
the out-of-bounds tests:

```sh
cmake -S . -B build-asan -DWIRETAP_SANITIZE=ON
cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure
```

## Generate a capture

```sh
python3 tools/feedgen.py --out capture.bin --messages 1000000
python3 tools/feedgen.py --seed 7 --symbols 50 --rate 250000 --duration 60 --drop-rate 0.001
```

Output is fully deterministic for a given `--seed`. Notable flags:

| Flag          | Meaning                                                        |
|---------------|----------------------------------------------------------------|
| `--seed`      | RNG seed (default 42)                                          |
| `--symbols`   | number of symbols, named `SYM00000..`                          |
| `--messages`  | total messages to generate                                     |
| `--rate`      | target msgs/sec pacing; 0 = flat out (sustains >500k msgs/s)   |
| `--duration`  | seconds to run (overrides `--messages`)                        |
| `--drop-rate` | probability a whole packet is dropped; sequence numbers still advance |
| `--mpp`       | messages per packet (default 128)                              |
| `--mode udp`  | send live to a multicast group (default `239.1.1.1:31337`, `--ttl`, `--iface` for IP_MULTICAST_IF) |
| `--manifest`  | write a TSV of expected decoded updates (round-trip testing)   |

Inspect a capture with the C++ dump tool:

```sh
./build/wiretap-dump capture.bin
```

## Receive a feed

```sh
# terminal 1: generate a live feed on the loopback
python3 tools/feedgen.py --mode udp --iface lo --rate 200000 --duration 30

# terminal 2: receive it
./build/wiretap_recv --iface lo --mode busy --duration 10
```

`wiretap_recv` runs a receive thread and a decode thread connected by a
lock-free SPSC ring. The receive thread never decodes: it stamps arrival time
and pushes raw datagrams; the decode thread decodes and updates the book. No
mutexes, no allocation and no logging on either hot path.

| Flag             | Meaning                                                        |
|------------------|----------------------------------------------------------------|
| `--group/--port` | multicast group (default `239.1.1.1:31337`)                    |
| `--iface`        | interface for `IP_ADD_MEMBERSHIP`                              |
| `--mode busy`    | recvmmsg(MSG_DONTWAIT) tight loop on a pinned core              |
| `--mode epoll`   | edge-triggered epoll_wait + recvmmsg drain (Linux only)        |
| `--batch`        | recvmmsg batch size (default 32)                               |
| `--ring-size`    | SPSC ring slots, power of two (default 8192)                   |
| `--rcvbuf`       | requested `SO_RCVBUF`; the kernel-granted value is reported    |
| `--rx-core`      | pin the receive thread via `pthread_setaffinity_np`            |
| `--decode-core`  | pin the decode thread                                          |
| `--sched-fifo`   | request SCHED_FIFO; prints a CAP_SYS_NICE warning if denied    |
| `--duration`     | stop after N seconds, drain the ring, print stats (0 = SIGINT) |
| `--no-book`      | decode but skip book building                                  |
| `--recover HOST:PORT` | enable gap recovery via the TCP retransmission server      |
| `--reorder-window N`  | out-of-order packet buffer (default 1024)                  |
| `--recover-timeout-ms N` | declare a gap permanently lost after N ms (default 1000) |
| `--latency-dir DIR` | directory for .hgrm histograms + JSON summary (default `.`) |
| `--latency-prefix STR` | report file prefix (default `wiretap`)                    |

Output ends with: packets received, packets/messages decoded, ring drops,
oversize drops, decode errors, final book totals, per-stage latency
percentiles, gap/recovery counters, and the timestamp tier counts.

## Timestamping

`wiretap_recv` enables `SO_TIMESTAMPING` (hardware + software) and falls back
to `SO_TIMESTAMPNS`, then to the userspace clock. The chosen mechanism is
logged at startup and the shutdown report prints how many datagrams actually
carried hardware vs software vs no kernel stamps — a software stamp is never
reported as a hardware one. Check what your NIC advertises:

```sh
sudo tools/check_nic_timestamping.sh eth0
```

Hot-path timing uses rdtsc (calibrated once against CLOCK_MONOTONIC at
startup; a missing `constant_tsc` CPU flag triggers a loud warning);
conversion to nanoseconds happens only when a sample is recorded.

## Latency measurement

Each of these stages is recorded as its own HdrHistogram (3 significant
digits, 1 ns .. 10 s), lock-free per thread, merged only at report time:

| Stage              | Definition                                | Thread   |
|--------------------|-------------------------------------------|----------|
| `wire_to_userspace`| recv_ts - hw/kernel_ts                    | receiver |
| `queue_delay`      | decode_start_ts - recv_ts (ring dwell)    | decode   |
| `decode_time`      | decode_end_ts - decode_start_ts           | decode   |
| `wire_to_book`     | book_applied_ts - hw/kernel_ts (headline) | decode   |

On shutdown the p50/p90/p99/p99.9/p99.99/max table is printed and each stage
is written to `{prefix}-{stage}.hgrm` (HdrHistogram's standard percentile
format) plus a `{prefix}-latency.json` summary.

## Gap detection and recovery

The decode thread tracks the expected sequence number. A missing range opens
a GapEvent, the out-of-order packets are held in a reorder window
(`--reorder-window`, default 1024), and processing continues. A recovery
thread fetches the missing range from a TCP retransmission server and the
window is drained in sequence order once healed. Ranges still missing after
`--recover-timeout-ms` are declared permanently lost (skipped, counted).

Run the retransmission server next to a capture of the full feed:

```sh
python3 tools/feedgen.py --out capture.bin --messages 2000000   # full feed
python3 tools/retransmit_server.py --capture capture.bin --port 38899

# terminal 1: live feed with ~30% of packets dropped (same seed as the capture)
python3 tools/feedgen.py --mode udp --seed 7 --drop-rate 0.3 --rate 100000 --duration 60
# terminal 2:
./build/wiretap_recv --mode busy --recover 127.0.0.1:38899 --duration 60
```

A run with `--drop-rate` is an exact subsequence of the equivalent zero-drop
run (dropping never perturbs the message stream), so the server can always
supply the missing packets. Shutdown reports: gaps detected, healed,
permanently lost, recovered packets, duplicates, window drops, plus a
time-to-heal histogram (`{prefix}-heal.hgrm`).

## Regenerate the test fixture

```sh
python3 tools/feedgen.py --out tests/data/roundtrip.bin \
    --manifest tests/data/roundtrip.tsv --seed 7 --symbols 20 --messages 6000
python3 tools/bookref.py    # -> tests/data/book_expected.tsv

python3 tools/feedgen.py --out tests/data/recovery_full.bin \
    --seed 987 --symbols 20 --messages 8000
python3 tools/feedgen.py --out tests/data/recovery_dropped.bin \
    --seed 987 --symbols 20 --messages 8000 --drop-rate 0.3
```

`RoundTrip.PythonEncodeMatchesCppDecode` compares every decoded BookUpdate
against the manifest; `BookBuilder.FixtureReplayMatchesPythonReference`
compares the final book against the Python reference dump;
`Recovery.RestoresBookByteIdenticalToZeroDropRun` feeds the dropped capture
through the live recovery path and asserts the healed book is byte-identical
to the zero-drop replay. Keep the fixtures under 1 MB each.

## Wire format

See [docs/wire-format.md](docs/wire-format.md).
