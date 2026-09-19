# WireTap

Low-latency UDP multicast market-data feed handler. C++17 core that decodes a
simplified NASDAQ TotalView-ITCH 5.0 subset (MoldUDP64 framing) into normalized
book updates and maintains a per-symbol limit order book, plus a Python
tooling layer for feed generation and analysis.

Current milestone: wire format + feed generator + bounds-checked decoder +
lock-free receive path (SPSC ring, busy-poll/epoll UDP multicast receiver,
book builder). Next up: gap recovery and analysis tooling.

## Layout

```
CMakeLists.txt            # C++17, -O2 -march=native, Release+RelWithDebInfo, GoogleTest
include/wiretap/          # public headers: itch.hpp, book.hpp, spsc_ring.hpp
src/                      # decoder, receiver, book_builder + wiretap_recv/wiretap-dump
tests/                    # GoogleTest unit tests + committed capture fixture
tools/                    # Python: feedgen.py, bookref.py
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

Output ends with: packets received, packets/messages decoded, ring drops,
oversize drops, decode errors, and final book totals.

## Regenerate the test fixture

```sh
python3 tools/feedgen.py --out tests/data/roundtrip.bin \
    --manifest tests/data/roundtrip.tsv --seed 7 --symbols 20 --messages 6000
python3 tools/bookref.py    # -> tests/data/book_expected.tsv
```

`RoundTrip.PythonEncodeMatchesCppDecode` compares every decoded BookUpdate
against the manifest; `BookBuilder.FixtureReplayMatchesPythonReference`
replays the capture and compares the final book against the Python reference
dump. Keep the fixture under 1 MB.

## Wire format

See [docs/wire-format.md](docs/wire-format.md).
