# WireTap

Low-latency UDP multicast market-data feed handler. C++17 core that decodes a
simplified NASDAQ TotalView-ITCH 5.0 subset (MoldUDP64 framing) into normalized
book updates, plus a Python tooling layer for feed generation and analysis.

Current milestone: scaffold + wire format + synthetic feed generator + bounds
checked decoder. No UDP sockets in the C++ layer yet.

## Layout

```
CMakeLists.txt            # C++17, -O2 -march=native, Release+RelWithDebInfo, GoogleTest
include/wiretap/          # public headers: itch.hpp (wire structs), book.hpp
src/                      # core library (decoder.cpp/.hpp) + wiretap-dump binary
tests/                    # GoogleTest unit tests + committed capture fixture
tools/                    # Python: feedgen.py
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

## Regenerate the test fixture

```sh
python3 tools/feedgen.py --out tests/data/roundtrip.bin \
    --manifest tests/data/roundtrip.tsv --seed 7 --symbols 20 --messages 6000
```

`RoundTrip.PythonEncodeMatchesCppDecode` compares every decoded BookUpdate
against the manifest, so the fixture must stay under 1 MB.

## Wire format

See [docs/wire-format.md](docs/wire-format.md).
