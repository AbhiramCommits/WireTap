# Contributing to WireTap

## Build, test, lint

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure

# Sanitizers (address + UB) and ThreadSanitizer (must stay clean):
cmake -S . -B build-asan -DWIRETAP_SANITIZE=ON && cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
cmake -S . -B build-tsan -DWIRETAP_TSAN=ON && cmake --build build-tsan -j
ctest --test-dir build-tsan --output-on-failure

# Formatting (CI enforces this) and static analysis (CI enforces this):
clang-format --dry-run -Werror $(find include src tests -name '*.cpp' -o -name '*.hpp')
# clang-tidy runs against compile_commands.json:
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
clang-tidy -p build src/*.cpp

# Python:
ruff check tools/ bench/
python3 -m py_compile tools/feedgen.py tools/analytics.py tools/dashboard/backend.py
```

`clang-format` (`.clang-format`) is the single source of truth for C++ style;
CI pins version 18 (`pip install clang-format==18.1.8` to match it locally,
or `apt install clang-format` on Ubuntu 24.04), and runs
`clang-format --dry-run -Werror`. Run `clang-format -i <file>` before
committing. `.clang-tidy` enables `clang-analyzer-*`, `bugprone-*`, and
`performance-*` as errors; two checks are deliberately disabled and
documented in the config: `bugprone-exception-escape` (the hot path is
intentionally `noexcept`; OOM terminates by design) and
`performance-inefficient-string-concatenation` (the JSON snapshot builder
concatenates deliberately).

## Committed test data

`tests/data/*.bin` + `*.tsv` are generated deterministically:

```sh
python3 tools/feedgen.py --out tests/data/roundtrip.bin \
    --manifest tests/data/roundtrip.tsv --seed 7 --symbols 20 --messages 6000
python3 tools/bookref.py
python3 tools/feedgen.py --out tests/data/recovery_full.bin \
    --seed 987 --symbols 20 --messages 8000
python3 tools/feedgen.py --out tests/data/recovery_dropped.bin \
    --seed 987 --symbols 20 --messages 8000 --drop-rate 0.3
```

If a change alters feedgen output, regenerate all five files and update the
round-trip expectations. A run with `--drop-rate` must remain an exact
subsequence of the zero-drop run.

## Benchmarking

```sh
./bench/run_bench.sh                  # default matrix (~20 min, 14 cells)
./bench/run_bench.sh --full           # full 96-cell matrix (~4 h)
python3 bench/analyze.py              # -> bench/REPORT.md + bench/plots.html
```

Every number in the docs must be reproducible: label it with the command that
produced it and the hardware it ran on. Never hand-edit benchmark outputs into
documentation without running the harness.

## Writing code for the hot path

- rx and decode threads: no allocation, no locking, no logging, no
  `std::cout`, no blocking syscalls. Downstream pushes are `try_push` and
  failures must be counted, never retried.
- All cross-thread counters are relaxed atomics; histograms are per-thread and
  merged only after join.
- Malformed input returns an error enum; exceptions are for startup and
  shutdown paths only.
- Timestamp reporting must stay honest: the shutdown report distinguishes
  hardware / kernel-software / userspace stamps, and a tier can never be
  reported as a better one than it is.
