// wiretap/time_base.hpp - process-wide time base for latency measurement.
//
// On x86_64/i386 the hot-path clock is the TSC (rdtsc, ~20 cycles); on other
// platforms it falls back to CLOCK_MONOTONIC nanoseconds. initialize()
// calibrates the TSC frequency once against CLOCK_MONOTONIC, anchors ticks to
// CLOCK_REALTIME, and verifies the constant_tsc CPU flag on Linux (loud
// warning if missing, since per-core TSC offsets would skew timestamps).
//
// All conversions are integer-only (no floating point on the hot path) and
// overflow-safe via quotient/remainder splitting.

#pragma once

#include <cstdint>

namespace wiretap {

class TimeBase {
 public:
  static TimeBase& instance() noexcept;

  // Calibrates the time base (~100 ms). Idempotent. Prints the chosen clock,
  // the calibrated frequency, and the constant_tsc verdict.
  void initialize();

  bool using_rdtsc() const noexcept { return using_rdtsc_; }
  bool constant_tsc() const noexcept { return constant_tsc_; }
  std::uint64_t ticks_per_second() const noexcept { return ticks_per_second_; }

  // Current time in ticks. Cheap on the hot path; safe from any thread.
  std::uint64_t now_ticks() const noexcept { return raw_ticks(); }

  // ticks (from now_ticks) -> wall-clock nanoseconds since the epoch.
  std::uint64_t ticks_to_realtime_ns(std::uint64_t ticks) const noexcept;
  // wall-clock nanoseconds -> ticks (normalizing kernel timestamps).
  std::uint64_t realtime_ns_to_ticks(std::uint64_t ns) const noexcept;
  // Delta between two tick values -> nanoseconds.
  std::uint64_t delta_ns(std::uint64_t end_ticks,
                         std::uint64_t start_ticks) const noexcept;
  // Nanosecond duration -> ticks (for timeout configuration).
  std::uint64_t ns_to_ticks(std::uint64_t ns) const noexcept;

 private:
  TimeBase() = default;
  static std::uint64_t raw_ticks() noexcept;

  std::uint64_t ticks_per_second_ = 1000000000ull;  // default: 1 tick == 1 ns
  std::uint64_t epoch_ticks_ = 0;
  std::uint64_t epoch_realtime_ns_ = 0;
  bool initialized_ = false;
  bool using_rdtsc_ = false;
  bool constant_tsc_ = false;
};

}  // namespace wiretap
