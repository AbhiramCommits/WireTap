#include "time_base.hpp"

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <thread>

namespace wiretap {

namespace {

std::uint64_t wall_clock_ns(clockid_t clock) noexcept {
  struct timespec ts {};
  ::clock_gettime(clock, &ts);
  return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull +
         static_cast<std::uint64_t>(ts.tv_nsec);
}

[[maybe_unused]] bool cpu_has_flag(const char* flag) noexcept {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  std::ifstream f("/proc/cpuinfo");
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("flags", 0) == 0 && line.find(flag) != std::string::npos) {
      return true;
    }
  }
#else
  (void)flag;
#endif
  return false;
}

}  // namespace

TimeBase& TimeBase::instance() noexcept {
  static TimeBase tb;
  return tb;
}

std::uint64_t TimeBase::raw_ticks() noexcept {
#if defined(__x86_64__) || defined(__i386__)
  return static_cast<std::uint64_t>(__builtin_ia32_rdtsc());
#else
  return wall_clock_ns(CLOCK_MONOTONIC);
#endif
}

void TimeBase::initialize() {
  if (initialized_)
    return;

#if defined(__x86_64__) || defined(__i386__)
  using_rdtsc_ = true;
  constant_tsc_ = cpu_has_flag("constant_tsc");
  if (!constant_tsc_) {
    std::fprintf(stderr,
                 "wiretap: WARNING: TSC without the constant_tsc CPU flag: "
                 "timestamps can skew across cores. Pin rx/decode threads to "
                 "one core or enable constant_tsc in firmware.\n");
  }
#else
  using_rdtsc_ = false;
  std::fprintf(stderr,
               "wiretap: rdtsc is not available on this platform; the time "
               "base falls back to CLOCK_MONOTONIC.\n");
#endif

  const std::uint64_t t0_ticks = raw_ticks();
  const std::uint64_t t0_mono = wall_clock_ns(CLOCK_MONOTONIC);
  const std::uint64_t t0_real = wall_clock_ns(CLOCK_REALTIME);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  const std::uint64_t t1_ticks = raw_ticks();
  const std::uint64_t t1_mono = wall_clock_ns(CLOCK_MONOTONIC);

  if (using_rdtsc_ && t1_mono > t0_mono && t1_ticks > t0_ticks) {
    ticks_per_second_ = (t1_ticks - t0_ticks) * 1000000000ull / (t1_mono - t0_mono);
  } else {
    ticks_per_second_ = 1000000000ull;  // ticks are already nanoseconds
  }
  epoch_ticks_ = t0_ticks;
  epoch_realtime_ns_ = t0_real;
  initialized_ = true;

  if (using_rdtsc_) {
    std::fprintf(stderr, "wiretap: time base: rdtsc at %.3f GHz, constant_tsc=%s\n",
                 static_cast<double>(ticks_per_second_) / 1e9, constant_tsc_ ? "yes" : "no");
  } else {
    std::fprintf(stderr, "wiretap: time base: CLOCK_MONOTONIC (1 tick = 1 ns)\n");
  }
}

std::uint64_t TimeBase::ticks_to_realtime_ns(std::uint64_t ticks) const noexcept {
  const std::uint64_t d = ticks - epoch_ticks_;
  const std::uint64_t ns = (d / ticks_per_second_) * 1000000000ull +
                           ((d % ticks_per_second_) * 1000000000ull) / ticks_per_second_;
  return epoch_realtime_ns_ + ns;
}

std::uint64_t TimeBase::realtime_ns_to_ticks(std::uint64_t ns) const noexcept {
  const std::uint64_t d = ns - epoch_realtime_ns_;
  const std::uint64_t ticks = (d / 1000000000ull) * ticks_per_second_ +
                              ((d % 1000000000ull) * ticks_per_second_) / 1000000000ull;
  return epoch_ticks_ + ticks;
}

std::uint64_t TimeBase::delta_ns(std::uint64_t end_ticks,
                                 std::uint64_t start_ticks) const noexcept {
  if (end_ticks <= start_ticks)
    return 0;
  const std::uint64_t d = end_ticks - start_ticks;
  return (d / ticks_per_second_) * 1000000000ull +
         ((d % ticks_per_second_) * 1000000000ull) / ticks_per_second_;
}

std::uint64_t TimeBase::ns_to_ticks(std::uint64_t ns) const noexcept {
  return (ns / 1000000000ull) * ticks_per_second_ +
         ((ns % 1000000000ull) * ticks_per_second_) / 1000000000ull;
}

}  // namespace wiretap
