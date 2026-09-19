#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <thread>

#include "time_base.hpp"

namespace wt = wiretap;

TEST(TimeBase, InitializeIsIdempotent) {
  wt::TimeBase& tb = wt::TimeBase::instance();
  tb.initialize();
  const std::uint64_t tps = tb.ticks_per_second();
  EXPECT_GT(tps, 0u);
  tb.initialize();  // second call must not recalibrate
  EXPECT_EQ(tb.ticks_per_second(), tps);
}

TEST(TimeBase, NowTicksMonotonic) {
  wt::TimeBase& tb = wt::TimeBase::instance();
  tb.initialize();
  std::uint64_t prev = tb.now_ticks();
  for (int i = 0; i < 10000; ++i) {
    const std::uint64_t now = tb.now_ticks();
    EXPECT_GE(now, prev);
    prev = now;
  }
}

TEST(TimeBase, DeltaConversionRoundTrip) {
  wt::TimeBase& tb = wt::TimeBase::instance();
  tb.initialize();
  // 1 ms worth of ticks -> ~1,000,000 ns (within rounding).
  const std::uint64_t span = tb.ticks_per_second() / 1000;
  const std::uint64_t ns = tb.delta_ns(span, 0);
  EXPECT_NEAR(static_cast<double>(ns), 1e6, 1000.0);
  // ns -> ticks -> ns identity.
  EXPECT_EQ(tb.delta_ns(tb.ns_to_ticks(1234567), 0), 1234567u);
}

TEST(TimeBase, RealtimeMappingMatchesWallClock) {
  wt::TimeBase& tb = wt::TimeBase::instance();
  tb.initialize();
  struct timespec ts {};
  ::clock_gettime(CLOCK_REALTIME, &ts);
  const std::uint64_t wall = static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull +
                             static_cast<std::uint64_t>(ts.tv_nsec);
  const std::uint64_t mapped = tb.ticks_to_realtime_ns(tb.now_ticks());
  const std::int64_t diff = mapped > wall ? static_cast<std::int64_t>(mapped - wall)
                                          : static_cast<std::int64_t>(wall - mapped);
  EXPECT_LT(diff, 2 * 1000000000LL);  // within 2 s of the wall clock

  // realtime ns -> ticks -> realtime ns round trip (sub-microsecond).
  const std::uint64_t ticks = tb.realtime_ns_to_ticks(wall);
  const std::uint64_t back = tb.ticks_to_realtime_ns(ticks);
  EXPECT_NEAR(static_cast<double>(back), static_cast<double>(wall), 1000.0);
}

TEST(TimeBase, TicksAdvanceOverSleep) {
  wt::TimeBase& tb = wt::TimeBase::instance();
  tb.initialize();
  const std::uint64_t a = tb.now_ticks();
  std::this_thread::sleep_for(std::chrono::milliseconds(5));
  const std::uint64_t b = tb.now_ticks();
  const std::uint64_t ns = tb.delta_ns(b, a);
  EXPECT_GT(ns, 1000000u);   // at least 1 ms elapsed
  EXPECT_LT(ns, 1000000000u); // less than 1 s
}
