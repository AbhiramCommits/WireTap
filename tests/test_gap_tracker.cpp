// GapTracker unit tests: in-order fast path, gap + heal, duplicates,
// timeout -> permanently lost, window overflow, flush semantics.

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "gap_tracker.hpp"
#include "time_base.hpp"

namespace wt = wiretap;

namespace {

std::vector<std::uint8_t> bytes_for(std::uint64_t seq) {
  std::vector<std::uint8_t> b(24);
  b[0] = static_cast<std::uint8_t>(seq);
  return b;
}

std::uint64_t ticks() { return wt::TimeBase::instance().now_ticks(); }

// Pushes `seq` (as if its packet bytes had arrived) and applies everything
// the tracker releases, appending applied seqs to `applied`.
void push_and_drain(wt::GapTracker& tracker, std::uint64_t seq,
                    std::vector<std::uint64_t>& applied) {
  const auto data = bytes_for(seq);
  const std::uint64_t now = ticks();
  const auto res = tracker.push(seq, now, data.data(), data.size(), now, now);
  if (res.disposition == wt::PacketDisposition::Apply) applied.push_back(seq);
  wt::BufferedPacket p;
  while (tracker.pop_applicable(p)) applied.push_back(p.seq);
}

}  // namespace

TEST(GapTracker, InOrderFastPath) {
  wt::TimeBase::instance().initialize();
  wt::GapTracker tracker;
  std::vector<std::uint64_t> applied;
  for (std::uint64_t s = 1; s <= 100; ++s) push_and_drain(tracker, s, applied);
  ASSERT_EQ(applied.size(), 100u);
  for (std::uint64_t i = 0; i < 100; ++i) EXPECT_EQ(applied[i], i + 1);
  EXPECT_EQ(tracker.gaps_detected(), 0u);
  EXPECT_EQ(tracker.expected_sequence(), 101u);
  EXPECT_TRUE(tracker.settled());
}

TEST(GapTracker, GapDetectedThenHealed) {
  wt::TimeBase::instance().initialize();
  wt::GapTracker tracker;
  std::vector<std::uint64_t> applied;
  push_and_drain(tracker, 1, applied);
  push_and_drain(tracker, 2, applied);
  push_and_drain(tracker, 5, applied);  // gap [3,4] opens; 5 buffered
  ASSERT_EQ(applied.size(), 2u);
  EXPECT_EQ(tracker.gaps_detected(), 1u);
  EXPECT_TRUE(tracker.gap_active());
  EXPECT_EQ(tracker.events().size(), 1u);
  EXPECT_EQ(tracker.events()[0].start, 3u);
  EXPECT_EQ(tracker.events()[0].end, 4u);

  push_and_drain(tracker, 3, applied);  // heals the head
  push_and_drain(tracker, 4, applied);
  // Strict sequence order: 5 was buffered but applies only after 3 and 4.
  ASSERT_EQ(applied.size(), 5u);
  EXPECT_EQ(applied[2], 3u);
  EXPECT_EQ(applied[3], 4u);
  EXPECT_EQ(applied[4], 5u);
  EXPECT_EQ(tracker.gaps_healed(), 1u);
  EXPECT_EQ(tracker.permanently_lost(), 0u);
  EXPECT_TRUE(tracker.settled());
  EXPECT_TRUE(tracker.events()[0].healed);
}

TEST(GapTracker, DuplicatesDiscarded) {
  wt::TimeBase::instance().initialize();
  wt::GapTracker tracker;
  std::vector<std::uint64_t> applied;
  push_and_drain(tracker, 1, applied);
  push_and_drain(tracker, 2, applied);
  push_and_drain(tracker, 2, applied);  // duplicate
  push_and_drain(tracker, 2, applied);
  push_and_drain(tracker, 3, applied);
  ASSERT_EQ(applied.size(), 3u);
  EXPECT_EQ(tracker.duplicates(), 2u);
  EXPECT_EQ(tracker.expected_sequence(), 4u);
}

TEST(GapTracker, TimeoutSkipsToBufferedPacket) {
  wt::TimeBase::instance().initialize();
  const std::uint64_t timeout_ns = 1000000000ull;
  wt::GapTracker tracker(/*window=*/16, timeout_ns);
  std::vector<std::uint64_t> applied;
  push_and_drain(tracker, 1, applied);
  push_and_drain(tracker, 2, applied);
  push_and_drain(tracker, 10, applied);  // gap [3,9]
  EXPECT_TRUE(tracker.gap_active());

  tracker.advance_time(ticks() + wt::TimeBase::instance().ns_to_ticks(timeout_ns + 1));
  wt::BufferedPacket p;
  while (tracker.pop_applicable(p)) applied.push_back(p.seq);

  EXPECT_EQ(tracker.permanently_lost(), 7u);  // 3..9
  EXPECT_EQ(tracker.gaps_healed(), 0u);
  EXPECT_FALSE(tracker.gap_active());  // skipping to the buffered packet closed it
  EXPECT_TRUE(tracker.settled());
  ASSERT_EQ(applied.size(), 3u);
  EXPECT_EQ(applied[2], 10u);
  EXPECT_FALSE(tracker.events()[0].healed);
}

TEST(GapTracker, TimeoutWithoutBufferedAdvancesOneAndRearms) {
  wt::TimeBase::instance().initialize();
  const std::uint64_t timeout_ns = 1000000000ull;
  wt::GapTracker tracker(/*window=*/4, timeout_ns);
  std::vector<std::uint64_t> applied;
  push_and_drain(tracker, 1, applied);
  push_and_drain(tracker, 5, applied);  // gap [2,4]; 5 buffered
  // Evict everything beyond the window to simulate total loss.
  push_and_drain(tracker, 9, applied);   // buffered, gap extends to 8
  push_and_drain(tracker, 10, applied);  // buffered (window 4 holds 9,10 + 5? evictions)
  // Force the timeout path with no useful buffer: skip seqs one at a time.
  for (int i = 0; i < 20; ++i) {
    tracker.advance_time(ticks() + wt::TimeBase::instance().ns_to_ticks(2 * timeout_ns));
    wt::BufferedPacket p;
    while (tracker.pop_applicable(p)) applied.push_back(p.seq);
    if (!tracker.gap_active()) break;
  }
  EXPECT_FALSE(tracker.gap_active());
  EXPECT_GT(tracker.permanently_lost(), 0u);
  EXPECT_EQ(tracker.expected_sequence(), 11u);
}

TEST(GapTracker, WindowOverflowDropsFurthestOut) {
  wt::TimeBase::instance().initialize();
  wt::GapTracker tracker(/*window=*/4, /*timeout_ns=*/60000000000ull);
  std::vector<std::uint64_t> applied;
  push_and_drain(tracker, 1, applied);
  for (std::uint64_t s = 5; s <= 20; ++s) push_and_drain(tracker, s, applied);
  // 16 packets arrive into a 4-slot window: 12 must be evicted.
  EXPECT_EQ(tracker.window_drops(), 12u);
  EXPECT_TRUE(tracker.gap_active());
}

TEST(GapTracker, FlushMarksRemainderLostAndReleasesWindow) {
  wt::TimeBase::instance().initialize();
  wt::GapTracker tracker;
  std::vector<std::uint64_t> applied;
  push_and_drain(tracker, 1, applied);
  push_and_drain(tracker, 2, applied);
  push_and_drain(tracker, 5, applied);  // gap [3,4]
  push_and_drain(tracker, 6, applied);  // buffered
  tracker.flush(ticks());
  wt::BufferedPacket p;
  while (tracker.pop_applicable(p)) applied.push_back(p.seq);
  EXPECT_EQ(tracker.permanently_lost(), 2u);
  EXPECT_EQ(tracker.gaps_healed(), 0u);
  ASSERT_EQ(applied.size(), 4u);
  EXPECT_EQ(applied[2], 5u);
  EXPECT_EQ(applied[3], 6u);
  EXPECT_EQ(tracker.expected_sequence(), 7u);
  EXPECT_TRUE(tracker.settled());
}

TEST(GapTracker, PartialRecoveryCountsLossAndSkips) {
  wt::TimeBase::instance().initialize();
  const std::uint64_t timeout_ns = 1000000000ull;
  wt::GapTracker tracker(/*window=*/16, timeout_ns);
  std::vector<std::uint64_t> applied;
  push_and_drain(tracker, 1, applied);
  push_and_drain(tracker, 6, applied);  // gap [2,5]
  push_and_drain(tracker, 4, applied);  // recovered 4 (buffered)
  push_and_drain(tracker, 5, applied);  // recovered 5 (buffered)
  // 2 and 3 never arrive: timeout skips them, then 4,5 apply.
  tracker.advance_time(ticks() + wt::TimeBase::instance().ns_to_ticks(timeout_ns + 1));
  wt::BufferedPacket p;
  while (tracker.pop_applicable(p)) applied.push_back(p.seq);
  EXPECT_EQ(tracker.permanently_lost(), 2u);
  EXPECT_EQ(tracker.gaps_healed(), 0u);  // partial: not "healed"
  ASSERT_EQ(applied.size(), 4u);
  EXPECT_EQ(applied[1], 4u);
  EXPECT_EQ(applied[2], 5u);
  EXPECT_EQ(applied[3], 6u);
  EXPECT_EQ(tracker.expected_sequence(), 7u);
  EXPECT_TRUE(tracker.settled());
}
