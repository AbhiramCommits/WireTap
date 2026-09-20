// SPSC ring tests: FIFO order under contention, drop accounting, API basics.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

#include "wiretap/spsc_ring.hpp"

namespace wt = wiretap;

namespace {

struct alignas(64) Item {
  std::uint64_t seq;
  std::uint64_t payload[7];  // 64-byte slot
};

Item make_item(std::uint64_t seq) {
  Item it{};
  it.seq = seq;
  for (int i = 0; i < 7; ++i)
    it.payload[i] = seq * 31 + static_cast<std::uint64_t>(i);
  return it;
}

}  // namespace

TEST(SpscRing, CapacityRoundedToPowerOfTwo) {
  wt::SpscRing<Item> ring(5);
  EXPECT_EQ(ring.capacity(), 8u);
  wt::SpscRing<Item> ring2(1);
  EXPECT_EQ(ring2.capacity(), 1u);
  wt::SpscRing<Item> ring3(1024);
  EXPECT_EQ(ring3.capacity(), 1024u);
  wt::SpscRing<Item> ring4(0);
  EXPECT_EQ(ring4.capacity(), 1u);
}

TEST(SpscRing, PushPopFifo) {
  wt::SpscRing<Item> ring(4);
  for (std::uint64_t i = 0; i < 4; ++i)
    EXPECT_TRUE(ring.try_push(make_item(i)));
  EXPECT_TRUE(ring.full());
  EXPECT_FALSE(ring.try_push(make_item(99)));  // full
  EXPECT_EQ(ring.drops(), 1u);

  Item out;
  for (std::uint64_t i = 0; i < 4; ++i) {
    ASSERT_TRUE(ring.try_pop(out));
    EXPECT_EQ(out.seq, i);
  }
  EXPECT_FALSE(ring.try_pop(out));  // empty
  EXPECT_TRUE(ring.empty());
}

TEST(SpscRing, DropCounterCountsRejectedPushes) {
  wt::SpscRing<Item> ring(4);
  for (std::uint64_t i = 0; i < 10; ++i)
    ring.try_push(make_item(i));
  EXPECT_EQ(ring.drops(), 6u);  // 10 - 4 slots
  Item out;
  for (std::uint64_t i = 0; i < 4; ++i) {
    ASSERT_TRUE(ring.try_pop(out));
    EXPECT_EQ(out.seq, i);  // first 4 survive
  }
  EXPECT_FALSE(ring.try_pop(out));
}

TEST(SpscRing, SingleSlotBounce) {
  wt::SpscRing<Item> ring(1);
  Item out;
  EXPECT_TRUE(ring.try_push(make_item(1)));
  EXPECT_FALSE(ring.try_push(make_item(2)));
  ASSERT_TRUE(ring.try_pop(out));
  EXPECT_EQ(out.seq, 1u);
  EXPECT_TRUE(ring.try_push(make_item(3)));
  ASSERT_TRUE(ring.try_pop(out));
  EXPECT_EQ(out.seq, 3u);
  EXPECT_EQ(ring.drops(), 1u);
}

TEST(SpscRing, StressTenMillionItemsFifoNoLoss) {
  constexpr std::uint64_t kTotal = 10'000'000;
  wt::SpscRing<Item> ring(1u << 20);

  std::atomic<bool> producer_done{false};
  std::atomic<std::uint64_t> pushed{0};

  std::thread producer([&] {
    for (std::uint64_t i = 0; i < kTotal; ++i) {
      while (!ring.try_push(make_item(i))) {
        // Never blocks forever: the consumer keeps up by design.
        ASSERT_LT(ring.drops(), 1u);
      }
      pushed.fetch_add(1, std::memory_order_relaxed);
    }
    producer_done.store(true, std::memory_order_release);
  });

  std::uint64_t popped = 0;
  Item out;
  bool saw_gap = false;
  std::uint64_t expected = 0;
  while (!producer_done.load(std::memory_order_acquire) || popped < kTotal) {
    if (!ring.try_pop(out)) {
      if (producer_done.load(std::memory_order_acquire))
        break;
      continue;
    }
    if (out.seq != expected)
      saw_gap = true;  // FIFO violation
    for (int i = 0; i < 7; ++i) {
      if (out.payload[i] != expected * 31 + static_cast<std::uint64_t>(i)) {
        saw_gap = true;  // corruption
      }
    }
    ++expected;
    ++popped;
  }
  producer.join();

  EXPECT_EQ(pushed.load(), kTotal);
  EXPECT_EQ(popped, kTotal);
  EXPECT_FALSE(saw_gap);
  EXPECT_EQ(ring.drops(), 0u);  // zero loss when the consumer keeps up
  EXPECT_TRUE(ring.empty());
}

TEST(SpscRing, SizeApproximatesOccupancy) {
  wt::SpscRing<Item> ring(8);
  EXPECT_EQ(ring.size(), 0u);
  ring.try_push(make_item(1));
  ring.try_push(make_item(2));
  EXPECT_EQ(ring.size(), 2u);
  Item out;
  ring.try_pop(out);
  EXPECT_EQ(ring.size(), 1u);
}
