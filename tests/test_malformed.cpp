// Malformed-input tests: every truncation point of a valid packet must yield
// an error, and the decoder must never touch memory outside [data, data+len).
// A guard-page test makes out-of-bounds reads a hard crash even without ASan.

#include <gtest/gtest.h>

#include <cstring>

#include "decoder.hpp"
#include "test_common.hpp"

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#define WIRETAP_HAS_GUARD_PAGE 1
#endif

namespace wt = wiretap;

namespace {

std::vector<std::uint8_t> big_valid_packet() {
  std::vector<std::vector<std::uint8_t>> msgs;
  msgs.push_back(testutil::system_event(0x00000000DEADBEEF, 'O'));
  for (int i = 0; i < 40; ++i) {
    msgs.push_back(testutil::add_order(i % 2 ? 'B' : 'S', 1000 + i, 100 + i, "AAPL",
                                       1000000 + i));
  }
  msgs.push_back(testutil::order_executed(1001, 50, 1));
  msgs.push_back(testutil::system_event(0x0000010000000000, 'E'));
  return testutil::packet(msgs, 1);
}

void expect_canary_intact(const std::uint8_t* data, std::size_t len,
                          std::uint8_t canary) {
  for (std::size_t i = len; i < len + 32; ++i) {
    EXPECT_EQ(data[i], canary) << "canary corrupted at offset " << i;
  }
}

}  // namespace

TEST(Malformed, EveryTruncationPointFails) {
  const auto pkt = big_valid_packet();
  wt::Decoder dec;
  for (std::size_t len = 0; len < pkt.size(); ++len) {
    std::vector<wt::BookUpdate> out;
    const auto r = dec.decode_packet(pkt.data(), len, out);
    EXPECT_NE(r.error, wt::DecodeError::Ok) << "prefix len=" << len << " decoded clean";
    EXPECT_TRUE(out.empty()) << "prefix len=" << len << " left partial updates";
  }
}

TEST(Malformed, FullPacketDecodesAtExactLength) {
  const auto pkt = big_valid_packet();
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), pkt.size(), out);
  EXPECT_EQ(r.error, wt::DecodeError::Ok);
  EXPECT_EQ(r.updates_decoded, 43u);
  EXPECT_EQ(out.size(), 43u);
}

TEST(Malformed, CanaryRegionUntouched) {
  const auto pkt = big_valid_packet();
  std::vector<std::uint8_t> buf(pkt.size() + 32, 0xAA);
  std::memcpy(buf.data(), pkt.data(), pkt.size());
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;

  EXPECT_EQ(dec.decode_packet(buf.data(), pkt.size(), out).error, wt::DecodeError::Ok);
  expect_canary_intact(buf.data(), pkt.size(), 0xAA);

  out.clear();
  EXPECT_NE(dec.decode_packet(buf.data(), pkt.size() - 3, out).error,
            wt::DecodeError::Ok);
  expect_canary_intact(buf.data(), pkt.size(), 0xAA);
}

TEST(Malformed, RandomizedFuzzNoCrashNoCanaryDamage) {
  // xorshift32: deterministic across platforms.
  std::uint32_t x = 0x12345678u;
  auto next = [&x]() {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
  };

  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  for (int iter = 0; iter < 20000; ++iter) {
    const std::size_t n = next() % 300;
    std::vector<std::uint8_t> buf(n + 32);
    for (std::size_t i = 0; i < n; ++i) buf[i] = static_cast<std::uint8_t>(next());
    for (std::size_t i = n; i < n + 32; ++i) buf[i] = 0x5A;
    out.clear();
    dec.decode_packet(buf.data(), n, out);  // must never crash
    for (std::size_t i = n; i < n + 32; ++i) {
      ASSERT_EQ(buf[i], 0x5A) << "canary damaged at iter=" << iter << " off=" << i;
    }
  }
}

#if WIRETAP_HAS_GUARD_PAGE
TEST(Malformed, GuardPageCatchesOutOfBoundsReads) {
  const auto pkt = big_valid_packet();
  const long page = ::sysconf(_SC_PAGESIZE);
  ASSERT_GT(page, 0);
  ASSERT_LT(pkt.size(), static_cast<std::size_t>(page) - 64);

  void* base = ::mmap(nullptr, static_cast<std::size_t>(page) * 2,
                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(base, MAP_FAILED);
  ASSERT_EQ(::mprotect(static_cast<char*>(base) + page, static_cast<std::size_t>(page),
                       PROT_NONE),
            0);

  // Packet data ends exactly at the guard page: any read past len faults.
  std::uint8_t* buf =
      static_cast<std::uint8_t*>(base) + page - pkt.size();
  std::memcpy(buf, pkt.data(), pkt.size());

  wt::Decoder dec;
  for (std::size_t len = 0; len < pkt.size(); ++len) {
    std::vector<wt::BookUpdate> out;
    const auto r = dec.decode_packet(buf, len, out);
    EXPECT_NE(r.error, wt::DecodeError::Ok) << "prefix len=" << len;
    EXPECT_TRUE(out.empty());
  }
  {
    std::vector<wt::BookUpdate> out;
    EXPECT_EQ(dec.decode_packet(buf, pkt.size(), out).error, wt::DecodeError::Ok);
  }

  ASSERT_EQ(::munmap(base, static_cast<std::size_t>(page) * 2), 0);
}
#endif
