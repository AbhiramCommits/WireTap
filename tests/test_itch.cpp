#include <gtest/gtest.h>

#include "wiretap/itch.hpp"

namespace wt = wiretap::itch;

TEST(ItchSizes, MatchTotalView5_0Spec) {
  EXPECT_EQ(sizeof(wt::AddOrder), 26u);
  EXPECT_EQ(sizeof(wt::AddOrderMpid), 30u);
  EXPECT_EQ(sizeof(wt::OrderExecuted), 21u);
  EXPECT_EQ(sizeof(wt::OrderCancel), 13u);
  EXPECT_EQ(sizeof(wt::OrderDelete), 9u);
  EXPECT_EQ(sizeof(wt::OrderReplace), 25u);
  EXPECT_EQ(sizeof(wt::TradeNonCross), 34u);
  EXPECT_EQ(sizeof(wt::SystemEvent), 8u);
  EXPECT_EQ(wt::kPacketHeaderSize, 20u);
  EXPECT_EQ(wt::kMessageLengthSize, 2u);
  EXPECT_EQ(wt::kSessionLength, 10u);
  EXPECT_EQ(wt::kMaxMessageSize, 34u);
}

TEST(ItchMessageSize, KnownTypes) {
  EXPECT_EQ(wt::message_size('A'), wt::kAddOrderSize);
  EXPECT_EQ(wt::message_size('F'), wt::kAddOrderMpidSize);
  EXPECT_EQ(wt::message_size('E'), wt::kOrderExecutedSize);
  EXPECT_EQ(wt::message_size('X'), wt::kOrderCancelSize);
  EXPECT_EQ(wt::message_size('D'), wt::kOrderDeleteSize);
  EXPECT_EQ(wt::message_size('U'), wt::kOrderReplaceSize);
  EXPECT_EQ(wt::message_size('P'), wt::kTradeNonCrossSize);
  EXPECT_EQ(wt::message_size('S'), wt::kSystemEventSize);
}

TEST(ItchMessageSize, UnknownTypes) {
  EXPECT_EQ(wt::message_size('R'), 0u);
  EXPECT_EQ(wt::message_size('\0'), 0u);
  EXPECT_FALSE(wt::is_known('Z'));
  EXPECT_TRUE(wt::is_known('S'));
}

TEST(ItchBeDecoders, KnownPatterns) {
  const std::uint8_t bytes[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
  EXPECT_EQ(wt::be16(bytes), 0x0102u);
  EXPECT_EQ(wt::be32(bytes), 0x01020304u);
  EXPECT_EQ(wt::be48(bytes), 0x010203040506ull);
  EXPECT_EQ(wt::be64(bytes), 0x0102030405060708ull);
}

TEST(ItchBeDecoders, UnalignedAccess) {
  const std::uint8_t bytes[] = {0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xBB};
  EXPECT_EQ(wt::be16(bytes + 1), 0x0102u);
  EXPECT_EQ(wt::be32(bytes + 1), 0x01020304u);
  EXPECT_EQ(wt::be48(bytes + 1), 0x010203040506ull);
  EXPECT_EQ(wt::be64(bytes + 1), 0x0102030405060708ull);
}

TEST(ItchBeDecoders, AllOnes) {
  const std::uint8_t ff[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  EXPECT_EQ(wt::be16(ff), 0xFFFFu);
  EXPECT_EQ(wt::be32(ff), 0xFFFFFFFFu);
  EXPECT_EQ(wt::be48(ff), 0x0000FFFFFFFFFFFFull);
  EXPECT_EQ(wt::be64(ff), 0xFFFFFFFFFFFFFFFFull);
}

TEST(ItchLoadUnaligned, MisalignedStructCopy) {
  alignas(16) std::uint8_t buf[16 + 26] = {};
  std::uint8_t* p = buf + 1;  // deliberately misaligned
  p[0] = 'A';
  for (int i = 0; i < 8; ++i)
    p[1 + i] = 0x11;
  p[9] = 'S';
  p[10] = 0x00;
  p[11] = 0x00;
  p[12] = 0x01;
  p[13] = 0xF4;  // 500 shares
  std::memcpy(p + 14, "AAPL    ", 8);
  p[22] = 0x00;
  p[23] = 0x12;
  p[24] = 0xD6;
  p[25] = 0x87;  // 1234567 ticks = $123.4567

  const auto m = wt::load_unaligned<wt::AddOrder>(p);
  EXPECT_EQ(m.type, 'A');
  EXPECT_EQ(m.order_ref_number(), 0x1111111111111111ull);
  EXPECT_EQ(m.side, 'S');
  EXPECT_EQ(m.share_qty(), 500u);
  EXPECT_EQ(m.price_ticks(), 1234567u);
}
