#include <gtest/gtest.h>

#include <cstring>

#include "decoder.hpp"
#include "test_common.hpp"
#include "wiretap/itch.hpp"

namespace wt = wiretap;

namespace {

// One packet containing every supported message type plus an unknown one.
std::vector<std::uint8_t> kitchen_sink_packet() {
  std::vector<std::vector<std::uint8_t>> msgs;
  msgs.push_back(testutil::system_event(0x001122334455, 'O'));
  msgs.push_back(testutil::add_order('B', 0x0102030405060708ull, 700, "AAPL", 1234500));
  msgs.push_back(testutil::add_order_mpid('S', 0x1020304050607080ull, 250, "MSFT",
                                          987654, "WIRE"));
  msgs.push_back(testutil::order_executed(0x0102030405060708ull, 300, 1));
  msgs.push_back(testutil::order_cancel(0x0102030405060708ull, 400));
  msgs.push_back(testutil::order_delete(0x1020304050607080ull));
  msgs.push_back(testutil::order_replace(0x0102030405060708ull, 0xAAAAAAAA55555555ull,
                                         120, 1234600));
  msgs.push_back(testutil::trade_non_cross(0xAAAAAAAA55555555ull, 'B', 120, "AAPL",
                                           1234600, 2));
  // Unknown type 'R', 4-byte payload: must be skipped by length.
  msgs.push_back({0x52, 0x01, 0x02, 0x03});
  return testutil::packet(msgs, 42);
}

}  // namespace

TEST(Decoder, RoundTripsEveryMessageType) {
  const auto pkt = kitchen_sink_packet();
  wt::Decoder dec(/*recv_ts_ns=*/999);
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), pkt.size(), out);
  ASSERT_EQ(r.error, wt::DecodeError::Ok);
  EXPECT_EQ(r.sequence_number, 42u);
  EXPECT_EQ(r.message_count, 9u);
  EXPECT_EQ(r.updates_decoded, 8u);  // 'R' skipped
  ASSERT_EQ(out.size(), 8u);

  {
    const auto& u = out[0];  // SystemEvent
    EXPECT_EQ(u.action, wt::Action::SystemEvent);
    EXPECT_EQ(u.exchange_ts_ns, 0x001122334455ull);
    EXPECT_EQ(u.qty, 0u);
    EXPECT_EQ(u.order_ref, 0u);
    EXPECT_EQ(u.side, wt::Side::Unknown);
  }
  {
    const auto& u = out[1];  // AddOrder
    EXPECT_EQ(u.action, wt::Action::Added);
    EXPECT_EQ(u.order_ref, 0x0102030405060708ull);
    EXPECT_EQ(u.side, wt::Side::Buy);
    EXPECT_EQ(u.qty, 700u);
    EXPECT_EQ(u.price_ticks, 1234500);
    EXPECT_EQ(wt::symbol_string(u.symbol), "AAPL");
  }
  {
    const auto& u = out[2];  // AddOrderMPID
    EXPECT_EQ(u.action, wt::Action::Added);
    EXPECT_EQ(u.order_ref, 0x1020304050607080ull);
    EXPECT_EQ(u.side, wt::Side::Sell);
    EXPECT_EQ(u.qty, 250u);
    EXPECT_EQ(u.price_ticks, 987654);
    EXPECT_EQ(wt::symbol_string(u.symbol), "MSFT");
  }
  {
    const auto& u = out[3];  // OrderExecuted
    EXPECT_EQ(u.action, wt::Action::Executed);
    EXPECT_EQ(u.order_ref, 0x0102030405060708ull);
    EXPECT_EQ(u.qty, 300u);
    EXPECT_EQ(u.price_ticks, 0);
  }
  {
    const auto& u = out[4];  // OrderCancel
    EXPECT_EQ(u.action, wt::Action::Canceled);
    EXPECT_EQ(u.order_ref, 0x0102030405060708ull);
    EXPECT_EQ(u.qty, 400u);
  }
  {
    const auto& u = out[5];  // OrderDelete
    EXPECT_EQ(u.action, wt::Action::Deleted);
    EXPECT_EQ(u.order_ref, 0x1020304050607080ull);
    EXPECT_EQ(u.qty, 0u);
  }
  {
    const auto& u = out[6];  // OrderReplace
    EXPECT_EQ(u.action, wt::Action::Replaced);
    EXPECT_EQ(u.order_ref, 0xAAAAAAAA55555555ull);
    EXPECT_EQ(u.order_ref_old, 0x0102030405060708ull);
    EXPECT_EQ(u.qty, 120u);
    EXPECT_EQ(u.price_ticks, 1234600);
  }
  {
    const auto& u = out[7];  // TradeNonCross
    EXPECT_EQ(u.action, wt::Action::Executed);
    EXPECT_EQ(u.order_ref, 0xAAAAAAAA55555555ull);
    EXPECT_EQ(u.side, wt::Side::Buy);
    EXPECT_EQ(u.qty, 120u);
    EXPECT_EQ(u.price_ticks, 1234600);
    EXPECT_EQ(wt::symbol_string(u.symbol), "AAPL");
  }
  for (const auto& u : out) EXPECT_EQ(u.recv_ts_ns, 999u);
}

TEST(Decoder, AppendsAcrossPackets) {
  const auto pkt = testutil::packet(
      {testutil::add_order('B', 1, 100, "AAPL", 1000000)}, 1);
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  EXPECT_EQ(dec.decode_packet(pkt.data(), pkt.size(), out).error, wt::DecodeError::Ok);
  EXPECT_EQ(dec.decode_packet(pkt.data(), pkt.size(), out).error, wt::DecodeError::Ok);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].order_ref, 1u);
  EXPECT_EQ(out[1].order_ref, 1u);
}

TEST(Decoder, EmptyPacketCountZero) {
  std::vector<std::uint8_t> pkt(20);
  std::memcpy(pkt.data(), "WIRETAP001", 10);
  testutil::put_be64(pkt.data() + 10, 7);
  testutil::put_be16(pkt.data() + 18, 0);
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), pkt.size(), out);
  EXPECT_EQ(r.error, wt::DecodeError::Ok);
  EXPECT_EQ(r.sequence_number, 7u);
  EXPECT_EQ(r.message_count, 0u);
  EXPECT_EQ(r.updates_decoded, 0u);
  EXPECT_TRUE(out.empty());
}

TEST(Decoder, TruncatedHeader) {
  const auto pkt = kitchen_sink_packet();
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  for (std::size_t len = 0; len < wt::itch::kPacketHeaderSize; ++len) {
    out.clear();
    const auto r = dec.decode_packet(pkt.data(), len, out);
    EXPECT_EQ(r.error, wt::DecodeError::TruncatedHeader) << "len=" << len;
    EXPECT_TRUE(out.empty());
  }
}

TEST(Decoder, NullPointer) {
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(nullptr, 0, out);
  EXPECT_EQ(r.error, wt::DecodeError::TruncatedHeader);
}

TEST(Decoder, TruncatedLengthField) {
  // 20-byte header + 1 byte of the first 2-byte length prefix.
  const auto pkt = kitchen_sink_packet();
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), wt::itch::kPacketHeaderSize + 1, out);
  EXPECT_EQ(r.error, wt::DecodeError::TruncatedMessage);
  EXPECT_TRUE(out.empty());
}

TEST(Decoder, TruncatedMessageBody) {
  // Declared count of 2, but the second message is cut short.
  auto pkt = testutil::packet({testutil::add_order('B', 1, 10, "AAPL", 1000000),
                               testutil::order_delete(2)},
                              5);
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), pkt.size() - 1, out);
  EXPECT_EQ(r.error, wt::DecodeError::TruncatedMessage);
  EXPECT_TRUE(out.empty());
}

TEST(Decoder, DeclaredCountExceedsData) {
  // Message count says 2, buffer holds only 1 message.
  auto pkt = testutil::packet({testutil::order_delete(2)}, 5);
  testutil::put_be16(pkt.data() + 18, 2);
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), pkt.size(), out);
  EXPECT_EQ(r.error, wt::DecodeError::TruncatedMessage);
  EXPECT_TRUE(out.empty());
}

TEST(Decoder, ZeroMessageLength) {
  auto pkt = testutil::packet({testutil::order_delete(2)}, 5);
  testutil::put_be16(pkt.data() + 20, 0);  // first message length = 0
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), pkt.size(), out);
  EXPECT_EQ(r.error, wt::DecodeError::BadMessageLength);
  EXPECT_TRUE(out.empty());
}

TEST(Decoder, KnownTypeWrongLength) {
  // 'A' (26 bytes) declared as 25.
  auto pkt = testutil::packet({testutil::add_order('B', 1, 10, "AAPL", 1000000)}, 5);
  testutil::put_be16(pkt.data() + 20, 25);
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), pkt.size(), out);
  EXPECT_EQ(r.error, wt::DecodeError::BadMessageLength);
  EXPECT_TRUE(out.empty());
}

TEST(Decoder, UnknownTypeIsSkippedByLength) {
  std::vector<std::vector<std::uint8_t>> msgs;
  msgs.push_back({0x52, 0x01});  // unknown type 'R', 2-byte payload
  msgs.push_back(testutil::order_delete(7));
  const auto pkt = testutil::packet(msgs, 3);
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), pkt.size(), out);
  EXPECT_EQ(r.error, wt::DecodeError::Ok);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].action, wt::Action::Deleted);
  EXPECT_EQ(out[0].order_ref, 7u);
}

TEST(Decoder, ErrorRollsBackPartialUpdates) {
  const auto good = testutil::packet({testutil::order_delete(1)}, 1);
  // Two messages; the second is truncated so the first decodes then rolls back.
  const auto bad = testutil::packet({testutil::add_order('B', 2, 10, "AAPL", 1000000),
                                     testutil::order_delete(3)},
                                    2);
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  ASSERT_EQ(dec.decode_packet(good.data(), good.size(), out).error, wt::DecodeError::Ok);
  ASSERT_EQ(out.size(), 1u);
  const auto r = dec.decode_packet(bad.data(), bad.size() - 1, out);  // truncated
  EXPECT_EQ(r.error, wt::DecodeError::TruncatedMessage);
  EXPECT_EQ(r.updates_decoded, 0u);
  ASSERT_EQ(out.size(), 1u);  // prior updates preserved, partial rollback done
  EXPECT_EQ(out[0].order_ref, 1u);
}

TEST(Decoder, TrailingBytesAreIgnored) {
  auto pkt = testutil::packet({testutil::order_delete(9)}, 4);
  const std::size_t orig = pkt.size();
  pkt.resize(orig + 5, 0xEE);  // junk after the packet
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), orig, out);
  EXPECT_EQ(r.error, wt::DecodeError::Ok);
  ASSERT_EQ(out.size(), 1u);
}

TEST(Decoder, BadSideCharYieldsUnknown) {
  auto pkt = testutil::packet({testutil::add_order('B', 1, 10, "AAPL", 1000000)}, 5);
  pkt[20 + 2 + 9] = 'Q';  // side byte
  wt::Decoder dec;
  std::vector<wt::BookUpdate> out;
  const auto r = dec.decode_packet(pkt.data(), pkt.size(), out);
  EXPECT_EQ(r.error, wt::DecodeError::Ok);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].side, wt::Side::Unknown);
}

TEST(PacketLength, WalksWellFormedCapture) {
  const auto pkt = kitchen_sink_packet();
  std::size_t len = 0;
  ASSERT_TRUE(wt::packet_length(pkt.data(), pkt.size(), len));
  EXPECT_EQ(len, pkt.size());
}

TEST(PacketLength, RejectsTruncatedInput) {
  const auto pkt = kitchen_sink_packet();
  std::size_t len = 0;
  EXPECT_FALSE(wt::packet_length(pkt.data(), 19, len));
  EXPECT_FALSE(wt::packet_length(pkt.data(), pkt.size() - 1, len));
  EXPECT_FALSE(wt::packet_length(nullptr, 100, len));
}
