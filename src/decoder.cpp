#include "decoder.hpp"

#include <cstring>

#include "wiretap/itch.hpp"

namespace wiretap {

bool packet_length(const std::uint8_t* data, std::size_t size,
                   std::size_t& length) noexcept {
  if (data == nullptr || size < itch::kPacketHeaderSize) return false;
  const std::uint16_t count = itch::be16(data + itch::kSessionLength + itch::kSequenceLength);
  std::size_t off = itch::kPacketHeaderSize;
  for (std::uint16_t i = 0; i < count; ++i) {
    if (off + itch::kMessageLengthSize > size) return false;
    const std::uint16_t mlen = itch::be16(data + off);
    off += itch::kMessageLengthSize;
    if (off + mlen > size) return false;
    off += mlen;
  }
  length = off;
  return true;
}

namespace {

inline Side side_from(char c) noexcept {
  return c == 'B' ? Side::Buy : (c == 'S' ? Side::Sell : Side::Unknown);
}

inline void set_symbol(char dst[8], const char* src) noexcept { std::memcpy(dst, src, 8); }

// Decodes one message body into a BookUpdate. `body` points at the type byte;
// the caller has already validated the length against the expected size.
void decode_message(char type, const std::uint8_t* body, BookUpdate& u) noexcept {
  switch (type) {
    case itch::kAddOrderType: {
      const auto m = itch::load_unaligned<itch::AddOrder>(body);
      u.action = Action::Added;
      u.order_ref = m.order_ref_number();
      u.side = side_from(m.side);
      u.qty = m.share_qty();
      u.price_ticks = static_cast<std::int64_t>(m.price_ticks());
      set_symbol(u.symbol, m.stock);
      return;
    }
    case itch::kAddOrderMpidType: {
      const auto m = itch::load_unaligned<itch::AddOrderMpid>(body);
      u.action = Action::Added;
      u.order_ref = m.order_ref_number();
      u.side = side_from(m.side);
      u.qty = m.share_qty();
      u.price_ticks = static_cast<std::int64_t>(m.price_ticks());
      set_symbol(u.symbol, m.stock);
      return;
    }
    case itch::kOrderExecutedType: {
      const auto m = itch::load_unaligned<itch::OrderExecuted>(body);
      u.action = Action::Executed;
      u.order_ref = m.order_ref_number();
      u.qty = m.executed_shares();
      return;
    }
    case itch::kOrderCancelType: {
      const auto m = itch::load_unaligned<itch::OrderCancel>(body);
      u.action = Action::Canceled;
      u.order_ref = m.order_ref_number();
      u.qty = m.canceled_shares();
      return;
    }
    case itch::kOrderDeleteType: {
      const auto m = itch::load_unaligned<itch::OrderDelete>(body);
      u.action = Action::Deleted;
      u.order_ref = m.order_ref_number();
      return;
    }
    case itch::kOrderReplaceType: {
      const auto m = itch::load_unaligned<itch::OrderReplace>(body);
      u.action = Action::Replaced;
      u.order_ref = m.new_ref_number();
      u.order_ref_old = m.original_ref_number();
      u.qty = m.new_share_qty();
      u.price_ticks = static_cast<std::int64_t>(m.new_price_ticks());
      return;
    }
    case itch::kTradeNonCrossType: {
      const auto m = itch::load_unaligned<itch::TradeNonCross>(body);
      u.action = Action::Executed;
      u.order_ref = m.order_ref_number();
      u.side = side_from(m.side);
      u.qty = m.share_qty();
      u.price_ticks = static_cast<std::int64_t>(m.price_ticks());
      set_symbol(u.symbol, m.stock);
      return;
    }
    case itch::kSystemEventType: {
      const auto m = itch::load_unaligned<itch::SystemEvent>(body);
      u.action = Action::SystemEvent;
      u.exchange_ts_ns = m.timestamp_ns();
      return;
    }
    default:
      return;  // unknown types are skipped by the caller
  }
}

}  // namespace

DecodeResult Decoder::decode_packet(const std::uint8_t* data, std::size_t len,
                                    std::vector<BookUpdate>& out) const noexcept {
  DecodeResult res;
  const std::size_t initial = out.size();
  if (data == nullptr || len < itch::kPacketHeaderSize) {
    out.resize(initial);
    res.error = DecodeError::TruncatedHeader;
    return res;
  }

  res.sequence_number = itch::be64(data + itch::kSessionLength);
  res.message_count = itch::be16(data + itch::kSessionLength + itch::kSequenceLength);

  std::size_t off = itch::kPacketHeaderSize;
  for (std::uint16_t i = 0; i < res.message_count; ++i) {
    if (off + itch::kMessageLengthSize > len) {
      out.resize(initial);
      res.error = DecodeError::TruncatedMessage;
      return res;
    }
    const std::uint16_t mlen = itch::be16(data + off);
    off += itch::kMessageLengthSize;
    if (mlen == 0) {
      out.resize(initial);
      res.error = DecodeError::BadMessageLength;
      return res;
    }
    if (off + mlen > len) {
      out.resize(initial);
      res.error = DecodeError::TruncatedMessage;
      return res;
    }

    const char type = static_cast<char>(data[off]);
    const std::size_t expected = itch::message_size(type);
    if (expected != 0) {
      if (mlen != expected) {
        out.resize(initial);
        res.error = DecodeError::BadMessageLength;
        return res;
      }
      BookUpdate u;
      u.recv_ts_ns = recv_ts_ns_;
      decode_message(type, data + off, u);
      out.push_back(u);
    }
    // Unknown message types are skipped using the declared length.
    off += mlen;
  }

  res.updates_decoded = static_cast<std::uint16_t>(out.size() - initial);
  res.error = DecodeError::Ok;
  return res;
}

}  // namespace wiretap
