// wiretap/itch.hpp - NASDAQ TotalView-ITCH 5.0 (subset) wire-format structs.
//
// Multi-byte numeric fields are big-endian, exactly as on the wire. The
// structs below are packed PODs describing the on-wire layout: copy them out
// of a buffer with load_unaligned() before touching members, because packet
// buffers are not guaranteed to be aligned.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace wiretap {
namespace itch {

// ---------------------------------------------------------------------------
// Framing (MoldUDP64-style)
//   session[10] | sequence_number u64 BE | message_count u16 BE | messages...
// ---------------------------------------------------------------------------

inline constexpr std::size_t kSessionLength = 10;
inline constexpr std::size_t kSequenceLength = 8;
inline constexpr std::size_t kCountLength = 2;
inline constexpr std::size_t kPacketHeaderSize =
    kSessionLength + kSequenceLength + kCountLength;  // 20 bytes
inline constexpr std::size_t kMessageLengthSize = 2;  // u16 BE prefix per message

// ---------------------------------------------------------------------------
// Message sizes (payload only; excludes the u16 length prefix)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kAddOrderSize = 26;       // 'A'
inline constexpr std::size_t kAddOrderMpidSize = 30;   // 'F'
inline constexpr std::size_t kOrderExecutedSize = 21;  // 'E'
inline constexpr std::size_t kOrderCancelSize = 13;    // 'X'
inline constexpr std::size_t kOrderDeleteSize = 9;     // 'D'
inline constexpr std::size_t kOrderReplaceSize = 25;   // 'U'
inline constexpr std::size_t kTradeNonCrossSize = 34;  // 'P'
inline constexpr std::size_t kSystemEventSize = 8;     // 'S'

inline constexpr std::size_t kMaxMessageSize = kTradeNonCrossSize;

inline constexpr char kAddOrderType = 'A';
inline constexpr char kAddOrderMpidType = 'F';
inline constexpr char kOrderExecutedType = 'E';
inline constexpr char kOrderCancelType = 'X';
inline constexpr char kOrderDeleteType = 'D';
inline constexpr char kOrderReplaceType = 'U';
inline constexpr char kTradeNonCrossType = 'P';
inline constexpr char kSystemEventType = 'S';

// Expected payload size for a known message type, or 0 if unknown.
inline constexpr std::size_t message_size(char type) noexcept {
  switch (type) {
    case kAddOrderType:
      return kAddOrderSize;
    case kAddOrderMpidType:
      return kAddOrderMpidSize;
    case kOrderExecutedType:
      return kOrderExecutedSize;
    case kOrderCancelType:
      return kOrderCancelSize;
    case kOrderDeleteType:
      return kOrderDeleteSize;
    case kOrderReplaceType:
      return kOrderReplaceSize;
    case kTradeNonCrossType:
      return kTradeNonCrossSize;
    case kSystemEventType:
      return kSystemEventSize;
    default:
      return 0;
  }
}

inline constexpr bool is_known(char type) noexcept {
  return message_size(type) != 0;
}

// ---------------------------------------------------------------------------
// Big-endian decode helpers.
// Hand-written (no ntohll); byte-at-a-time so they are safe on unaligned
// addresses.
// ---------------------------------------------------------------------------

inline std::uint16_t be16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) |
                                    static_cast<std::uint16_t>(p[1]));
}

inline std::uint32_t be32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

inline std::uint64_t be48(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint64_t>(p[0]) << 40) | (static_cast<std::uint64_t>(p[1]) << 32) |
         (static_cast<std::uint64_t>(p[2]) << 24) | (static_cast<std::uint64_t>(p[3]) << 16) |
         (static_cast<std::uint64_t>(p[4]) << 8) | static_cast<std::uint64_t>(p[5]);
}

inline std::uint64_t be64(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint64_t>(p[0]) << 56) | (static_cast<std::uint64_t>(p[1]) << 48) |
         (static_cast<std::uint64_t>(p[2]) << 40) | (static_cast<std::uint64_t>(p[3]) << 32) |
         (static_cast<std::uint64_t>(p[4]) << 24) | (static_cast<std::uint64_t>(p[5]) << 16) |
         (static_cast<std::uint64_t>(p[6]) << 8) | static_cast<std::uint64_t>(p[7]);
}

// Unaligned load via memcpy: the one safe way to materialize a packed POD
// struct from an arbitrary buffer pointer.
template <typename T>
inline T load_unaligned(const void* p) noexcept {
  static_assert(std::is_trivially_copyable<T>::value, "T must be trivially copyable");
  T value;
  std::memcpy(&value, p, sizeof(T));
  return value;
}

// ---------------------------------------------------------------------------
// Packed wire-format structs. Sizes verified at compile time.
// Alpha fields are left-justified and space padded; numeric fields are u64/u32
// big-endian; prices are 4-byte unsigned with 4 implied decimal places.
// ---------------------------------------------------------------------------

#pragma pack(push, 1)

struct AddOrder {     // 'A'
  char type;          // 0:  'A'
  char order_ref[8];  // 1:  u64 BE
  char side;          // 9:  'B' | 'S'
  char shares[4];     // 10: u32 BE
  char stock[8];      // 14: alpha
  char price[4];      // 22: u32 BE

  std::uint64_t order_ref_number() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(order_ref));
  }
  std::uint32_t share_qty() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(shares));
  }
  std::uint32_t price_ticks() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(price));
  }
};
static_assert(sizeof(AddOrder) == kAddOrderSize, "AddOrder must be 26 bytes");

struct AddOrderMpid {   // 'F'
  char type;            // 0:  'F'
  char order_ref[8];    // 1:  u64 BE
  char side;            // 9:  'B' | 'S'
  char shares[4];       // 10: u32 BE
  char stock[8];        // 14: alpha
  char price[4];        // 22: u32 BE
  char attribution[4];  // 26: alpha MPID

  std::uint64_t order_ref_number() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(order_ref));
  }
  std::uint32_t share_qty() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(shares));
  }
  std::uint32_t price_ticks() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(price));
  }
};
static_assert(sizeof(AddOrderMpid) == kAddOrderMpidSize, "AddOrderMpid must be 30 bytes");

struct OrderExecuted {   // 'E'
  char type;             // 0:  'E'
  char order_ref[8];     // 1:  u64 BE
  char exec_shares[4];   // 9:  u32 BE
  char match_number[8];  // 13: u64 BE

  std::uint64_t order_ref_number() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(order_ref));
  }
  std::uint32_t executed_shares() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(exec_shares));
  }
  std::uint64_t match_number_value() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(match_number));
  }
};
static_assert(sizeof(OrderExecuted) == kOrderExecutedSize, "OrderExecuted must be 21 bytes");

struct OrderCancel {      // 'X'
  char type;              // 0: 'X'
  char order_ref[8];      // 1: u64 BE
  char cancel_shares[4];  // 9: u32 BE

  std::uint64_t order_ref_number() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(order_ref));
  }
  std::uint32_t canceled_shares() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(cancel_shares));
  }
};
static_assert(sizeof(OrderCancel) == kOrderCancelSize, "OrderCancel must be 13 bytes");

struct OrderDelete {  // 'D'
  char type;          // 0: 'D'
  char order_ref[8];  // 1: u64 BE

  std::uint64_t order_ref_number() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(order_ref));
  }
};
static_assert(sizeof(OrderDelete) == kOrderDeleteSize, "OrderDelete must be 9 bytes");

struct OrderReplace {     // 'U'
  char type;              // 0:  'U'
  char old_order_ref[8];  // 1:  u64 BE
  char new_order_ref[8];  // 9:  u64 BE
  char shares[4];         // 17: u32 BE
  char price[4];          // 21: u32 BE

  std::uint64_t original_ref_number() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(old_order_ref));
  }
  std::uint64_t new_ref_number() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(new_order_ref));
  }
  std::uint32_t new_share_qty() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(shares));
  }
  std::uint32_t new_price_ticks() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(price));
  }
};
static_assert(sizeof(OrderReplace) == kOrderReplaceSize, "OrderReplace must be 25 bytes");

struct TradeNonCross {   // 'P'
  char type;             // 0:  'P'
  char order_ref[8];     // 1:  u64 BE
  char side;             // 9:  'B' | 'S'
  char shares[4];        // 10: u32 BE
  char stock[8];         // 14: alpha
  char price[4];         // 22: u32 BE
  char match_number[8];  // 26: u64 BE

  std::uint64_t order_ref_number() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(order_ref));
  }
  std::uint32_t share_qty() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(shares));
  }
  std::uint32_t price_ticks() const noexcept {
    return be32(reinterpret_cast<const std::uint8_t*>(price));
  }
  std::uint64_t match_number_value() const noexcept {
    return be64(reinterpret_cast<const std::uint8_t*>(match_number));
  }
};
static_assert(sizeof(TradeNonCross) == kTradeNonCrossSize, "TradeNonCross must be 34 bytes");

struct SystemEvent {  // 'S'
  char type;          // 0: 'S'
  char timestamp[6];  // 1: u48 BE nanoseconds since midnight
  char event_code;    // 7: 'O' start | 'S' start of system hours |
                      //    'C' end of system hours | 'E' end of messages

  std::uint64_t timestamp_ns() const noexcept {
    return be48(reinterpret_cast<const std::uint8_t*>(timestamp));
  }
};
static_assert(sizeof(SystemEvent) == kSystemEventSize, "SystemEvent must be 8 bytes");

#pragma pack(pop)

}  // namespace itch
}  // namespace wiretap
