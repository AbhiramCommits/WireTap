// wiretap/book.hpp - normalized book updates emitted by the decoder.

#pragma once

#include <cstdint>
#include <string>

namespace wiretap {

enum class Side : std::uint8_t {
  Unknown = 0,
  Buy = 1,
  Sell = 2,
};

enum class Action : std::uint8_t {
  None = 0,
  Added,       // 'A' AddOrder, 'F' AddOrderMPID
  Executed,    // 'E' OrderExecuted, 'P' TradeNonCross
  Canceled,    // 'X' OrderCancel
  Deleted,     // 'D' OrderDelete
  Replaced,    // 'U' OrderReplace
  SystemEvent, // 'S' SystemEvent
  kCount
};

inline const char* action_name(Action a) noexcept {
  switch (a) {
    case Action::Added:
      return "ADDED";
    case Action::Executed:
      return "EXECUTED";
    case Action::Canceled:
      return "CANCELED";
    case Action::Deleted:
      return "DELETED";
    case Action::Replaced:
      return "REPLACED";
    case Action::SystemEvent:
      return "SYSTEM_EVENT";
    default:
      return "NONE";
  }
}

inline const char* side_name(Side s) noexcept {
  switch (s) {
    case Side::Buy:
      return "B";
    case Side::Sell:
      return "S";
    default:
      return "-";
  }
}

// One normalized book event. Fields that a message does not carry are left at
// their default values (symbol zeroed, side Unknown, price/qty/ref 0).
struct BookUpdate {
  char symbol[8] = {};        // alpha, left-justified, space padded; zeroed when N/A
  Side side = Side::Unknown;  // 'B'/'S'
  std::int64_t price_ticks = 0;  // raw ticks; 4 implied decimal places
  std::uint32_t qty = 0;
  std::uint64_t order_ref = 0;      // 'U': the NEW order reference
  std::uint64_t order_ref_old = 0;  // 'U': the ORIGINAL order reference
  Action action = Action::None;
  std::uint64_t exchange_ts_ns = 0;  // only SystemEvent carries a timestamp in this subset
  std::uint64_t recv_ts_ns = 0;      // set by the decoder from its configured clock
};

// "symbol" as a trimmed std::string, e.g. "AAPL".
inline std::string symbol_string(const char symbol[8]) {
  std::size_t len = 0;
  while (len < 8 && symbol[len] != '\0' && symbol[len] != ' ') ++len;
  return std::string(symbol, len);
}

}  // namespace wiretap
