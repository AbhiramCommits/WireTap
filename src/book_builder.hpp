// wiretap/book_builder.hpp - limit order book maintained from BookUpdates.

#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <map>
#include <unordered_map>
#include <vector>

#include "wiretap/book.hpp"

namespace wiretap {

struct DepthLevel {
  std::uint32_t price_ticks = 0;
  std::uint64_t qty = 0;
};

struct DepthSnapshot {
  std::vector<DepthLevel> bids;  // best first (price descending)
  std::vector<DepthLevel> asks;  // best first (price ascending)
};

// Maintains one limit order book per symbol:
//  - an order_ref -> (symbol, side, price, qty) map for lifecycle tracking
//  - per-symbol price levels aggregated across orders
// Supports Add/Execute/Cancel/Delete/Replace; ignores SystemEvent. Events
// referencing an unknown order (e.g. after a gap) are counted, not applied.
class BookBuilder {
 public:
  BookBuilder() {
    symbols_.reserve(256);
    orders_.reserve(8192);
  }

  void apply(const BookUpdate& u);

  // Top-`depth` snapshot of `symbol`'s book. Returns false if the symbol has
  // never been seen; otherwise fills `out` (always clears it first).
  bool snapshot(const char symbol[8], std::size_t depth, DepthSnapshot& out) const;

  std::uint64_t order_count() const noexcept {
    return order_count_.load(std::memory_order_relaxed);
  }
  std::uint64_t symbol_count() const noexcept {
    return symbol_count_.load(std::memory_order_relaxed);
  }
  std::uint64_t applied_updates() const noexcept {
    return applied_.load(std::memory_order_relaxed);
  }
  std::uint64_t unknown_ref_events() const noexcept {
    return unknown_.load(std::memory_order_relaxed);
  }

 private:
  struct SymbolBook {
    char name[8] = {0};
    std::map<std::uint32_t, std::uint64_t> bids;  // price ascending
    std::map<std::uint32_t, std::uint64_t> asks;  // price ascending
  };

  struct OrderRecord {
    std::uint64_t symbol_key;
    Side side;
    std::uint32_t price_ticks;
    std::uint32_t qty;
  };

  static std::uint64_t symbol_key(const char symbol[8]) noexcept {
    std::uint64_t k = 0;
    std::memcpy(&k, symbol, 8);
    return k;
  }

  static std::map<std::uint32_t, std::uint64_t>& side_map(SymbolBook& sb, Side side) noexcept;
  static void add_level(SymbolBook& sb, Side side, std::uint32_t price, std::uint64_t qty);
  static void remove_level(SymbolBook& sb, Side side, std::uint32_t price, std::uint64_t qty);

  std::unordered_map<std::uint64_t, SymbolBook> symbols_;
  std::unordered_map<std::uint64_t, OrderRecord> orders_;
  std::atomic<std::uint64_t> order_count_{0};
  std::atomic<std::uint64_t> symbol_count_{0};
  std::atomic<std::uint64_t> applied_{0};
  std::atomic<std::uint64_t> unknown_{0};
};

}  // namespace wiretap
