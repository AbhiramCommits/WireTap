#include "book_builder.hpp"

#include <algorithm>

namespace wiretap {

std::map<std::uint32_t, std::uint64_t>& BookBuilder::side_map(SymbolBook& sb, Side side) noexcept {
  return side == Side::Sell ? sb.asks : sb.bids;
}

void BookBuilder::add_level(SymbolBook& sb, Side side, std::uint32_t price, std::uint64_t qty) {
  auto& levels = side_map(sb, side);
  levels[price] += qty;
}

void BookBuilder::remove_level(SymbolBook& sb, Side side, std::uint32_t price, std::uint64_t qty) {
  auto& levels = side_map(sb, side);
  auto it = levels.find(price);
  if (it == levels.end())
    return;
  if (qty >= it->second) {
    levels.erase(it);
  } else {
    it->second -= qty;
  }
}

void BookBuilder::apply(const BookUpdate& u) {
  applied_.fetch_add(1, std::memory_order_relaxed);

  switch (u.action) {
    case Action::Added: {
      const std::uint64_t key = symbol_key(u.symbol);
      auto it = symbols_.find(key);
      if (it == symbols_.end()) {
        it = symbols_.emplace(key, SymbolBook{}).first;
        std::memcpy(it->second.name, u.symbol, 8);
        symbol_count_.fetch_add(1, std::memory_order_relaxed);
      }
      SymbolBook& sb = it->second;
      const std::uint32_t price = static_cast<std::uint32_t>(u.price_ticks);
      orders_.emplace(u.order_ref, OrderRecord{key, u.side, price, u.qty});
      add_level(sb, u.side, price, u.qty);
      order_count_.fetch_add(1, std::memory_order_relaxed);
      break;
    }

    case Action::Executed:
    case Action::Canceled: {
      auto it = orders_.find(u.order_ref);
      if (it == orders_.end()) {
        unknown_.fetch_add(1, std::memory_order_relaxed);
        break;
      }
      OrderRecord& o = it->second;
      SymbolBook& sb = symbols_.find(o.symbol_key)->second;
      const std::uint64_t q = std::min<std::uint64_t>(u.qty, o.qty);  // never trust the feed
      remove_level(sb, o.side, o.price_ticks, q);
      o.qty -= static_cast<std::uint32_t>(q);
      if (o.qty == 0) {
        orders_.erase(it);
        order_count_.fetch_sub(1, std::memory_order_relaxed);
      }
      break;
    }

    case Action::Deleted: {
      auto it = orders_.find(u.order_ref);
      if (it == orders_.end()) {
        unknown_.fetch_add(1, std::memory_order_relaxed);
        break;
      }
      SymbolBook& sb = symbols_.find(it->second.symbol_key)->second;
      remove_level(sb, it->second.side, it->second.price_ticks, it->second.qty);
      orders_.erase(it);
      order_count_.fetch_sub(1, std::memory_order_relaxed);
      break;
    }

    case Action::Replaced: {
      // 'U' carries no symbol: the new order inherits the original's.
      auto old = orders_.find(u.order_ref_old);
      if (old == orders_.end()) {
        unknown_.fetch_add(1, std::memory_order_relaxed);
        break;
      }
      const std::uint64_t key = old->second.symbol_key;
      const Side side = old->second.side;
      const std::uint32_t price = static_cast<std::uint32_t>(u.price_ticks);
      SymbolBook& sb = symbols_.find(key)->second;
      remove_level(sb, side, old->second.price_ticks, old->second.qty);
      orders_.erase(old);
      orders_.emplace(u.order_ref, OrderRecord{key, side, price, u.qty});
      add_level(sb, side, price, u.qty);
      break;
    }

    case Action::SystemEvent:
    case Action::None:
    default:
      break;  // not book state
  }
}

bool BookBuilder::snapshot(const char symbol[8], std::size_t depth, DepthSnapshot& out) const {
  out.bids.clear();
  out.asks.clear();
  const auto it = symbols_.find(symbol_key(symbol));
  if (it == symbols_.end())
    return false;

  const SymbolBook& sb = it->second;
  out.bids.reserve(std::min(depth, sb.bids.size()));
  for (auto rit = sb.bids.rbegin(); rit != sb.bids.rend() && out.bids.size() < depth; ++rit) {
    out.bids.push_back({rit->first, rit->second});
  }
  out.asks.reserve(std::min(depth, sb.asks.size()));
  for (auto it2 = sb.asks.begin(); it2 != sb.asks.end() && out.asks.size() < depth; ++it2) {
    out.asks.push_back({it2->first, it2->second});
  }
  return true;
}

}  // namespace wiretap
