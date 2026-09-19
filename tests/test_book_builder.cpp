// BookBuilder tests: unit-level lifecycle checks plus a full replay of the
// committed capture fixture compared against the Python reference dump
// (tools/bookref.py -> tests/data/book_expected.tsv).

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "book_builder.hpp"
#include "decoder.hpp"

namespace wt = wiretap;

namespace {

// snapshot() reads a fixed 8-byte symbol; string literals must be padded.
bool snap(const wt::BookBuilder& book, const char* symbol, std::size_t depth,
          wt::DepthSnapshot& out) {
  char padded[8] = {};
  std::strncpy(padded, symbol, 8);
  return book.snapshot(padded, depth, out);
}

wt::BookUpdate add(char symbol, wt::Side side, std::uint32_t price,
                   std::uint32_t qty, std::uint64_t ref) {
  wt::BookUpdate u;
  std::snprintf(u.symbol, 8, "%c", symbol);
  u.action = wt::Action::Added;
  u.side = side;
  u.price_ticks = price;
  u.qty = qty;
  u.order_ref = ref;
  return u;
}

wt::BookUpdate exec(std::uint64_t ref, std::uint32_t qty) {
  wt::BookUpdate u;
  u.action = wt::Action::Executed;
  u.order_ref = ref;
  u.qty = qty;
  return u;
}

wt::BookUpdate cancel(std::uint64_t ref, std::uint32_t qty) {
  wt::BookUpdate u;
  u.action = wt::Action::Canceled;
  u.order_ref = ref;
  u.qty = qty;
  return u;
}

wt::BookUpdate del(std::uint64_t ref) {
  wt::BookUpdate u;
  u.action = wt::Action::Deleted;
  u.order_ref = ref;
  return u;
}

wt::BookUpdate replace(std::uint64_t old_ref, std::uint64_t new_ref,
                       std::uint32_t price, std::uint32_t qty) {
  wt::BookUpdate u;
  u.action = wt::Action::Replaced;
  u.order_ref = new_ref;
  u.order_ref_old = old_ref;
  u.price_ticks = price;
  u.qty = qty;
  return u;
}

}  // namespace

TEST(BookBuilder, AddExecuteCancelDelete) {
  wt::BookBuilder book;
  book.apply(add('A', wt::Side::Buy, 100000, 500, 1));
  book.apply(add('A', wt::Side::Buy, 99900, 300, 2));
  book.apply(add('A', wt::Side::Sell, 100500, 200, 3));

  wt::DepthSnapshot s;
  ASSERT_TRUE(snap(book, "A", 10, s));
  ASSERT_EQ(s.bids.size(), 2u);
  EXPECT_EQ(s.bids[0].price_ticks, 100000u);
  EXPECT_EQ(s.bids[0].qty, 500u);
  EXPECT_EQ(s.bids[1].price_ticks, 99900u);
  EXPECT_EQ(s.bids[1].qty, 300u);
  ASSERT_EQ(s.asks.size(), 1u);
  EXPECT_EQ(s.asks[0].price_ticks, 100500u);
  EXPECT_EQ(s.asks[0].qty, 200u);
  EXPECT_EQ(book.order_count(), 3u);

  book.apply(exec(1, 200));  // partial
  ASSERT_TRUE(snap(book, "A", 10, s));
  EXPECT_EQ(s.bids[0].qty, 300u);
  EXPECT_EQ(book.order_count(), 3u);

  book.apply(exec(1, 300));  // completes order 1
  ASSERT_TRUE(snap(book, "A", 10, s));
  ASSERT_EQ(s.bids.size(), 1u);
  EXPECT_EQ(s.bids[0].price_ticks, 99900u);
  EXPECT_EQ(book.order_count(), 2u);

  book.apply(cancel(2, 100));
  ASSERT_TRUE(snap(book, "A", 10, s));
  EXPECT_EQ(s.bids[0].qty, 200u);

  book.apply(del(3));
  ASSERT_TRUE(snap(book, "A", 10, s));
  EXPECT_TRUE(s.asks.empty());
  EXPECT_EQ(book.order_count(), 1u);
}

TEST(BookBuilder, ReplaceInheritsSymbolAndSide) {
  wt::BookBuilder book;
  book.apply(add('B', wt::Side::Sell, 50000, 100, 10));
  book.apply(replace(10, 11, 51000, 150));  // 'U' carries no symbol

  wt::DepthSnapshot s;
  ASSERT_TRUE(snap(book, "B", 10, s));
  ASSERT_EQ(s.asks.size(), 1u);
  EXPECT_EQ(s.asks[0].price_ticks, 51000u);
  EXPECT_EQ(s.asks[0].qty, 150u);
  EXPECT_EQ(book.order_count(), 1u);
}

TEST(BookBuilder, MergesSamePriceLevels) {
  wt::BookBuilder book;
  book.apply(add('C', wt::Side::Buy, 77000, 250, 1));
  book.apply(add('C', wt::Side::Buy, 77000, 350, 2));
  wt::DepthSnapshot s;
  ASSERT_TRUE(snap(book, "C", 10, s));
  ASSERT_EQ(s.bids.size(), 1u);
  EXPECT_EQ(s.bids[0].qty, 600u);
}

TEST(BookBuilder, UnknownRefsAreCountedNotApplied) {
  wt::BookBuilder book;
  book.apply(exec(42, 100));
  book.apply(del(43));
  book.apply(replace(44, 45, 1000, 10));
  EXPECT_EQ(book.unknown_ref_events(), 3u);
  EXPECT_EQ(book.order_count(), 0u);
  EXPECT_EQ(book.symbol_count(), 0u);
}

TEST(BookBuilder, ExecutedClampsToRemainingQty) {
  wt::BookBuilder book;
  book.apply(add('D', wt::Side::Buy, 30000, 50, 1));
  book.apply(exec(1, 1000));  // over-execution: clamp
  wt::DepthSnapshot s;
  ASSERT_TRUE(snap(book, "D", 10, s));
  EXPECT_TRUE(s.bids.empty());
  EXPECT_EQ(book.order_count(), 0u);
  EXPECT_EQ(book.unknown_ref_events(), 0u);
}

TEST(BookBuilder, DepthLimitAndMissingSymbol) {
  wt::BookBuilder book;
  for (std::uint64_t i = 0; i < 5; ++i) {
    book.apply(add('E', wt::Side::Buy, 100000 - static_cast<std::uint32_t>(i),
                   100, i + 1));
  }
  wt::DepthSnapshot s;
  ASSERT_TRUE(snap(book, "E", 2, s));
  ASSERT_EQ(s.bids.size(), 2u);
  EXPECT_EQ(s.bids[0].price_ticks, 100000u);
  EXPECT_EQ(s.bids[1].price_ticks, 99999u);
  EXPECT_FALSE(snap(book, "ZZZZZZZZ", 2, s));
  EXPECT_TRUE(s.bids.empty());
  EXPECT_TRUE(s.asks.empty());
}

// -- full replay vs Python reference ---------------------------------------

namespace {

struct ExpectedRow {
  std::string symbol;
  char side;
  std::uint32_t price;
  std::uint64_t qty;
};

std::string data_file(const char* name) {
  return std::string(WIRETAP_TEST_DATA_DIR) + "/" + name;
}

std::vector<std::uint8_t> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  EXPECT_TRUE(f.good()) << "missing test data file: " << path;
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(f)),
                                   std::istreambuf_iterator<char>());
}

// symbol -> {bids (best first), asks (best first)}, plus the ORDERS total.
struct ExpectedBook {
  std::map<std::string, std::pair<std::vector<ExpectedRow>,
                                  std::vector<ExpectedRow>>> levels;
  std::uint64_t orders = 0;
};

void parse_expected(const std::string& path, ExpectedBook& eb) {
  std::ifstream f(path);
  EXPECT_TRUE(f.good()) << "missing reference book file: " << path;
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::istringstream ss(line);
    std::string a, b;
    ASSERT_TRUE(std::getline(ss, a, '\t') && std::getline(ss, b, '\t'));
    if (a == "ORDERS") {
      eb.orders = std::stoull(b);
      continue;
    }
    std::string c, d;
    ASSERT_TRUE(std::getline(ss, c, '\t') && std::getline(ss, d, '\t'));
    ExpectedRow row{a, b.at(0), static_cast<std::uint32_t>(std::stoul(c)),
                    std::stoull(d)};
    if (row.side == 'B') {
      eb.levels[row.symbol].first.push_back(row);
    } else {
      eb.levels[row.symbol].second.push_back(row);
    }
  }
}

}  // namespace

TEST(BookBuilder, FixtureReplayMatchesPythonReference) {
  const auto bin = read_file(data_file("roundtrip.bin"));
  ExpectedBook expected;
  parse_expected(data_file("book_expected.tsv"), expected);

  wt::BookBuilder book;
  wt::Decoder dec;
  std::size_t off = 0;
  std::size_t packets = 0;
  std::vector<wt::BookUpdate> updates;
  updates.reserve(256);
  while (off < bin.size()) {
    std::size_t plen = 0;
    ASSERT_TRUE(wt::packet_length(bin.data() + off, bin.size() - off, plen));
    updates.clear();
    const auto r = dec.decode_packet(bin.data() + off, plen, updates);
    ASSERT_EQ(r.error, wt::DecodeError::Ok);
    for (const auto& u : updates) book.apply(u);
    ++packets;
    off += plen;
  }
  ASSERT_GT(packets, 0u);
  ASSERT_EQ(book.applied_updates(), 6000u);
  ASSERT_EQ(book.unknown_ref_events(), 0u);

  EXPECT_EQ(book.order_count(), expected.orders);
  EXPECT_EQ(book.symbol_count(), 20u);

  // Compare every live level, symbol by symbol.
  std::size_t checked_symbols = 0;
  for (const auto& [symbol, sides] : expected.levels) {
    wt::DepthSnapshot s;
    ASSERT_TRUE(book.snapshot(symbol.c_str(), 4096, s))
        << "builder missing symbol " << symbol;
    const auto& [bids, asks] = sides;
    ASSERT_EQ(s.bids.size(), bids.size()) << "symbol " << symbol << " bids";
    for (std::size_t i = 0; i < bids.size(); ++i) {
      EXPECT_EQ(s.bids[i].price_ticks, bids[i].price) << symbol << " bid " << i;
      EXPECT_EQ(s.bids[i].qty, bids[i].qty) << symbol << " bid " << i;
    }
    ASSERT_EQ(s.asks.size(), asks.size()) << "symbol " << symbol << " asks";
    for (std::size_t i = 0; i < asks.size(); ++i) {
      EXPECT_EQ(s.asks[i].price_ticks, asks[i].price) << symbol << " ask " << i;
      EXPECT_EQ(s.asks[i].qty, asks[i].qty) << symbol << " ask " << i;
    }
    ++checked_symbols;
  }
  EXPECT_EQ(checked_symbols, expected.levels.size());
}
