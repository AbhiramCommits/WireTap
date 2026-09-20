// Python(encode) -> C++(decode) round-trip test.
//
// tools/feedgen.py generated tests/data/roundtrip.bin together with a TSV
// manifest (tests/data/roundtrip.tsv) that records exactly what the generator
// wrote. This test decodes every packet in the capture and compares every
// field of every BookUpdate against the manifest.

#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "decoder.hpp"

namespace wt = wiretap;

namespace {

struct ExpectedUpdate {
  std::uint64_t seq = 0;
  char type = 0;
  std::string symbol;
  char side = 0;
  std::int64_t price = 0;
  std::uint32_t qty = 0;
  std::uint64_t ref = 0;
  std::uint64_t old_ref = 0;
  std::string action;
  std::uint64_t ts = 0;
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

bool parse_row(const std::string& line, ExpectedUpdate& e) {
  std::istringstream ss(line);
  std::vector<std::string> fields;
  std::string tok;
  while (std::getline(ss, tok, '\t'))
    fields.push_back(tok);
  if (fields.size() != 10)
    return false;
  try {
    e.seq = std::stoull(fields[0]);
    e.type = fields[1].at(0);
    e.symbol = fields[2];
    e.side = fields[3].at(0);
    e.price = std::stoll(fields[4]);
    e.qty = static_cast<std::uint32_t>(std::stoul(fields[5]));
    e.ref = std::stoull(fields[6]);
    e.old_ref = std::stoull(fields[7]);
    e.action = fields[8];
    e.ts = std::stoull(fields[9]);
  } catch (...) {
    return false;
  }
  return true;
}

std::vector<ExpectedUpdate> read_manifest(const std::string& path) {
  std::ifstream f(path);
  EXPECT_TRUE(f.good()) << "missing manifest: " << path;
  std::vector<ExpectedUpdate> rows;
  std::string line;
  while (std::getline(f, line)) {
    ExpectedUpdate e;
    EXPECT_TRUE(parse_row(line, e)) << "bad manifest row: " << line;
    rows.push_back(e);
  }
  return rows;
}

wt::Action action_for(char type) {
  switch (type) {
    case 'A':
    case 'F':
      return wt::Action::Added;
    case 'E':
    case 'P':
      return wt::Action::Executed;
    case 'X':
      return wt::Action::Canceled;
    case 'D':
      return wt::Action::Deleted;
    case 'U':
      return wt::Action::Replaced;
    case 'S':
      return wt::Action::SystemEvent;
    default:
      return wt::Action::None;
  }
}

wt::Side side_for(char c) {
  switch (c) {
    case 'B':
      return wt::Side::Buy;
    case 'S':
      return wt::Side::Sell;
    default:
      return wt::Side::Unknown;
  }
}

}  // namespace

TEST(RoundTrip, FixtureUnderOneMegabyte) {
  const auto bin = read_file(data_file("roundtrip.bin"));
  EXPECT_LT(bin.size(), 1024u * 1024u);
}

TEST(RoundTrip, ManifestCoversEveryMessageType) {
  const auto rows = read_manifest(data_file("roundtrip.tsv"));
  std::set<char> seen;
  for (const auto& r : rows)
    seen.insert(r.type);
  for (char t : std::string("AFEXDUPS")) {
    EXPECT_NE(seen.find(t), seen.end()) << "fixture never emits '" << t << "'";
  }
}

TEST(RoundTrip, PythonEncodeMatchesCppDecode) {
  const auto bin = read_file(data_file("roundtrip.bin"));
  const auto rows = read_manifest(data_file("roundtrip.tsv"));
  ASSERT_FALSE(bin.empty());
  ASSERT_FALSE(rows.empty());

  wt::Decoder dec;
  std::size_t off = 0;
  std::size_t row = 0;
  std::size_t packets = 0;
  std::uint64_t prev_seq = 0;

  while (off < bin.size()) {
    std::size_t plen = 0;
    ASSERT_TRUE(wt::packet_length(bin.data() + off, bin.size() - off, plen))
        << "malformed fixture packet at offset " << off;

    std::vector<wt::BookUpdate> out;
    const auto r = dec.decode_packet(bin.data() + off, plen, out);
    ASSERT_EQ(r.error, wt::DecodeError::Ok) << "decode failed at offset " << off;
    ++packets;

    if (prev_seq != 0) {
      EXPECT_EQ(r.sequence_number, prev_seq + 1) << "sequence gap in fixture";
    }
    prev_seq = r.sequence_number;

    for (const auto& u : out) {
      ASSERT_LT(row, rows.size()) << "decoder produced more updates than the manifest";
      const ExpectedUpdate& e = rows[row];
      EXPECT_EQ(r.sequence_number, e.seq);
      EXPECT_EQ(u.action, action_for(e.type)) << "manifest row " << row;
      EXPECT_STREQ(wt::action_name(u.action), e.action.c_str());
      EXPECT_EQ(wt::symbol_string(u.symbol), e.symbol) << "manifest row " << row;
      EXPECT_EQ(u.side, side_for(e.side)) << "manifest row " << row;
      EXPECT_EQ(u.price_ticks, e.price) << "manifest row " << row;
      EXPECT_EQ(u.qty, e.qty) << "manifest row " << row;
      EXPECT_EQ(u.order_ref, e.ref) << "manifest row " << row;
      EXPECT_EQ(u.order_ref_old, e.old_ref) << "manifest row " << row;
      EXPECT_EQ(u.exchange_ts_ns, e.ts) << "manifest row " << row;
      ++row;
    }
    off += plen;
  }

  EXPECT_EQ(off, bin.size());
  EXPECT_EQ(row, rows.size()) << "manifest has more rows than decoded updates";
  EXPECT_GT(packets, 0u);
}
