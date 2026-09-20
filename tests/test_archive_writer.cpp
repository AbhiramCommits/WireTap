// ArchiveWriter tests (only built when WIRETAP_HAVE_ARROW).
//
// Replays the committed capture fixture through the archive path and checks
// the Parquet output: partitioned hive layout, ZSTD compression, row counts,
// stats/depth/gaps tables, ring-full drop accounting, and the UDS live
// snapshot publisher.

#if WIRETAP_HAVE_ARROW

#include <gtest/gtest.h>

#include <arrow/api.h>
#include <arrow/io/api.h>
#include <parquet/arrow/reader.h>
#include <parquet/metadata.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "archive_writer.hpp"
#include "decoder.hpp"
#include "wiretap/itch.hpp"

namespace wt = wiretap;

namespace {

namespace fs = std::filesystem;

std::string data_file(const char* name) {
  return std::string(WIRETAP_TEST_DATA_DIR) + "/" + name;
}

std::vector<std::uint8_t> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  EXPECT_TRUE(f.good());
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(f)),
                                   std::istreambuf_iterator<char>());
}

std::string make_temp_dir() {
  char tmpl[] = "/tmp/wiretap-archive-XXXXXX";
  char* dir = ::mkdtemp(tmpl);
  EXPECT_NE(dir, nullptr);
  return dir;
}

void expect_status(const arrow::Status& st) {
  ASSERT_TRUE(st.ok()) << st.ToString();
}

std::vector<fs::path> parquet_files(const fs::path& root) {
  std::vector<fs::path> out;
  if (!fs::exists(root))
    return out;
  for (const auto& entry : fs::recursive_directory_iterator(root)) {
    if (entry.path().extension() == ".parquet")
      out.push_back(entry.path());
  }
  return out;
}

}  // namespace

TEST(ArchiveWriter, WritesPartitionedZstdParquetArchive) {
  const auto capture = read_file(data_file("roundtrip.bin"));
  const std::string dir = make_temp_dir();

  wt::SpscRing<wt::BookUpdate> updates(1u << 16);
  wt::SpscRing<wt::SecondStats> stats(64);
  wt::SpscRing<wt::GapEvent> gaps(64);

  // Replay the fixture: decode every packet and push updates into the ring
  // exactly like the decode thread would.
  wt::Decoder dec;
  std::size_t off = 0;
  std::vector<wt::BookUpdate> ups;
  ups.reserve(256);
  std::uint64_t pushed = 0;
  // Give every update a real receive timestamp so partitions land on today.
  struct timespec now_ts {};
  ::clock_gettime(CLOCK_REALTIME, &now_ts);
  const std::uint64_t now_ns = static_cast<std::uint64_t>(now_ts.tv_sec) * 1000000000ull +
                               static_cast<std::uint64_t>(now_ts.tv_nsec);
  dec.set_recv_ts_ns(now_ns);
  while (off < capture.size()) {
    std::size_t plen = 0;
    ASSERT_TRUE(wt::packet_length(capture.data() + off, capture.size() - off, plen));
    ups.clear();
    const auto r = dec.decode_packet(capture.data() + off, plen, ups);
    ASSERT_EQ(r.error, wt::DecodeError::Ok);
    for (const auto& u : ups) {
      ASSERT_TRUE(updates.try_push(u));
      ++pushed;
    }
    off += plen;
  }

  wt::SecondStats s{};
  s.sec = 1234567890;
  s.messages = pushed;
  s.packets = 47;
  s.queue_delay = {10, 100, 200, 300, 400, 500, 600};
  s.bucket_count = 1;
  s.buckets[0] = {123, 45};
  ASSERT_TRUE(stats.try_push(s));

  wt::GapEvent g{};
  g.start = 10;
  g.end = 12;
  g.missing = 3;
  g.healed = true;
  g.detected_ticks = 1000;
  g.healed_ticks = 2000;
  ASSERT_TRUE(gaps.try_push(g));

  wt::ArchiveWriter writer(dir, /*dash_socket=*/"");
  ASSERT_TRUE(writer.ok());
  std::atomic<bool> stop{false};
  std::thread t([&] { writer.run(updates, stats, gaps, stop); });
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  stop.store(true);
  t.join();
  ASSERT_TRUE(writer.ok()) << writer.error();

  EXPECT_EQ(writer.updates_written(), pushed);
  EXPECT_EQ(writer.stats_written(), 1u);
  EXPECT_EQ(writer.gaps_written(), 1u);
  EXPECT_GE(writer.depth_written(), 1u);

  // Hive layout: book/date=YYYY-MM-DD/symbol=SYMxxxxx/hour=H/*.parquet
  const auto files = parquet_files(fs::path(dir));
  ASSERT_GE(files.size(), 3u);
  std::set<std::string> symbols;
  bool found_book = false, found_stats = false, found_depth = false, found_gaps = false;
  for (const auto& f : files) {
    const std::string p = f.string();
    if (p.find("/book/") != std::string::npos)
      found_book = true;
    if (p.find("/stats/") != std::string::npos)
      found_stats = true;
    if (p.find("/depth/") != std::string::npos)
      found_depth = true;
    if (p.find("/gaps/") != std::string::npos)
      found_gaps = true;
    const auto pos = p.find("symbol=");
    if (pos != std::string::npos) {
      const std::string rest = p.substr(pos + 7);
      const auto slash = rest.find('/');
      symbols.insert(slash == std::string::npos ? rest : rest.substr(0, slash));
    }
  }
  EXPECT_TRUE(found_book);
  EXPECT_TRUE(found_stats);
  EXPECT_TRUE(found_depth);
  EXPECT_TRUE(found_gaps);
  // 20 fixture symbols plus one empty-symbol partition (Delete/Replace/
  // SystemEvent updates carry no symbol).
  EXPECT_EQ(symbols.size(), 21u);
  std::size_t sy_my = 0;
  for (const auto& sym : symbols) {
    if (sym.empty())
      continue;
    EXPECT_EQ(sym.substr(0, 3), "SYM");
    ++sy_my;
  }
  EXPECT_EQ(sy_my, 20u);

  // Read the book partition back and verify row count + a field value.
  std::uint64_t book_rows = 0;
  std::set<std::string> actions_seen;
  for (const auto& f : files) {
    if (f.string().find("/book/") == std::string::npos)
      continue;
    std::shared_ptr<arrow::io::ReadableFile> input;
    expect_status(arrow::io::ReadableFile::Open(f.string()).Value(&input));
    std::unique_ptr<parquet::arrow::FileReader> reader;
    expect_status(parquet::arrow::OpenFile(input, arrow::default_memory_pool()).Value(&reader));
    // Compression: every column chunk must be ZSTD.
    const auto meta = reader->parquet_reader()->metadata();
    ASSERT_GT(meta->num_row_groups(), 0);
    const auto rg = meta->RowGroup(0);
    for (int i = 0; i < rg->num_columns(); ++i) {
      EXPECT_EQ(rg->ColumnChunk(i)->compression(), parquet::Compression::ZSTD);
    }
    std::shared_ptr<arrow::Table> table;
    expect_status(reader->ReadTable(&table));
    book_rows += static_cast<std::uint64_t>(table->num_rows());
    const auto action_col = table->GetColumnByName("action");
    ASSERT_NE(action_col, nullptr);
    for (int64_t i = 0; i < action_col->length(); ++i) {
      const auto chunk = action_col->chunk(0);
      actions_seen.insert(chunk->GetScalar(i).ValueOrDie()->ToString());
    }
  }
  EXPECT_EQ(book_rows, pushed);
  EXPECT_EQ(book_rows, 6000u);
  EXPECT_NE(actions_seen.count("ADDED"), 0u);
  EXPECT_NE(actions_seen.count("EXECUTED"), 0u);

  fs::remove_all(fs::path(dir));
}

TEST(ArchiveWriter, RingFullDropsCountedNotBlocking) {
  // A tiny ring: pushes beyond capacity fail immediately (no blocking).
  wt::SpscRing<wt::BookUpdate> updates(4);
  wt::BookUpdate u{};
  u.action = wt::Action::Added;
  u.qty = 1;
  std::uint64_t dropped = 0;
  for (int i = 0; i < 100; ++i) {
    if (!updates.try_push(u))
      ++dropped;
  }
  EXPECT_EQ(dropped, 96u);
  EXPECT_EQ(updates.size(), 4u);
}

TEST(ArchiveWriter, PublishesLiveSnapshotOverUnixDatagramSocket) {
  const std::string dir = make_temp_dir();
  const std::string sock_path = dir + "/dash.sock";

  // Test-side receiver for the UDS datagram stream.
  const int rx = ::socket(AF_UNIX, SOCK_DGRAM, 0);
  ASSERT_GE(rx, 0);
  struct sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
  ::unlink(sock_path.c_str());
  ASSERT_EQ(::bind(rx, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr), 0);
  const int rcvtimeo = 2000;  // ms
  ::setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &rcvtimeo, sizeof rcvtimeo);

  wt::SpscRing<wt::BookUpdate> updates(1024);
  wt::SpscRing<wt::SecondStats> stats(64);
  wt::SpscRing<wt::GapEvent> gaps(64);

  wt::BookUpdate u{};
  u.action = wt::Action::Added;
  u.side = wt::Side::Buy;
  u.price_ticks = 100000;
  u.qty = 500;
  u.order_ref = 1;
  std::memcpy(u.symbol, "SYM00000", 8);
  ASSERT_TRUE(updates.try_push(u));

  wt::SecondStats s{};
  s.sec = 1234567890;
  s.messages = 1;
  s.wire_to_book = {1, 200, 300, 400, 500, 600, 700};
  s.bucket_count = 2;
  s.buckets[0] = {100, 50};
  s.buckets[1] = {1000, 10};
  ASSERT_TRUE(stats.try_push(s));

  wt::ArchiveWriter writer(dir, sock_path);
  ASSERT_TRUE(writer.ok());
  std::atomic<bool> stop{false};
  std::thread t([&] { writer.run(updates, stats, gaps, stop); });
  std::this_thread::sleep_for(std::chrono::milliseconds(400));  // allow publish
  stop.store(true);
  t.join();

  EXPECT_GE(writer.snapshots_published(), 1u);

  char buf[262144];
  const ssize_t n = ::recv(rx, buf, sizeof buf, 0);
  ASSERT_GT(n, 0);
  const std::string json(buf, static_cast<std::size_t>(n));
  EXPECT_NE(json.find("\"books\""), std::string::npos);
  EXPECT_NE(json.find("\"SYM00000\""), std::string::npos);
  EXPECT_NE(json.find("\"bids\""), std::string::npos);
  EXPECT_NE(json.find("\"histogram\""), std::string::npos);
  EXPECT_NE(json.find("\"wire_to_book\""), std::string::npos);
  EXPECT_NE(json.find("[100,50]"), std::string::npos);

  ::close(rx);
  fs::remove_all(fs::path(dir));
}

#endif  // WIRETAP_HAVE_ARROW
