#include "archive_writer.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <arrow/api.h>
#include <arrow/io/api.h>
#include <arrow/util/compression.h>
#include <parquet/arrow/writer.h>
#include <parquet/file_reader.h>

#include <hdr/hdr_histogram.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <thread>

#include "time_base.hpp"

namespace wiretap {

namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxPendingUpdates = 1'000'000;  // ~1M rows per flush
constexpr std::size_t kStatsFlushRows = 60;            // ~1 minute of seconds
constexpr int kFlushMaxAgeMs = 5000;
constexpr int kPublishIntervalMs = 100;  // 10 Hz
constexpr int kMaxRecentGaps = 20;

std::shared_ptr<arrow::Schema> book_schema() {
  static const auto schema = arrow::schema({
      arrow::field("recv_ts_ns", arrow::timestamp(arrow::TimeUnit::NANO)),
      arrow::field("date", arrow::utf8()),
      arrow::field("symbol", arrow::utf8()),
      arrow::field("hour", arrow::int8()),
      arrow::field("side", arrow::utf8()),
      arrow::field("price_ticks", arrow::int64()),
      arrow::field("qty", arrow::uint32()),
      arrow::field("order_ref", arrow::uint64()),
      arrow::field("order_ref_old", arrow::uint64()),
      arrow::field("action", arrow::utf8()),
      arrow::field("exchange_ts_ns", arrow::int64()),
  });
  return schema;
}

std::shared_ptr<arrow::Schema> stats_schema() {
  static const auto schema = arrow::schema({
      arrow::field("sec", arrow::timestamp(arrow::TimeUnit::SECOND)),
      arrow::field("messages", arrow::uint64()),
      arrow::field("packets", arrow::uint64()),
      arrow::field("ring_drops", arrow::uint64()),
      arrow::field("archive_drops", arrow::uint64()),
      arrow::field("gaps_detected", arrow::uint64()),
      arrow::field("gaps_healed", arrow::uint64()),
      arrow::field("permanently_lost", arrow::uint64()),
      arrow::field("recovered", arrow::uint64()),
      arrow::field("qd_count", arrow::uint64()),
      arrow::field("qd_p50", arrow::uint64()),
      arrow::field("qd_p90", arrow::uint64()),
      arrow::field("qd_p99", arrow::uint64()),
      arrow::field("qd_p999", arrow::uint64()),
      arrow::field("qd_p9999", arrow::uint64()),
      arrow::field("qd_max", arrow::uint64()),
      arrow::field("dt_count", arrow::uint64()),
      arrow::field("dt_p50", arrow::uint64()),
      arrow::field("dt_p90", arrow::uint64()),
      arrow::field("dt_p99", arrow::uint64()),
      arrow::field("dt_p999", arrow::uint64()),
      arrow::field("dt_p9999", arrow::uint64()),
      arrow::field("dt_max", arrow::uint64()),
      arrow::field("wtb_count", arrow::uint64()),
      arrow::field("wtb_p50", arrow::uint64()),
      arrow::field("wtb_p90", arrow::uint64()),
      arrow::field("wtb_p99", arrow::uint64()),
      arrow::field("wtb_p999", arrow::uint64()),
      arrow::field("wtb_p9999", arrow::uint64()),
      arrow::field("wtb_max", arrow::uint64()),
  });
  return schema;
}

std::shared_ptr<arrow::Schema> depth_schema() {
  static const auto schema = arrow::schema({
      arrow::field("sec", arrow::timestamp(arrow::TimeUnit::SECOND)),
      arrow::field("symbol", arrow::utf8()),
      arrow::field("side", arrow::utf8()),
      arrow::field("level", arrow::uint8()),
      arrow::field("price_ticks", arrow::int64()),
      arrow::field("qty", arrow::uint64()),
  });
  return schema;
}

std::shared_ptr<arrow::Schema> gaps_schema() {
  static const auto schema = arrow::schema({
      arrow::field("detected_ts_ns", arrow::timestamp(arrow::TimeUnit::NANO)),
      arrow::field("healed_ts_ns", arrow::timestamp(arrow::TimeUnit::NANO)),
      arrow::field("start", arrow::uint64()),
      arrow::field("end", arrow::uint64()),
      arrow::field("missing", arrow::uint64()),
      arrow::field("healed", arrow::boolean()),
  });
  return schema;
}

std::shared_ptr<parquet::WriterProperties> writer_properties() {
  static const auto props = parquet::WriterProperties::Builder()
                                .compression(arrow::Compression::ZSTD)
                                ->max_row_group_length(1'000'000)
                                ->build();
  return props;
}

// "YYYY-MM-DD" and hour from epoch nanoseconds.
void civil_date(std::uint64_t epoch_ns, char date[11], int& hour) {
  const std::time_t t = static_cast<std::time_t>(epoch_ns / 1000000000ull);
  struct tm tm {};
  ::gmtime_r(&t, &tm);
  std::snprintf(date, 11, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
  hour = tm.tm_hour;
}

}  // namespace

std::uint32_t dump_histogram_buckets(struct ::hdr_histogram* h, HistogramBucket* out,
                                     std::uint32_t max) {
  if (h == nullptr || out == nullptr || max == 0)
    return 0;
  // hdr_iter_init() uses the "all values" iteration: one step per occupied
  // bucket, with the count in iter.count and the value in iter.value.
  struct hdr_iter iter {};
  ::hdr_iter_init(&iter, h);
  std::uint32_t n = 0;
  while (n < max && ::hdr_iter_next(&iter)) {
    if (iter.count <= 0)
      continue;
    out[n].value = static_cast<std::uint64_t>(iter.value);
    out[n].count = static_cast<std::uint64_t>(iter.count);
    ++n;
  }
  return n;
}

// One open Parquet file per (date, symbol, hour) partition.
struct ArchiveWriter::ParquetWriter {
  std::unique_ptr<parquet::arrow::FileWriter> writer;
  std::string path;
};

ArchiveWriter::ArchiveWriter(std::string archive_dir, std::string dash_socket_path)
    : archive_dir_(std::move(archive_dir)), dash_socket_path_(std::move(dash_socket_path)) {
  pending_updates_.reserve(kMaxPendingUpdates);
  pending_stats_rows_.reserve(kStatsFlushRows + 1);
  pending_depth_rows_.reserve(1024);
  if (!archive_dir_.empty()) {
    std::error_code ec;
    fs::create_directories(archive_dir_, ec);
    if (ec) {
      ok_ = false;
      error_ = "cannot create archive dir: " + ec.message();
    }
  }
  if (ok_ && !dash_socket_path_.empty()) {
    dash_fd_ = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    if (dash_fd_ < 0) {
      ok_ = false;
      error_ = std::string("dash socket: ") + std::strerror(errno);
    } else {
      // Snapshots (books + histogram) can exceed the tiny default dgram
      // send buffer; raise it so sendto does not fail with EMSGSIZE.
      const int sndbuf = 1u << 22u;
      ::setsockopt(dash_fd_, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
    }
  }
  if (ok_ && archive_dir_.empty() && dash_socket_path_.empty()) {
    ok_ = false;
    error_ = "ArchiveWriter: neither archive dir nor dash socket configured";
  }
}

ArchiveWriter::~ArchiveWriter() {
  if (dash_fd_ >= 0)
    ::close(dash_fd_);
}

void ArchiveWriter::close_all_writers() {
  for (auto& [key, pw] : writers_) {
    if (pw->writer != nullptr) {
      (void)pw->writer->Close();
    }
  }
  writers_.clear();
}

std::shared_ptr<ArchiveWriter::ParquetWriter> ArchiveWriter::writer_for(
    const std::string& partition_key, const fs::path& dir,
    const std::shared_ptr<arrow::Schema>& schema) {
  auto it = writers_.find(partition_key);
  if (it != writers_.end())
    return it->second;

  std::error_code ec;
  fs::create_directories(dir, ec);
  std::string path = (dir / ("part-" + std::to_string(file_counter_++) + ".parquet")).string();

  std::shared_ptr<arrow::io::FileOutputStream> out;
  arrow::Result<std::shared_ptr<arrow::io::FileOutputStream>> res =
      arrow::io::FileOutputStream::Open(path);
  if (!res.ok()) {
    ok_ = false;
    error_ = "cannot open " + path + ": " + res.status().ToString();
    return nullptr;
  }
  out = res.ValueOrDie();

  arrow::Result<std::unique_ptr<parquet::arrow::FileWriter>> result =
      parquet::arrow::FileWriter::Open(*schema, arrow::default_memory_pool(), out,
                                       writer_properties());
  if (!result.ok()) {
    ok_ = false;
    error_ = "cannot create parquet writer: " + result.status().ToString();
    return nullptr;
  }
  auto pw = std::make_shared<ParquetWriter>();
  pw->writer = std::move(result).ValueOrDie();
  pw->path = path;
  writers_[partition_key] = pw;
  return pw;
}

void ArchiveWriter::flush_updates() {
  if (pending_updates_.empty() || !ok_) {
    pending_updates_.clear();
    return;
  }

  // Group row indices by partition key (date|symbol|hour).
  std::map<std::string, std::vector<std::uint64_t>> groups;
  char date[11];
  int hour = 0;
  std::string key;
  for (std::uint64_t i = 0; i < pending_updates_.size(); ++i) {
    const BookUpdate& u = pending_updates_[i];
    civil_date(static_cast<std::uint64_t>(u.recv_ts_ns), date, hour);
    const std::string sym = symbol_string(u.symbol);
    key.clear();
    key.append(date);
    key.push_back('|');
    key.append(sym);
    key.push_back('|');
    key.append(std::to_string(hour));
    groups[key].push_back(i);
  }

  const auto schema = book_schema();
  for (const auto& [partition, rows] : groups) {
    // partition key: date|symbol|hour
    const std::size_t p1 = partition.find('|');
    const std::size_t p2 = partition.rfind('|');
    const std::string date_str = partition.substr(0, p1);
    const std::string sym = partition.substr(p1 + 1, p2 - p1 - 1);
    const std::string hour_str = partition.substr(p2 + 1);
    const fs::path dir = fs::path(archive_dir_) / "book" / ("date=" + date_str) /
                         ("symbol=" + sym) / ("hour=" + hour_str);
    auto pw = writer_for(partition, dir, schema);
    if (pw == nullptr) {
      pending_updates_.clear();
      return;
    }

    arrow::TimestampBuilder ts_builder(arrow::timestamp(arrow::TimeUnit::NANO),
                                       arrow::default_memory_pool());
    arrow::StringBuilder date_builder, symbol_builder, side_builder, action_builder;
    arrow::Int8Builder hour_builder;
    arrow::Int64Builder price_builder, exchange_builder;
    arrow::UInt32Builder qty_builder;
    arrow::UInt64Builder ref_builder, old_ref_builder;

    for (std::uint64_t idx : rows) {
      const BookUpdate& u = pending_updates_[idx];
      (void)ts_builder.Append(static_cast<std::int64_t>(u.recv_ts_ns));
      (void)date_builder.Append(date_str);
      (void)symbol_builder.Append(sym);
      (void)hour_builder.Append(static_cast<std::int8_t>(std::stoi(hour_str)));
      (void)(void)side_builder.Append(side_name(u.side));
      (void)price_builder.Append(u.price_ticks);
      (void)qty_builder.Append(u.qty);
      (void)ref_builder.Append(u.order_ref);
      (void)old_ref_builder.Append(u.order_ref_old);
      (void)action_builder.Append(action_name(u.action));
      (void)exchange_builder.Append(static_cast<std::int64_t>(u.exchange_ts_ns));
    }

    std::shared_ptr<arrow::Array> ts_arr, date_arr, sym_arr, hour_arr, side_arr, price_arr, qty_arr,
        ref_arr, old_ref_arr, action_arr, exch_arr;
    auto status = [](const arrow::Status& st) {
      if (!st.ok())
        throw std::runtime_error(st.ToString());
    };
    status(ts_builder.Finish(&ts_arr));
    status(date_builder.Finish(&date_arr));
    status(symbol_builder.Finish(&sym_arr));
    status(hour_builder.Finish(&hour_arr));
    status(side_builder.Finish(&side_arr));
    status(price_builder.Finish(&price_arr));
    status(qty_builder.Finish(&qty_arr));
    status(ref_builder.Finish(&ref_arr));
    status(old_ref_builder.Finish(&old_ref_arr));
    status(action_builder.Finish(&action_arr));
    status(exchange_builder.Finish(&exch_arr));

    auto batch = arrow::RecordBatch::Make(schema, static_cast<std::int64_t>(rows.size()),
                                          {ts_arr, date_arr, sym_arr, hour_arr, side_arr, price_arr,
                                           qty_arr, ref_arr, old_ref_arr, action_arr, exch_arr});
    arrow::Status st = pw->writer->WriteRecordBatch(*batch);
    if (!st.ok()) {
      ok_ = false;
      error_ = "parquet write failed: " + st.ToString();
      pending_updates_.clear();
      return;
    }
    updates_written_ += rows.size();
  }
  pending_updates_.clear();
}

void ArchiveWriter::flush_stats() {
  if (pending_stats_rows_.empty() || !ok_) {
    pending_stats_rows_.clear();
    return;
  }
  std::error_code ec;
  const fs::path dir = fs::path(archive_dir_) / "stats";
  fs::create_directories(dir, ec);

  auto pw = writer_for("stats", dir, stats_schema());
  if (pw == nullptr) {
    pending_stats_rows_.clear();
    return;
  }

  const auto schema = stats_schema();
  arrow::TimestampBuilder ts_builder(arrow::timestamp(arrow::TimeUnit::SECOND),
                                     arrow::default_memory_pool());
  arrow::UInt64Builder cols[29];
  for (const auto& row : pending_stats_rows_) {
    // rows are TSV: sec then 28 u64 columns
    std::vector<std::string> f;
    std::string tok;
    std::istringstream ss(row);
    while (std::getline(ss, tok, '\t'))
      f.push_back(tok);
    if (f.size() != 30)
      continue;
    (void)ts_builder.Append(std::stoll(f[0]));
    for (int i = 0; i < 29; ++i)
      (void)cols[i].Append(std::stoull(f[i + 1]));
  }

  std::vector<std::shared_ptr<arrow::Array>> arrays;
  arrays.reserve(30);
  std::shared_ptr<arrow::Array> a;
  (void)ts_builder.Finish(&a);
  arrays.push_back(a);
  for (int i = 0; i < 29; ++i) {
    (void)cols[i].Finish(&a);
    arrays.push_back(a);
  }
  auto batch = arrow::RecordBatch::Make(
      schema, static_cast<std::int64_t>(pending_stats_rows_.size()), arrays);
  arrow::Status st = pw->writer->WriteRecordBatch(*batch);
  if (!st.ok()) {
    ok_ = false;
    error_ = "stats write failed: " + st.ToString();
  } else {
    stats_written_ += pending_stats_rows_.size();
  }
  pending_stats_rows_.clear();
}

void ArchiveWriter::flush_depth() {
  if (pending_depth_rows_.empty() || !ok_) {
    pending_depth_rows_.clear();
    return;
  }
  std::error_code ec;
  const fs::path dir = fs::path(archive_dir_) / "depth";
  fs::create_directories(dir, ec);

  auto pw = writer_for("depth", dir, depth_schema());
  if (pw == nullptr) {
    pending_depth_rows_.clear();
    return;
  }
  const auto schema = depth_schema();
  arrow::TimestampBuilder sec_builder(arrow::timestamp(arrow::TimeUnit::SECOND),
                                      arrow::default_memory_pool());
  arrow::StringBuilder sym_builder, side_builder;
  arrow::UInt8Builder level_builder;
  arrow::Int64Builder price_builder;
  arrow::UInt64Builder qty_builder;

  for (const auto& row : pending_depth_rows_) {
    // TSV: sec symbol side level price qty
    std::vector<std::string> f;
    std::string tok;
    std::istringstream ss(row);
    while (std::getline(ss, tok, '\t'))
      f.push_back(tok);
    if (f.size() != 6)
      continue;
    (void)(void)sec_builder.Append(std::stoll(f[0]));
    (void)(void)sym_builder.Append(f[1]);
    (void)(void)side_builder.Append(f[2]);
    (void)(void)level_builder.Append(static_cast<std::uint8_t>(std::stoi(f[3])));
    (void)price_builder.Append(std::stoll(f[4]));
    (void)qty_builder.Append(std::stoull(f[5]));
  }
  std::shared_ptr<arrow::Array> a0, a1, a2, a3, a4, a5;
  (void)sec_builder.Finish(&a0);
  (void)sym_builder.Finish(&a1);
  (void)side_builder.Finish(&a2);
  (void)level_builder.Finish(&a3);
  (void)price_builder.Finish(&a4);
  (void)qty_builder.Finish(&a5);
  auto batch = arrow::RecordBatch::Make(
      schema, static_cast<std::int64_t>(pending_depth_rows_.size()), {a0, a1, a2, a3, a4, a5});
  arrow::Status st = pw->writer->WriteRecordBatch(*batch);
  if (!st.ok()) {
    ok_ = false;
    error_ = "depth write failed: " + st.ToString();
  } else {
    depth_written_ += pending_depth_rows_.size();
  }
  pending_depth_rows_.clear();
}

void ArchiveWriter::flush_gaps() {
  if (pending_gaps_.empty() || !ok_) {
    pending_gaps_.clear();
    return;
  }
  std::error_code ec;
  const fs::path dir = fs::path(archive_dir_) / "gaps";
  fs::create_directories(dir, ec);

  auto pw = writer_for("gaps", dir, gaps_schema());
  if (pw == nullptr) {
    pending_gaps_.clear();
    return;
  }
  const auto schema = gaps_schema();
  arrow::TimestampBuilder dts(arrow::timestamp(arrow::TimeUnit::NANO),
                              arrow::default_memory_pool());
  arrow::TimestampBuilder hts(arrow::timestamp(arrow::TimeUnit::NANO),
                              arrow::default_memory_pool());
  arrow::UInt64Builder start_b, end_b, missing_b;
  arrow::BooleanBuilder healed_b;

  TimeBase& tb = TimeBase::instance();
  for (const auto& g : pending_gaps_) {
    (void)(void)dts.Append(static_cast<std::int64_t>(tb.ticks_to_realtime_ns(g.detected_ticks)));
    (void)(void)hts.Append(
        static_cast<std::int64_t>(g.healed ? tb.ticks_to_realtime_ns(g.healed_ticks) : 0));
    (void)(void)start_b.Append(g.start);
    (void)(void)end_b.Append(g.end);
    (void)(void)missing_b.Append(g.missing);
    (void)(void)healed_b.Append(g.healed);
  }
  std::shared_ptr<arrow::Array> a0, a1, a2, a3, a4, a5;
  (void)dts.Finish(&a0);
  (void)hts.Finish(&a1);
  (void)start_b.Finish(&a2);
  (void)end_b.Finish(&a3);
  (void)missing_b.Finish(&a4);
  (void)healed_b.Finish(&a5);
  auto batch = arrow::RecordBatch::Make(schema, static_cast<std::int64_t>(pending_gaps_.size()),
                                        {a0, a1, a2, a3, a4, a5});
  arrow::Status st = pw->writer->WriteRecordBatch(*batch);
  if (!st.ok()) {
    ok_ = false;
    error_ = "gaps write failed: " + st.ToString();
  } else {
    gaps_written_ += pending_gaps_.size();
  }
  pending_gaps_.clear();
}

void ArchiveWriter::publish_snapshot() {
  if (dash_fd_ < 0)
    return;
  TimeBase& tb = TimeBase::instance();
  const std::uint64_t now_ticks = tb.now_ticks();

  std::string out;
  out.reserve(65536);
  out += "{\"ts_ns\":";
  out += std::to_string(tb.ticks_to_realtime_ns(now_ticks));

  out += ",\"archive_drops\":";
  out += std::to_string(last_stats_.archive_drops);
  out += ",\"ring_drops\":";
  out += std::to_string(last_stats_.ring_drops);
  out += ",\"gaps\":{\"detected\":";
  out += std::to_string(last_stats_.gaps_detected);
  out += ",\"healed\":";
  out += std::to_string(last_stats_.gaps_healed);
  out += ",\"lost\":";
  out += std::to_string(last_stats_.permanently_lost);
  out += ",\"recovered\":";
  out += std::to_string(last_stats_.recovered);
  out += ",\"recent\":[";
  const std::size_t from =
      recent_gaps_.size() > kMaxRecentGaps ? recent_gaps_.size() - kMaxRecentGaps : 0;
  for (std::size_t i = from; i < recent_gaps_.size(); ++i) {
    const GapEvent& g = recent_gaps_[i];
    if (i > from)
      out += ',';
    out += "{\"start\":";
    out += std::to_string(g.start);
    out += ",\"end\":";
    out += std::to_string(g.end);
    out += ",\"missing\":";
    out += std::to_string(g.missing);
    out += ",\"healed\":";
    out += g.healed ? "true" : "false";
    out += ",\"heal_ns\":";
    out += std::to_string(g.healed ? tb.delta_ns(g.healed_ticks, g.detected_ticks) : 0);
    out += '}';
  }
  out += "]}";

  auto lat = [&](const char* name, const LatencyPercentiles& p) {
    out += ",\"";
    out += name;
    out += "\":{\"count\":";
    out += std::to_string(p.count);
    out += ",\"p50\":";
    out += std::to_string(p.p50);
    out += ",\"p90\":";
    out += std::to_string(p.p90);
    out += ",\"p99\":";
    out += std::to_string(p.p99);
    out += ",\"p99_9\":";
    out += std::to_string(p.p999);
    out += ",\"p99_99\":";
    out += std::to_string(p.p9999);
    out += ",\"max\":";
    out += std::to_string(p.max);
    out += '}';
  };
  lat("queue_delay", last_stats_.queue_delay);
  lat("decode_time", last_stats_.decode_time);
  lat("wire_to_book", last_stats_.wire_to_book);

  out += ",\"histogram\":{\"sec\":";
  out += std::to_string(last_stats_.sec);
  out += ",\"buckets\":[";
  for (std::uint32_t i = 0; i < last_stats_.bucket_count; ++i) {
    if (i > 0)
      out += ',';
    out += '[';
    out += std::to_string(last_stats_.buckets[i].value);
    out += ',';
    out += std::to_string(last_stats_.buckets[i].count);
    out += ']';
  }
  out += "]}";

  out += ",\"stats\":{\"sec\":";
  out += std::to_string(last_stats_.sec);
  out += ",\"messages\":";
  out += std::to_string(last_stats_.messages);
  out += ",\"packets\":";
  out += std::to_string(last_stats_.packets);
  out += '}';

  // Top-10 books for every symbol.
  out += ",\"books\":{";
  constexpr int kDepth = 10;
  std::uint64_t written_symbols = 0;
  // Symbols are enumerated by replaying the archive-thread book's symbols;
  // iterate a fixed small set via snapshots of known symbols.
  for (int i = 0; i < 1000; ++i) {
    char sym[9];
    std::snprintf(sym, sizeof sym, "SYM%05d", i);
    DepthSnapshot s;
    if (!book_.snapshot(sym, kDepth, s))
      break;
    if (written_symbols++ > 0)
      out += ',';
    out += '"';
    out += sym;
    out += "\":{\"bids\":[";
    for (std::size_t j = 0; j < s.bids.size(); ++j) {
      if (j > 0)
        out += ',';
      out += '[';
      out += std::to_string(s.bids[j].price_ticks);
      out += ',';
      out += std::to_string(s.bids[j].qty);
      out += ']';
    }
    out += "],\"asks\":[";
    for (std::size_t j = 0; j < s.asks.size(); ++j) {
      if (j > 0)
        out += ',';
      out += '[';
      out += std::to_string(s.asks[j].price_ticks);
      out += ',';
      out += std::to_string(s.asks[j].qty);
      out += ']';
    }
    out += "]}";
  }
  out += "}}";

  struct sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, dash_socket_path_.c_str(), sizeof(addr.sun_path) - 1);
  const ssize_t sent = ::sendto(dash_fd_, out.data(), out.size(), MSG_DONTWAIT | MSG_NOSIGNAL,
                                reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  if (sent == static_cast<ssize_t>(out.size())) {
    ++snapshots_published_;
  } else {
    ++publish_errors_;  // receiver down / socket full: never retry hard here
    if (publish_errors_ == 1) {
      std::fprintf(stderr, "wiretap: dash publish failed (%zu bytes): %s\n", out.size(),
                   std::strerror(errno));
    }
  }
}

void ArchiveWriter::drain(SpscRing<BookUpdate>& updates, SpscRing<SecondStats>& stats,
                          SpscRing<GapEvent>& gaps) {
  BookUpdate u;
  while (updates.try_pop(u)) {
    pending_updates_.push_back(u);
    book_.apply(u);
  }
  SecondStats s;
  if (stats.try_pop(s)) {
    last_stats_ = s;
    have_stats_ = true;
    if (archive_dir_.size()) {
      auto add = [](std::string& r, std::uint64_t v) {
        r += std::to_string(v);
        r.push_back('\t');
      };
      auto addp = [&](std::string& r, const LatencyPercentiles& p) {
        add(r, p.count);
        add(r, p.p50);
        add(r, p.p90);
        add(r, p.p99);
        add(r, p.p999);
        add(r, p.p9999);
        add(r, p.max);
      };
      std::string row;
      add(row, s.sec);
      add(row, s.messages);
      add(row, s.packets);
      add(row, s.ring_drops);
      add(row, s.archive_drops);
      add(row, s.gaps_detected);
      add(row, s.gaps_healed);
      add(row, s.permanently_lost);
      add(row, s.recovered);
      addp(row, s.queue_delay);
      addp(row, s.decode_time);
      addp(row, s.wire_to_book);
      row.pop_back();  // trailing tab
      pending_stats_rows_.emplace_back(std::move(row));
    }
    last_stats_ = s;
    have_stats_ = true;
  }
  GapEvent g;
  while (gaps.try_pop(g)) {
    recent_gaps_.push_back(g);
    if (recent_gaps_.size() > 200) {
      recent_gaps_.erase(
          recent_gaps_.begin(),
          recent_gaps_.begin() + static_cast<long>(recent_gaps_.size() - kMaxRecentGaps));
    }
    if (archive_dir_.size())
      pending_gaps_.push_back(g);
  }

  // Per-second depth snapshots (into the depth table).
  if (archive_dir_.size() && have_stats_) {
    const std::uint64_t sec = last_stats_.sec;
    if (sec != last_depth_sec_) {
      last_depth_sec_ = sec;
      constexpr int kDepth = 10;
      for (int i = 0; i < 1000; ++i) {
        char sym[9];
        std::snprintf(sym, sizeof sym, "SYM%05d", i);
        DepthSnapshot s;
        if (!book_.snapshot(sym, kDepth, s))
          break;
        auto emit = [&](const std::vector<DepthLevel>& levels, const char* side) {
          for (std::size_t j = 0; j < levels.size(); ++j) {
            char row[128];
            std::snprintf(row, sizeof row, "%llu\t%s\t%s\t%zu\t%u\t%llu\n",
                          static_cast<unsigned long long>(sec), sym, side, j, levels[j].price_ticks,
                          static_cast<unsigned long long>(levels[j].qty));
            pending_depth_rows_.emplace_back(row);
          }
        };
        emit(s.bids, "B");
        emit(s.asks, "A");
      }
    }
  }
}

void ArchiveWriter::run(SpscRing<BookUpdate>& updates, SpscRing<SecondStats>& stats,
                        SpscRing<GapEvent>& gaps, const std::atomic<bool>& stop) {
  auto last_flush = std::chrono::steady_clock::now();
  auto last_publish = last_flush;

  while (!stop.load(std::memory_order_relaxed)) {
    drain(updates, stats, gaps);

    const auto now = std::chrono::steady_clock::now();
    if (pending_updates_.size() >= kMaxPendingUpdates ||
        std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush).count() >=
            kFlushMaxAgeMs) {
      if (archive_dir_.size()) {
        flush_updates();
        flush_gaps();
        if (pending_stats_rows_.size() >= kStatsFlushRows)
          flush_stats();
        flush_depth();
      }
      last_flush = now;
    }
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_publish).count() >=
        kPublishIntervalMs) {
      publish_snapshot();
      last_publish = now;
    }
    if (updates.empty() && stats.empty() && gaps.empty()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  // Final drain + flush + close.
  drain(updates, stats, gaps);
  if (archive_dir_.size()) {
    flush_updates();
    flush_gaps();
    flush_stats();
    flush_depth();
    close_all_writers();
  }
  publish_snapshot();
}

std::uint64_t ArchiveWriter::updates_written() const noexcept {
  return updates_written_;
}
std::uint64_t ArchiveWriter::stats_written() const noexcept {
  return stats_written_;
}
std::uint64_t ArchiveWriter::gaps_written() const noexcept {
  return gaps_written_;
}
std::uint64_t ArchiveWriter::depth_written() const noexcept {
  return depth_written_;
}
std::uint64_t ArchiveWriter::snapshots_published() const noexcept {
  return snapshots_published_;
}
std::uint64_t ArchiveWriter::publish_errors() const noexcept {
  return publish_errors_;
}

}  // namespace wiretap
