// wiretap/archive_writer.hpp - Parquet archive + dashboard publishing.
//
// Cold-path data layer, gated on WIRETAP_HAVE_ARROW. The decode thread pushes
// BookUpdates / SecondStats / GapEvents into lock-free rings (try_push only:
// if a ring is full, the sample is dropped and counted, never blocking the
// decode thread). A dedicated archive thread drains the rings and:
//   - writes BookUpdates as Parquet (ZSTD, ~1M rows per row group),
//     partitioned by date/symbol/hour (hive layout),
//   - writes per-second aggregate stats (messages, gaps, latency
//     percentiles) to a stats table,
//   - writes per-second per-symbol depth snapshots to a depth table,
//   - writes closed gap events to a gaps table,
//   - optionally publishes a 10 Hz live snapshot (books, counters, latency,
//     histogram buckets, recent gaps) as JSON over a Unix datagram socket for
//     the dashboard backend.
//
// The archive thread also maintains its own BookBuilder (fed by the same
// BookUpdate stream) so the hot path never shares mutable state with it.

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "book_builder.hpp"
#include "gap_tracker.hpp"
#include "wiretap/spsc_ring.hpp"

struct hdr_histogram;  // global struct from hdr_histogram.h

namespace arrow {
class Schema;
}

namespace wiretap {

struct LatencyPercentiles {
  std::uint64_t count = 0;
  std::uint64_t p50 = 0;
  std::uint64_t p90 = 0;
  std::uint64_t p99 = 0;
  std::uint64_t p999 = 0;
  std::uint64_t p9999 = 0;
  std::uint64_t max = 0;
};

struct HistogramBucket {
  std::uint64_t value = 0;
  std::uint64_t count = 0;
};

// Full-distribution buckets for one histogram (3 sig figs, 1ns..10s fits in
// ~1024 buckets; keep headroom).
inline constexpr std::size_t kMaxHistogramBuckets = 2048;

// Per-second aggregate stats produced by the decode thread and pushed into
// the stats ring at each wall-clock second boundary.
struct SecondStats {
  std::uint64_t sec = 0;               // unix seconds
  std::uint64_t messages = 0;          // messages decoded this second
  std::uint64_t packets = 0;           // packets decoded this second
  std::uint64_t ring_drops = 0;        // live ring drops (cumulative)
  std::uint64_t archive_drops = 0;     // archive ring drops (cumulative)
  std::uint64_t gaps_detected = 0;     // cumulative
  std::uint64_t gaps_healed = 0;       // cumulative
  std::uint64_t permanently_lost = 0;  // cumulative
  std::uint64_t recovered = 0;         // cumulative
  LatencyPercentiles queue_delay{};
  LatencyPercentiles decode_time{};
  LatencyPercentiles wire_to_book{};
  std::uint32_t bucket_count = 0;  // wire_to_book distribution (may truncate)
  HistogramBucket buckets[kMaxHistogramBuckets]{};
};

class ArchiveWriter {
 public:
  // `archive_dir`: Parquet root (empty string = no parquet).
  // `dash_socket_path`: unix dgram path to publish live snapshots to
  // (empty string = no publishing).
  ArchiveWriter(std::string archive_dir, std::string dash_socket_path);
  ~ArchiveWriter();

  ArchiveWriter(const ArchiveWriter&) = delete;
  ArchiveWriter& operator=(const ArchiveWriter&) = delete;

  bool ok() const noexcept { return ok_; }
  const std::string& error() const noexcept { return error_; }

  // Blocks until `stop` is set; drains the rings before returning and
  // finalizes every open Parquet file.
  void run(SpscRing<BookUpdate>& updates, SpscRing<SecondStats>& stats, SpscRing<GapEvent>& gaps,
           const std::atomic<bool>& stop);

  std::uint64_t updates_written() const noexcept;
  std::uint64_t stats_written() const noexcept;
  std::uint64_t gaps_written() const noexcept;
  std::uint64_t depth_written() const noexcept;
  std::uint64_t snapshots_published() const noexcept;
  std::uint64_t publish_errors() const noexcept;

 private:
  struct ParquetWriter;  // implementation detail

  std::shared_ptr<ParquetWriter> writer_for(const std::string& partition_key,
                                            const std::filesystem::path& dir,
                                            const std::shared_ptr<arrow::Schema>& schema);
  void drain(SpscRing<BookUpdate>& updates, SpscRing<SecondStats>& stats, SpscRing<GapEvent>& gaps);
  void flush_updates();
  void flush_stats();
  void flush_depth();
  void flush_gaps();
  void publish_snapshot();
  void close_all_writers();

  std::string archive_dir_;
  std::string dash_socket_path_;
  bool ok_ = true;
  std::string error_;
  int dash_fd_ = -1;

  BookBuilder book_;  // archive-thread private book for live snapshots

  std::vector<BookUpdate> pending_updates_;      // flushed at ~1M rows / 5 s
  std::vector<std::string> pending_stats_rows_;  // TSV rows, flushed every 60
  std::vector<std::string> pending_depth_rows_;
  std::vector<GapEvent> pending_gaps_;

  std::map<std::string, std::shared_ptr<ParquetWriter>> writers_;  // by partition
  std::uint64_t file_counter_ = 0;
  std::uint64_t last_depth_sec_ = 0;

  std::vector<GapEvent> recent_gaps_;  // last 20 for the live snapshot

  // Last published second-stats (latency percentiles + histogram buckets).
  SecondStats last_stats_{};
  bool have_stats_ = false;

  std::uint64_t updates_written_{0};
  std::uint64_t stats_written_{0};
  std::uint64_t gaps_written_{0};
  std::uint64_t depth_written_{0};
  std::uint64_t snapshots_published_{0};
  std::uint64_t publish_errors_{0};
};

// Dumps a histogram's (value, count) buckets in ascending value order.
// Returns the number of buckets written (truncated to `max`). (Takes the
// GLOBAL hdr_histogram struct; declared inside the namespace for convenience.)
std::uint32_t dump_histogram_buckets(struct ::hdr_histogram* h, HistogramBucket* out,
                                     std::uint32_t max);

}  // namespace wiretap
