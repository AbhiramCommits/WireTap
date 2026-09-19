// wiretap/latency.hpp - HdrHistogram-based latency recording.
//
// One LatencyRecorder per thread (recording is single-threaded and lock-free:
// the receiver thread records wire_to_userspace, the decode thread records the
// other three stages). Histograms are merged only at report time, after the
// threads have been joined.

#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

struct hdr_histogram;

namespace wiretap {

enum class LatencyStage : std::uint8_t {
  WireToUserspace = 0,  // recv_ts - hw/kernel_ts (receiver thread)
  QueueDelay,           // decode_start_ts - recv_ts  (ring dwell)
  DecodeTime,           // decode_end_ts - decode_start_ts
  WireToBook,           // book_applied_ts - hw/kernel_ts (headline)
  kCount
};

const char* latency_stage_name(LatencyStage stage) noexcept;

// Writes a histogram in HdrHistogram's standard .hgrm percentile format.
// Returns false if the file could not be opened.
bool write_histogram_hgrm(struct hdr_histogram* h, const std::string& path);

// Releases a histogram allocated by hdr_init (frees the counts array too).
void free_histogram(struct hdr_histogram* h) noexcept;

// Total recorded count (h->total_count in HdrHistogram_c 0.11.x).
std::uint64_t histogram_total_count(const struct hdr_histogram* h) noexcept;

// Histograms: 3 significant digits, 1 ns .. 10 s.
class LatencyRecorder {
 public:
  LatencyRecorder();
  ~LatencyRecorder();
  LatencyRecorder(const LatencyRecorder&) = delete;
  LatencyRecorder& operator=(const LatencyRecorder&) = delete;

  // Records one sample in nanoseconds (clamped to >= 1). Call from a single
  // thread per instance.
  void record(LatencyStage stage, std::uint64_t ns) noexcept;

  // Merges `other` into this recorder. Report-time only (never concurrent
  // with record()).
  void merge(const LatencyRecorder& other) noexcept;

  std::uint64_t count(LatencyStage stage) const noexcept;
  std::uint64_t value_at(LatencyStage stage, double percentile) const noexcept;
  std::uint64_t max_value(LatencyStage stage) const noexcept;
  double mean(LatencyStage stage) const noexcept;

  // Prints a percentile table to `out` and writes per-stage .hgrm files plus
  // a JSON summary under `dir` (file names: {prefix}-{stage}.hgrm and
  // {prefix}-latency.json).
  void write_report(const std::string& dir, const std::string& prefix,
                    FILE* out) const;

  struct hdr_histogram* histogram(LatencyStage stage) noexcept {
    return hists_[static_cast<std::size_t>(stage)];
  }

 private:
  std::array<struct hdr_histogram*, static_cast<std::size_t>(LatencyStage::kCount)>
      hists_{};
};

}  // namespace wiretap
