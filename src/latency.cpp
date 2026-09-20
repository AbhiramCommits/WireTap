#include "latency.hpp"

#include <hdr/hdr_histogram.h>

#include <cstdlib>

#include <cinttypes>
#include <string>

namespace wiretap {

namespace {

constexpr std::int64_t kMinValueNs = 1;
constexpr std::int64_t kMaxValueNs = 10 * 1000 * 1000 * 1000LL;  // 10 s
constexpr int kSignificantDigits = 3;

struct hdr_histogram* make_histogram() {
  struct hdr_histogram* h = nullptr;
  ::hdr_init(kMinValueNs, kMaxValueNs, kSignificantDigits, &h);
  return h;
}

}  // namespace

const char* latency_stage_name(LatencyStage stage) noexcept {
  switch (stage) {
    case LatencyStage::WireToUserspace:
      return "wire_to_userspace";
    case LatencyStage::QueueDelay:
      return "queue_delay";
    case LatencyStage::DecodeTime:
      return "decode_time";
    case LatencyStage::WireToBook:
      return "wire_to_book";
    default:
      return "unknown";
  }
}

bool write_histogram_hgrm(struct hdr_histogram* h, const std::string& path) {
  if (h == nullptr)
    return false;
  FILE* f = std::fopen(path.c_str(), "w");
  if (f == nullptr)
    return false;
  ::hdr_percentiles_print(h, f, 5, 1.0, CLASSIC);
  std::fclose(f);
  return true;
}

void free_histogram(struct hdr_histogram* h) noexcept {
  if (h == nullptr)
    return;
  std::free(h->counts);  // counts is a separate allocation in 0.11.x
  std::free(h);
}

std::uint64_t histogram_total_count(const struct hdr_histogram* h) noexcept {
  return h == nullptr ? 0 : static_cast<std::uint64_t>(h->total_count);
}

LatencyRecorder::LatencyRecorder() {
  for (auto& h : hists_)
    h = make_histogram();
}

LatencyRecorder::~LatencyRecorder() {
  for (auto& h : hists_) {
    if (h != nullptr)
      free_histogram(h);
  }
}

void LatencyRecorder::record(LatencyStage stage, std::uint64_t ns) noexcept {
  struct hdr_histogram* h = hists_[static_cast<std::size_t>(stage)];
  if (h == nullptr)
    return;
  ::hdr_record_value(h, static_cast<std::int64_t>(ns >= 1 ? ns : 1));
}

void LatencyRecorder::reset() noexcept {
  for (auto& h : hists_) {
    if (h != nullptr)
      free_histogram(h);
    h = make_histogram();
  }
}

void LatencyRecorder::merge(const LatencyRecorder& other) noexcept {
  for (std::size_t i = 0; i < hists_.size(); ++i) {
    if (hists_[i] != nullptr && other.hists_[i] != nullptr) {
      ::hdr_add(hists_[i], other.hists_[i]);
    }
  }
}

std::uint64_t LatencyRecorder::count(LatencyStage stage) const noexcept {
  const struct hdr_histogram* h = hists_[static_cast<std::size_t>(stage)];
  return h == nullptr ? 0 : histogram_total_count(h);
}

std::uint64_t LatencyRecorder::value_at(LatencyStage stage, double percentile) const noexcept {
  const struct hdr_histogram* h = hists_[static_cast<std::size_t>(stage)];
  return h == nullptr ? 0 : static_cast<std::uint64_t>(::hdr_value_at_percentile(h, percentile));
}

std::uint64_t LatencyRecorder::max_value(LatencyStage stage) const noexcept {
  const struct hdr_histogram* h = hists_[static_cast<std::size_t>(stage)];
  return h == nullptr ? 0 : static_cast<std::uint64_t>(::hdr_max(h));
}

double LatencyRecorder::mean(LatencyStage stage) const noexcept {
  const struct hdr_histogram* h = hists_[static_cast<std::size_t>(stage)];
  return h == nullptr ? 0.0 : ::hdr_mean(h);
}

void LatencyRecorder::write_report(const std::string& dir, const std::string& prefix,
                                   FILE* out) const {
  const double percentiles[] = {50.0, 90.0, 99.0, 99.9, 99.99};
  std::fprintf(out,
               "latency (ns)            count       mean        p50        p90        p99      "
               "p99.9     p99.99        max\n");

  // JSON summary (hand-built; keys are fixed).
  std::string json_path = dir + "/" + prefix + "-latency.json";
  FILE* jf = std::fopen(json_path.c_str(), "w");
  if (jf != nullptr) {
    std::fprintf(jf, "{\n  \"stages\": {\n");
  }

  for (std::size_t i = 0; i < hists_.size(); ++i) {
    const auto stage = static_cast<LatencyStage>(i);
    const struct hdr_histogram* h = hists_[i];
    if (h == nullptr)
      continue;
    const std::uint64_t c = histogram_total_count(h);
    const double mean = c > 0 ? ::hdr_mean(h) : 0.0;  // hdr_mean is NaN when empty
    std::fprintf(out, "  %-18s %12" PRIu64 " %10.1f", latency_stage_name(stage), c, mean);
    for (double p : percentiles) {
      std::fprintf(out, " %10" PRIu64, static_cast<std::uint64_t>(::hdr_value_at_percentile(h, p)));
    }
    std::fprintf(out, " %10" PRIu64 "\n", static_cast<std::uint64_t>(::hdr_max(h)));

    {
      std::string hgrm_path = dir;
      hgrm_path += '/';
      hgrm_path += prefix;
      hgrm_path += '-';
      hgrm_path += latency_stage_name(stage);
      hgrm_path += ".hgrm";
      write_histogram_hgrm(hists_[i], hgrm_path);
    }

    if (jf != nullptr) {
      std::fprintf(jf,
                   "    \"%s\": {\"count\": %" PRIu64 ", \"mean_ns\": %.1f, \"p50_ns\": %" PRIu64
                   ", \"p90_ns\": %" PRIu64 ", \"p99_ns\": %" PRIu64 ", \"p99_9_ns\": %" PRIu64
                   ", \"p99_99_ns\": %" PRIu64 ", \"max_ns\": %" PRIu64 "}",
                   latency_stage_name(stage), c, mean,
                   static_cast<std::uint64_t>(::hdr_value_at_percentile(h, 50.0)),
                   static_cast<std::uint64_t>(::hdr_value_at_percentile(h, 90.0)),
                   static_cast<std::uint64_t>(::hdr_value_at_percentile(h, 99.0)),
                   static_cast<std::uint64_t>(::hdr_value_at_percentile(h, 99.9)),
                   static_cast<std::uint64_t>(::hdr_value_at_percentile(h, 99.99)),
                   static_cast<std::uint64_t>(::hdr_max(h)));
      std::fprintf(jf, i + 1 < hists_.size() ? ",\n" : "\n");
    }
  }

  if (jf != nullptr) {
    std::fprintf(jf, "  }\n}\n");
    std::fclose(jf);
  }
}

}  // namespace wiretap
