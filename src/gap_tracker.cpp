#include "gap_tracker.hpp"

#include <hdr/hdr_histogram.h>

#include <cinttypes>
#include <utility>

#include "latency.hpp"
#include "time_base.hpp"

namespace wiretap {

GapTracker::GapTracker(std::size_t window, std::uint64_t timeout_ns)
    : window_(window == 0 ? 1 : window),
      timeout_ticks_(TimeBase::instance().ns_to_ticks(timeout_ns)) {
  ::hdr_init(1, 10 * 1000 * 1000 * 1000LL, 3, &heal_hist_);
}

GapTracker::~GapTracker() {
  if (heal_hist_ != nullptr)
    free_histogram(heal_hist_);
}

PushResult GapTracker::push(std::uint64_t seq, std::uint64_t now_ticks, const std::uint8_t* bytes,
                            std::size_t len, std::uint64_t recv_ts_ticks,
                            std::uint64_t hw_ts_ticks) noexcept {
  PushResult res;

  if (!started_) {
    started_ = true;
    expected_ = seq + 1;  // `expected_` is the NEXT seq we want to apply
    res.disposition = PacketDisposition::Apply;
    return res;
  }

  if (seq == expected_) {
    ++expected_;
    pull_buffered();
    maybe_heal(now_ticks);
    res.disposition = PacketDisposition::Apply;
    return res;
  }

  if (seq < expected_) {
    dups_.fetch_add(1, std::memory_order_relaxed);
    res.disposition = PacketDisposition::Discard;
    return res;
  }

  // seq > expected_: a gap opens (or extends).
  if (!gap_active_) {
    gap_active_ = true;
    gap_end_ = seq;
    gap_detected_ticks_ = now_ticks;
    gap_lost_ = 0;
    gaps_.fetch_add(1, std::memory_order_relaxed);
    events_.push_back({expected_, seq - 1, seq - expected_, now_ticks, 0, false});
    res.gap_detected = true;
    res.new_gap = {expected_, seq - 1};
  } else if (seq > gap_end_) {
    // The gap extends: request the newly discovered missing range
    // [old gap_end + 1, seq - 1] so recovery covers it too.
    const std::uint64_t old_end = gap_end_;
    gap_end_ = seq;
    events_.back().end = seq - 1;
    if (seq - 1 > old_end) {
      events_.back().missing += seq - 1 - old_end;
      res.gap_detected = true;
      res.new_gap = {old_end + 1, seq - 1};
    }
  }

  BufferedPacket p;
  p.seq = seq;
  p.recv_ts_ticks = recv_ts_ticks;
  p.hw_ts_ticks = hw_ts_ticks;
  p.bytes.assign(bytes, bytes + len);
  buffered_.emplace(seq, std::move(p));
  if (buffered_.size() > window_) {
    buffered_.erase(std::prev(buffered_.end()));  // evict the furthest-out
    wdrops_.fetch_add(1, std::memory_order_relaxed);
  }

  res.disposition = PacketDisposition::Buffered;
  return res;
}

bool GapTracker::pop_applicable(BufferedPacket& out) noexcept {
  if (ready_.empty())
    return false;
  out = std::move(ready_.front());
  ready_.pop_front();
  return true;
}

void GapTracker::pull_buffered() noexcept {
  while (!buffered_.empty() && buffered_.begin()->first == expected_) {
    auto it = buffered_.begin();
    ready_.push_back(std::move(it->second));
    buffered_.erase(it);
    ++expected_;
  }
}

void GapTracker::maybe_heal(std::uint64_t now_ticks) noexcept {
  if (!gap_active_ || expected_ < gap_end_)
    return;
  gap_active_ = false;
  events_.back().end = expected_ - 1;
  if (gap_lost_ == 0) {
    events_.back().healed = true;
    events_.back().healed_ticks = now_ticks;
    healed_.fetch_add(1, std::memory_order_relaxed);
    const std::uint64_t heal_ns = TimeBase::instance().delta_ns(now_ticks, gap_detected_ticks_);
    ::hdr_record_value(heal_hist_, static_cast<std::int64_t>(heal_ns >= 1 ? heal_ns : 1));
  }
}

void GapTracker::advance_time(std::uint64_t now_ticks) noexcept {
  if (!gap_active_)
    return;
  if (now_ticks - gap_detected_ticks_ < timeout_ticks_)
    return;

  if (!buffered_.empty()) {
    // Skip straight to the next packet we actually have; everything before it
    // is permanently lost.
    const std::uint64_t next_known = buffered_.begin()->first;
    if (next_known > expected_) {
      gap_lost_ += next_known - expected_;
      lost_.fetch_add(next_known - expected_, std::memory_order_relaxed);
      expected_ = next_known;
    }
    pull_buffered();
    maybe_heal(now_ticks);
  } else {
    // Nothing buffered beyond the gap: give up on one seq and re-arm.
    ++expected_;
    ++gap_lost_;
    lost_.fetch_add(1, std::memory_order_relaxed);
    gap_detected_ticks_ = now_ticks;
    maybe_heal(now_ticks);
  }
}

void GapTracker::flush(std::uint64_t now_ticks) {
  if (!started_)
    return;
  if (gap_active_) {
    if (!buffered_.empty()) {
      const std::uint64_t next_known = buffered_.begin()->first;
      if (next_known > expected_) {
        gap_lost_ += next_known - expected_;
        lost_.fetch_add(next_known - expected_, std::memory_order_relaxed);
        expected_ = next_known;
      }
    } else {
      gap_lost_ += gap_end_ - expected_;
      lost_.fetch_add(gap_end_ - expected_, std::memory_order_relaxed);
      expected_ = gap_end_;
    }
    events_.back().end = expected_ - 1;
    gap_active_ = false;  // never "healed": the stream ended first
    (void)now_ticks;
  }
  pull_buffered();
}

void GapTracker::write_heal_report(const std::string& dir, const std::string& prefix,
                                   FILE* out) const {
  if (heal_hist_ == nullptr)
    return;
  std::fprintf(out,
               "time-to-heal (ns)      count       mean        p50        p90        p99      "
               "p99.9     p99.99        max\n");
  std::fprintf(out,
               "  %-18s %12" PRIu64 " %10.1f %10" PRIu64 " %10" PRIu64 " %10" PRIu64 " %10" PRIu64
               " %10" PRIu64 " %10" PRIu64 "\n",
               "gap_heal", static_cast<std::uint64_t>(histogram_total_count(heal_hist_)),
               ::hdr_mean(heal_hist_),
               static_cast<std::uint64_t>(::hdr_value_at_percentile(heal_hist_, 50.0)),
               static_cast<std::uint64_t>(::hdr_value_at_percentile(heal_hist_, 90.0)),
               static_cast<std::uint64_t>(::hdr_value_at_percentile(heal_hist_, 99.0)),
               static_cast<std::uint64_t>(::hdr_value_at_percentile(heal_hist_, 99.9)),
               static_cast<std::uint64_t>(::hdr_value_at_percentile(heal_hist_, 99.99)),
               static_cast<std::uint64_t>(::hdr_max(heal_hist_)));
  write_histogram_hgrm(heal_hist_, dir + "/" + prefix + "-heal.hgrm");
}

}  // namespace wiretap
