// wiretap/gap_tracker.hpp - sequence-number gap detection + reorder window.
//
// Owned by the decode thread (single writer; all mutating methods are
// decode-thread-only, so the hot path stays lock-free). Counters are relaxed
// atomics so a stats thread can read them live.
//
// Model: packets arrive with monotonically increasing sequence numbers. The
// tracker keeps an `expected` pointer:
//   seq == expected        -> apply immediately (hot path, zero copy)
//   seq <  expected        -> duplicate, discarded
//   seq >  expected        -> gap: buffer in the reorder window, emit a
//                             GapRequest so a recovery path can fetch the
//                             missing range
// advance_time() skips ranges that stay missing past the timeout
// (permanently lost); flush() closes everything out once producers are gone.
// A gap "heals" when the expected pointer catches up without any loss; the
// time-to-heal is recorded in its own histogram.

#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

struct hdr_histogram;

namespace wiretap {

struct GapRequest {
  std::uint64_t start = 0;  // first missing sequence number (inclusive)
  std::uint64_t end = 0;    // last missing sequence number (inclusive)
};

struct GapEvent {
  std::uint64_t start = 0;    // first seq affected by the gap episode
  std::uint64_t end = 0;      // last seq affected (may include survivors)
  std::uint64_t missing = 0;  // total seqs actually missing in the episode
  std::uint64_t detected_ticks = 0;
  std::uint64_t healed_ticks = 0;  // set when healed
  bool healed = false;             // false => permanently (partially) lost
};

struct BufferedPacket {
  std::uint64_t seq = 0;
  std::uint64_t recv_ts_ticks = 0;
  std::uint64_t hw_ts_ticks = 0;
  std::vector<std::uint8_t> bytes;
};

enum class PacketDisposition : std::uint8_t {
  Apply,     // caller applies the packet now
  Buffered,  // held in the reorder window (gap_detected/new_gap may be set)
  Discard,   // duplicate or stale
};

struct PushResult {
  PacketDisposition disposition = PacketDisposition::Discard;
  bool gap_detected = false;  // `new_gap` is valid
  GapRequest new_gap;
};

class GapTracker {
 public:
  // `window` = reorder window size; `timeout_ns` = how long a gap may stay
  // open before missing packets are declared permanently lost.
  explicit GapTracker(std::size_t window = 1024, std::uint64_t timeout_ns = 1000000000ull);
  ~GapTracker();
  GapTracker(const GapTracker&) = delete;
  GapTracker& operator=(const GapTracker&) = delete;

  // Decode-thread hot path. `bytes` is copied only when the packet is
  // buffered; the Apply path stores nothing.
  PushResult push(std::uint64_t seq, std::uint64_t now_ticks, const std::uint8_t* bytes,
                  std::size_t len, std::uint64_t recv_ts_ticks, std::uint64_t hw_ts_ticks) noexcept;

  // Pops the next packet that should be applied (the packet just pushed, or
  // buffered packets that became consecutive). Caller drains this after every
  // push/advance_time/flush.
  bool pop_applicable(BufferedPacket& out) noexcept;

  // Idle path: after the timeout, skips missing ranges and marks them
  // permanently lost.
  void advance_time(std::uint64_t now_ticks) noexcept;

  // Producers are gone: close any open gap (remainder = permanently lost) and
  // release everything left in the window.
  void flush(std::uint64_t now_ticks);

  void note_recovered_packet() noexcept { recovered_.fetch_add(1, std::memory_order_relaxed); }

  std::uint64_t gaps_detected() const noexcept { return gaps_.load(std::memory_order_relaxed); }
  std::uint64_t gaps_healed() const noexcept { return healed_.load(std::memory_order_relaxed); }
  std::uint64_t recovered_packets() const noexcept {
    return recovered_.load(std::memory_order_relaxed);
  }
  std::uint64_t permanently_lost() const noexcept { return lost_.load(std::memory_order_relaxed); }
  std::uint64_t duplicates() const noexcept { return dups_.load(std::memory_order_relaxed); }
  std::uint64_t window_drops() const noexcept { return wdrops_.load(std::memory_order_relaxed); }
  std::uint64_t expected_sequence() const noexcept { return expected_; }
  bool gap_active() const noexcept { return gap_active_; }
  bool settled() const noexcept { return !gap_active_ && buffered_.empty() && ready_.empty(); }
  const std::vector<GapEvent>& events() const noexcept { return events_; }

  // Number of events that are no longer active (final disposition known).
  // Callers that forward events elsewhere track their own cursor and copy
  // events in [cursor, closed_event_count()) — decode-thread only.
  std::size_t closed_event_count() const noexcept {
    return events_.size() - (gap_active_ ? 1u : 0u);
  }

  // Prints time-to-heal percentiles to `out` and writes
  // {dir}/{prefix}-heal.hgrm.
  void write_heal_report(const std::string& dir, const std::string& prefix, FILE* out) const;

 private:
  void pull_buffered() noexcept;
  void maybe_heal(std::uint64_t now_ticks) noexcept;

  std::size_t window_;
  std::uint64_t timeout_ticks_;

  std::uint64_t expected_ = 0;
  bool started_ = false;
  bool gap_active_ = false;
  std::uint64_t gap_end_ = 0;  // highest seq seen during the gap
  std::uint64_t gap_detected_ticks_ = 0;
  std::uint64_t gap_lost_ = 0;  // seqs lost in the CURRENT gap

  std::map<std::uint64_t, BufferedPacket> buffered_;  // reorder window
  std::deque<BufferedPacket> ready_;                  // apply in order

  std::vector<GapEvent> events_;
  struct hdr_histogram* heal_hist_ = nullptr;

  std::atomic<std::uint64_t> gaps_{0};
  std::atomic<std::uint64_t> healed_{0};
  std::atomic<std::uint64_t> recovered_{0};
  std::atomic<std::uint64_t> lost_{0};
  std::atomic<std::uint64_t> dups_{0};
  std::atomic<std::uint64_t> wdrops_{0};
};

}  // namespace wiretap
