// wiretap/recovery_client.hpp - TCP retransmission client for gap recovery.
//
// Runs in its own thread (cold path): pops GapRequests from a lock-free ring,
// fetches the missing sequence range from a retransmission server (see
// tools/retransmit_server.py), and pushes the recovered packets into a second
// lock-free ring that the decode thread drains through the same gap tracker.
//
// Protocol: "GET <start> <end>\n" -> raw MoldUDP64 packets back to back,
// server closes (EOF). "ERROR <msg>\n" -> the range is unavailable.

#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include "gap_tracker.hpp"
#include "receiver.hpp"
#include "wiretap/spsc_ring.hpp"

namespace wiretap {

class RecoveryClient {
 public:
  RecoveryClient(std::string host, std::uint16_t port) : host_(std::move(host)), port_(port) {}

  // Blocks until `stop` is set; drains already-queued requests before
  // returning.
  void run(SpscRing<GapRequest>& requests, SpscRing<Datagram>& recovered,
           const std::atomic<bool>& stop);

  std::uint64_t requests_served() const noexcept {
    return requests_.load(std::memory_order_relaxed);
  }
  std::uint64_t packets_fetched() const noexcept {
    return fetched_.load(std::memory_order_relaxed);
  }
  std::uint64_t errors() const noexcept { return errors_.load(std::memory_order_relaxed); }

 private:
  bool fetch_range(std::uint64_t start, std::uint64_t end, SpscRing<Datagram>& recovered);

  std::string host_;
  std::uint16_t port_;
  std::atomic<std::uint64_t> requests_{0};
  std::atomic<std::uint64_t> fetched_{0};
  std::atomic<std::uint64_t> errors_{0};
};

}  // namespace wiretap
