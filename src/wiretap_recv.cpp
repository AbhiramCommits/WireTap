// wiretap_recv - receive a MoldUDP64 ITCH feed over UDP multicast, decode it,
// maintain a limit order book, measure end-to-end latency, and heal sequence
// gaps via a TCP retransmission server.
//
// Threads:
//   rx       - recvmmsg/recvmsg hot loop (busy-poll or epoll), kernel/hw
//              timestamping, records wire_to_userspace, pushes raw datagrams
//              into a lock-free SPSC ring. No decode.
//   decode   - pops datagrams, bounds-checked decode, gap tracking + reorder
//              window, updates the book, records queue/decode/wire_to_book.
//   recovery - (optional) drains GapRequests and fetches missing ranges from
//              a retransmission server over TCP.
//   main     - 1 Hz stats sampling + clean shutdown (drains everything).
//
// The receive and decode paths never allocate (beyond gap-path buffering),
// lock, or log.

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "book_builder.hpp"
#include "decoder.hpp"
#include "gap_tracker.hpp"
#include "latency.hpp"
#include "receiver.hpp"
#include "recovery_client.hpp"
#include "thread_util.hpp"
#include "time_base.hpp"
#include "wiretap/itch.hpp"
#include "wiretap/spsc_ring.hpp"

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop.store(true, std::memory_order_relaxed); }

struct Options {
  std::string group = "239.1.1.1";
  std::uint16_t port = 31337;
  std::string iface;
  wiretap::RecvMode mode = wiretap::RecvMode::BusyPoll;
  std::uint32_t batch = 32;
  std::size_t ring_size = 8192;
  int rcvbuf = 0;
  int rx_core = -1;
  int decode_core = -1;
  bool sched_fifo = false;
  int fifo_priority = 50;
  double duration = 0.0;  // 0 = until SIGINT
  bool build_book = true;
  std::string recover_addr;     // "host:port" for gap recovery
  std::size_t reorder_window = 1024;
  std::uint64_t recover_timeout_ms = 1000;
  std::string latency_dir = ".";
  std::string latency_prefix = "wiretap";
};

void usage(const char* argv0) {
  std::fprintf(stderr,
               "usage: %s [options]\n"
               "  --group IP            multicast group (default 239.1.1.1)\n"
               "  --port PORT           UDP port (default 31337)\n"
               "  --iface NAME          multicast interface (default: any)\n"
               "  --mode busy|epoll     receive mode (default busy)\n"
               "  --batch N             recvmmsg batch size (default 32)\n"
               "  --ring-size N         SPSC ring slots, power of two (default 8192)\n"
               "  --rcvbuf BYTES        requested SO_RCVBUF (default 0 = kernel default)\n"
               "  --rx-core N           pin receive thread to CPU N (-1 = inherit)\n"
               "  --decode-core N       pin decode thread to CPU N (-1 = inherit)\n"
               "  --sched-fifo          try SCHED_FIFO (needs CAP_SYS_NICE)\n"
               "  --fifo-priority N     SCHED_FIFO priority (default 50)\n"
               "  --duration SEC        stop after N seconds (default: until SIGINT)\n"
               "  --no-book             decode but skip book building\n"
               "  --recover HOST:PORT   enable gap recovery via TCP retransmission server\n"
               "  --reorder-window N    out-of-order packet buffer (default 1024)\n"
               "  --recover-timeout-ms N  declare a gap permanently lost after N ms (default 1000)\n"
               "  --latency-dir DIR     write .hgrm histograms + JSON summary here (default .)\n"
               "  --latency-prefix STR  report file prefix (default wiretap)\n",
               argv0);
}

bool parse_args(int argc, char** argv, Options& o) {
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&](const char* what) -> const char* {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "wiretap_recv: missing value for %s\n", what);
        return nullptr;
      }
      return argv[++i];
    };
    if (a == "--group") {
      const char* v = next("--group");
      if (!v) return false;
      o.group = v;
    } else if (a == "--port") {
      const char* v = next("--port");
      if (!v) return false;
      o.port = static_cast<std::uint16_t>(std::atoi(v));
    } else if (a == "--iface") {
      const char* v = next("--iface");
      if (!v) return false;
      o.iface = v;
    } else if (a == "--mode") {
      const char* v = next("--mode");
      if (!v) return false;
      if (std::strcmp(v, "busy") == 0) {
        o.mode = wiretap::RecvMode::BusyPoll;
      } else if (std::strcmp(v, "epoll") == 0) {
        o.mode = wiretap::RecvMode::Epoll;
      } else {
        std::fprintf(stderr, "wiretap_recv: --mode must be 'busy' or 'epoll'\n");
        return false;
      }
    } else if (a == "--batch") {
      const char* v = next("--batch");
      if (!v) return false;
      o.batch = static_cast<std::uint32_t>(std::atoi(v));
    } else if (a == "--ring-size") {
      const char* v = next("--ring-size");
      if (!v) return false;
      o.ring_size = static_cast<std::size_t>(std::strtoull(v, nullptr, 10));
    } else if (a == "--rcvbuf") {
      const char* v = next("--rcvbuf");
      if (!v) return false;
      o.rcvbuf = std::atoi(v);
    } else if (a == "--rx-core") {
      const char* v = next("--rx-core");
      if (!v) return false;
      o.rx_core = std::atoi(v);
    } else if (a == "--decode-core") {
      const char* v = next("--decode-core");
      if (!v) return false;
      o.decode_core = std::atoi(v);
    } else if (a == "--sched-fifo") {
      o.sched_fifo = true;
    } else if (a == "--fifo-priority") {
      const char* v = next("--fifo-priority");
      if (!v) return false;
      o.fifo_priority = std::atoi(v);
    } else if (a == "--duration") {
      const char* v = next("--duration");
      if (!v) return false;
      o.duration = std::atof(v);
    } else if (a == "--no-book") {
      o.build_book = false;
    } else if (a == "--recover") {
      const char* v = next("--recover");
      if (!v) return false;
      o.recover_addr = v;
    } else if (a == "--reorder-window") {
      const char* v = next("--reorder-window");
      if (!v) return false;
      o.reorder_window = static_cast<std::size_t>(std::strtoull(v, nullptr, 10));
    } else if (a == "--recover-timeout-ms") {
      const char* v = next("--recover-timeout-ms");
      if (!v) return false;
      o.recover_timeout_ms = std::strtoull(v, nullptr, 10);
    } else if (a == "--latency-dir") {
      const char* v = next("--latency-dir");
      if (!v) return false;
      o.latency_dir = v;
    } else if (a == "--latency-prefix") {
      const char* v = next("--latency-prefix");
      if (!v) return false;
      o.latency_prefix = v;
    } else if (a == "-h" || a == "--help") {
      usage(argv[0]);
      return false;
    } else {
      std::fprintf(stderr, "wiretap_recv: unknown option '%s'\n", a.c_str());
      usage(argv[0]);
      return false;
    }
  }
  if (o.reorder_window == 0) o.reorder_window = 1;
  return true;
}

inline double now_s() noexcept {
  struct timespec ts {};
  ::clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) * 1e-9;
}

struct Counters {
  std::atomic<std::uint64_t> packets_decoded{0};
  std::atomic<std::uint64_t> messages_decoded{0};
  std::atomic<std::uint64_t> decode_errors{0};
};

// Decode thread: pop raw datagrams (live ring + recovered ring), track
// sequence numbers, apply to the book in order, record latency stages.
// Exits when the producers are gone, the recovered ring is drained, and the
// tracker is flushed.
void decode_loop(wiretap::SpscRing<wiretap::Datagram>& main_ring,
                 wiretap::SpscRing<wiretap::Datagram>& recovered_ring,
                 wiretap::SpscRing<wiretap::GapRequest>& gap_ring,
                 bool recovery_enabled, wiretap::GapTracker& tracker,
                 wiretap::BookBuilder* book, wiretap::Decoder& dec,
                 wiretap::LatencyRecorder& lat,
                 const std::atomic<bool>& rx_running,
                 const std::atomic<bool>& recovery_done, Counters& c) {
  wiretap::set_current_thread_name("wiretap-dec");
  wiretap::TimeBase& tb = wiretap::TimeBase::instance();
  wiretap::Datagram d;
  std::vector<wiretap::BookUpdate> updates;
  updates.reserve(256);  // no allocation on the decode path after warmup

  auto apply_packet = [&](const std::uint8_t* p, std::size_t n,
                          std::uint64_t recv_ticks, std::uint64_t hw_ticks) {
    c.packets_decoded.fetch_add(1, std::memory_order_relaxed);
    const std::uint64_t t0 = tb.now_ticks();
    dec.set_recv_ts_ns(tb.ticks_to_realtime_ns(recv_ticks));
    updates.clear();
    const auto r = dec.decode_packet(p, n, updates);
    const std::uint64_t t1 = tb.now_ticks();
    if (r.error != wiretap::DecodeError::Ok) {
      c.decode_errors.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    c.messages_decoded.fetch_add(r.updates_decoded, std::memory_order_relaxed);
    if (book != nullptr) {
      for (const auto& u : updates) book->apply(u);
    }
    const std::uint64_t t2 = tb.now_ticks();
    lat.record(wiretap::LatencyStage::QueueDelay, tb.delta_ns(t0, recv_ticks));
    lat.record(wiretap::LatencyStage::DecodeTime, tb.delta_ns(t1, t0));
    lat.record(wiretap::LatencyStage::WireToBook, tb.delta_ns(t2, hw_ticks));
  };

  auto drain_ready = [&] {
    wiretap::BufferedPacket p;
    while (tracker.pop_applicable(p)) {
      apply_packet(p.bytes.data(), p.bytes.size(), p.recv_ts_ticks, p.hw_ts_ticks);
    }
  };

  auto process_datagram = [&](const wiretap::Datagram& dg, bool recovered) {
    if (recovered) tracker.note_recovered_packet();
    const std::uint64_t seq =
        wiretap::itch::be64(dg.bytes.data() + wiretap::itch::kSessionLength);
    const auto res = tracker.push(seq, tb.now_ticks(), dg.bytes.data(), dg.length,
                                  dg.recv_ts_ticks, dg.hw_ts_ticks);
    if (res.disposition == wiretap::PacketDisposition::Apply) {
      apply_packet(dg.bytes.data(), dg.length, dg.recv_ts_ticks, dg.hw_ts_ticks);
    } else if (res.disposition == wiretap::PacketDisposition::Buffered &&
               res.gap_detected) {
      if (recovery_enabled) gap_ring.try_push(res.new_gap);
    }
    drain_ready();
  };

  for (;;) {
    if (main_ring.try_pop(d)) {
      process_datagram(d, /*recovered=*/false);
      continue;
    }
    if (recovered_ring.try_pop(d)) {
      process_datagram(d, /*recovered=*/true);
      continue;
    }
    tracker.advance_time(tb.now_ticks());  // idle only: timeout skips
    drain_ready();
    if (!rx_running.load(std::memory_order_acquire) &&
        recovery_done.load(std::memory_order_acquire)) {
      while (recovered_ring.try_pop(d)) process_datagram(d, true);
      tracker.flush(tb.now_ticks());
      drain_ready();
      break;
    }
    std::this_thread::yield();
  }
}

}  // namespace

int main(int argc, char** argv) {
  Options o;
  if (!parse_args(argc, argv, o)) return 2;

  struct sigaction sa {};
  sa.sa_handler = on_signal;
  ::sigaction(SIGINT, &sa, nullptr);
  ::sigaction(SIGTERM, &sa, nullptr);

  wiretap::TimeBase::instance().initialize();

  wiretap::SpscRing<wiretap::Datagram> ring(o.ring_size);

  wiretap::ReceiverConfig cfg;
  cfg.group = o.group;
  cfg.port = o.port;
  cfg.iface = o.iface;
  cfg.rcvbuf = o.rcvbuf;
  cfg.batch = o.batch;
  wiretap::Receiver rx(cfg, o.mode);
  std::string err;
  if (!rx.open_socket(err)) {
    std::fprintf(stderr, "wiretap_recv: %s\n", err.c_str());
    return 1;
  }

  // Recovery endpoint parsing.
  std::string recv_host;
  std::uint16_t recv_port = 0;
  if (!o.recover_addr.empty()) {
    const std::size_t colon = o.recover_addr.rfind(':');
    if (colon == std::string::npos) {
      std::fprintf(stderr, "wiretap_recv: --recover must be HOST:PORT\n");
      return 2;
    }
    recv_host = o.recover_addr.substr(0, colon);
    recv_port = static_cast<std::uint16_t>(
        std::strtoul(o.recover_addr.c_str() + colon + 1, nullptr, 10));
  }
  const bool recovery_enabled = !o.recover_addr.empty();

  std::fprintf(stderr,
               "wiretap_recv: %s:%u iface=%s mode=%s batch=%u ring=%zu "
               "SO_RCVBUF granted=%d\n",
               cfg.group.c_str(), cfg.port,
               cfg.iface.empty() ? "any" : cfg.iface.c_str(),
               o.mode == wiretap::RecvMode::BusyPoll ? "busy" : "epoll",
               o.batch, ring.capacity(), rx.granted_rcvbuf());
  std::fprintf(stderr, "wiretap_recv: timestamping: %s\n",
               wiretap::timestamp_mechanism_name(rx.timestamp_mechanism()));
  if (recovery_enabled) {
    std::fprintf(stderr,
                 "wiretap_recv: gap recovery: %s:%u window=%llu timeout=%llums\n",
                 recv_host.c_str(), recv_port,
                 static_cast<unsigned long long>(o.reorder_window),
                 static_cast<unsigned long long>(o.recover_timeout_ms));
  }

  wiretap::Decoder dec;
  std::unique_ptr<wiretap::BookBuilder> book;
  if (o.build_book) book = std::make_unique<wiretap::BookBuilder>();

  wiretap::GapTracker tracker(o.reorder_window, o.recover_timeout_ms * 1000000ull);
  wiretap::SpscRing<wiretap::GapRequest> gap_ring(64);
  wiretap::SpscRing<wiretap::Datagram> recovered_ring(4096);
  wiretap::LatencyRecorder rx_lat;   // receiver thread records wire_to_userspace
  wiretap::LatencyRecorder dec_lat;  // decode thread records the rest

  Counters c;
  std::atomic<bool> rx_running{true};
  std::atomic<bool> recovery_done{true};  // true when recovery is disabled
  std::atomic<bool> recovery_stop{false};
  std::unique_ptr<wiretap::RecoveryClient> recovery;
  if (recovery_enabled) {
    recovery = std::make_unique<wiretap::RecoveryClient>(recv_host, recv_port);
    recovery_done.store(false, std::memory_order_relaxed);
  }

  std::thread rx_thread([&] {
    wiretap::set_current_thread_name("wiretap-rx");
    if (o.rx_core >= 0 && !wiretap::pin_cpu(o.rx_core) && !o.sched_fifo) {
      std::fprintf(stderr,
                   "wiretap_recv: warning: receive thread is not pinned; "
                   "busy-polling on an unpinned core can preempt.\n");
    }
    if (o.sched_fifo) wiretap::set_fifo(o.fifo_priority, "rx");
    rx.recv_loop(ring, &rx_lat);
    rx_running.store(false, std::memory_order_release);
  });

  std::thread recovery_thread;
  if (recovery_enabled) {
    recovery_thread = std::thread([&] {
      wiretap::set_current_thread_name("wiretap-recover");
      recovery->run(gap_ring, recovered_ring, recovery_stop);
      recovery_done.store(true, std::memory_order_release);
    });
  }

  std::thread decode_thread([&] {
    if (o.decode_core >= 0) wiretap::pin_cpu(o.decode_core);
    if (o.sched_fifo) wiretap::set_fifo(o.fifo_priority, "decode");
    decode_loop(ring, recovered_ring, gap_ring, recovery_enabled, tracker,
                book.get(), dec, dec_lat, rx_running, recovery_done, c);
  });

  std::uint64_t prev_rx = 0, prev_msgs = 0;
  const double t0 = now_s();
  double last_report = t0;

  while (!g_stop.load(std::memory_order_relaxed)) {
    const double elapsed = now_s() - t0;
    if (o.duration > 0 && elapsed >= o.duration) break;
    for (int i = 0; i < 10 && !g_stop.load(std::memory_order_relaxed); ++i) {
      struct timespec nap {0, 100 * 1000 * 1000};  // 100 ms slices
      ::nanosleep(&nap, nullptr);
    }
    const double t = now_s();
    const double dt = t - last_report;
    last_report = t;

    const std::uint64_t rx_now = rx.packets_received();
    const std::uint64_t msgs_now =
        c.messages_decoded.load(std::memory_order_relaxed);
    std::fprintf(stderr,
                 "t=%6.1fs | rx %10llu (%8.0f pps) | msgs %12llu (%8.0f mps) | "
                 "drops %5llu | gaps %4llu (healed %4llu, lost %5llu) | "
                 "orders %8llu\n",
                 t - t0, static_cast<unsigned long long>(rx_now),
                 static_cast<double>(rx_now - prev_rx) / dt,
                 static_cast<unsigned long long>(msgs_now),
                 static_cast<double>(msgs_now - prev_msgs) / dt,
                 static_cast<unsigned long long>(ring.drops()),
                 static_cast<unsigned long long>(tracker.gaps_detected()),
                 static_cast<unsigned long long>(tracker.gaps_healed()),
                 static_cast<unsigned long long>(tracker.permanently_lost()),
                 static_cast<unsigned long long>(
                     book ? book->order_count() : 0));
    prev_rx = rx_now;
    prev_msgs = msgs_now;

    if (!rx_running.load(std::memory_order_acquire)) {
      std::fprintf(stderr, "wiretap_recv: receiver exited: %s\n",
                   rx.last_error().c_str());
      g_stop.store(true, std::memory_order_relaxed);
    }
  }

  // Clean shutdown: stop the producer, stop recovery, let the decoder drain
  // the rings and flush the reorder window.
  g_stop.store(true, std::memory_order_relaxed);
  rx.request_stop();
  rx_thread.join();
  if (recovery_thread.joinable()) {
    recovery_stop.store(true, std::memory_order_relaxed);
    recovery_thread.join();
  }
  decode_thread.join();

  const double elapsed = now_s() - t0;
  const std::uint64_t rx_total = rx.packets_received();
  const std::uint64_t msgs_total =
      c.messages_decoded.load(std::memory_order_relaxed);
  std::fprintf(stderr,
               "summary: %.2fs | packets rx %llu (%.0f pps) | messages %llu | "
               "ring drops %llu | oversize %llu | decode errors %llu\n",
               elapsed, static_cast<unsigned long long>(rx_total),
               elapsed > 0 ? static_cast<double>(rx_total) / elapsed : 0.0,
               static_cast<unsigned long long>(msgs_total),
               static_cast<unsigned long long>(ring.drops()),
               static_cast<unsigned long long>(rx.oversize_dropped()),
               static_cast<unsigned long long>(
                   c.decode_errors.load(std::memory_order_relaxed)));
  if (book) {
    std::fprintf(stderr,
                 "book: symbols %llu | open orders %llu | unknown refs %llu\n",
                 static_cast<unsigned long long>(book->symbol_count()),
                 static_cast<unsigned long long>(book->order_count()),
                 static_cast<unsigned long long>(book->unknown_ref_events()));
  }
  std::fprintf(stderr,
               "timestamps: hw=%llu sw=%llu userspace=%llu\n",
               static_cast<unsigned long long>(rx.hw_stamped()),
               static_cast<unsigned long long>(rx.sw_stamped()),
               static_cast<unsigned long long>(
                   rx.packets_received() - rx.hw_stamped() - rx.sw_stamped()));
  std::fprintf(stderr,
               "gaps: detected %llu | healed %llu | permanently lost %llu | "
               "recovered packets %llu | duplicates %llu | window drops %llu\n",
               static_cast<unsigned long long>(tracker.gaps_detected()),
               static_cast<unsigned long long>(tracker.gaps_healed()),
               static_cast<unsigned long long>(tracker.permanently_lost()),
               static_cast<unsigned long long>(tracker.recovered_packets()),
               static_cast<unsigned long long>(tracker.duplicates()),
               static_cast<unsigned long long>(tracker.window_drops()));
  if (recovery) {
    std::fprintf(stderr,
                 "recovery: requests %llu | fetched %llu packets | errors %llu\n",
                 static_cast<unsigned long long>(recovery->requests_served()),
                 static_cast<unsigned long long>(recovery->packets_fetched()),
                 static_cast<unsigned long long>(recovery->errors()));
  }

  // Latency: merge per-thread histograms only now, at report time.
  wiretap::LatencyRecorder report;
  report.merge(rx_lat);
  report.merge(dec_lat);
  report.write_report(o.latency_dir, o.latency_prefix, stderr);
  tracker.write_heal_report(o.latency_dir, o.latency_prefix, stderr);
  return 0;
}
