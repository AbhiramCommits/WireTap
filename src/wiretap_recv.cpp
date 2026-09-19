// wiretap_recv - receive a MoldUDP64 ITCH feed over UDP multicast, decode it,
// and maintain a limit order book.
//
// Threads:
//   rx     - recvmmsg/recv hot loop (busy-poll or epoll), stamps arrival time,
//            pushes raw datagrams into a lock-free SPSC ring. No decode.
//   decode - pops datagrams, bounds-checked decode, updates the book.
//   main   - 1 Hz stats sampling + clean shutdown (drains the ring).
//
// The receive and decode paths never allocate, lock, or log.

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
#include "receiver.hpp"
#include "thread_util.hpp"
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
               "  --no-book             decode but skip book building\n",
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
    } else if (a == "-h" || a == "--help") {
      usage(argv[0]);
      return false;
    } else {
      std::fprintf(stderr, "wiretap_recv: unknown option '%s'\n", a.c_str());
      usage(argv[0]);
      return false;
    }
  }
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

// Decode thread: pop raw datagrams, decode, apply to the book. Exits when the
// producer is gone and the ring is fully drained.
void decode_loop(wiretap::SpscRing<wiretap::Datagram>& ring,
                 wiretap::BookBuilder* book, wiretap::Decoder& dec,
                 const std::atomic<bool>& rx_running, Counters& c) {
  wiretap::set_current_thread_name("wiretap-dec");
  wiretap::Datagram d;
  std::vector<wiretap::BookUpdate> updates;
  updates.reserve(256);  // no allocation on the decode path after warmup

  auto process = [&](const wiretap::Datagram& dg) {
    c.packets_decoded.fetch_add(1, std::memory_order_relaxed);
    dec.set_recv_ts_ns(dg.recv_ts_ns);
    updates.clear();
    const auto r = dec.decode_packet(dg.bytes.data(), dg.length, updates);
    if (r.error != wiretap::DecodeError::Ok) {
      c.decode_errors.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    c.messages_decoded.fetch_add(r.updates_decoded, std::memory_order_relaxed);
    if (book != nullptr) {
      for (const auto& u : updates) book->apply(u);
    }
  };

  for (;;) {
    if (ring.try_pop(d)) {
      process(d);
      continue;
    }
    // Ring empty. Exit only once the producer is gone; if a stop has been
    // requested but the receiver is still winding down, keep draining.
    if (!rx_running.load(std::memory_order_acquire)) break;
    std::this_thread::yield();
  }
  while (ring.try_pop(d)) process(d);  // final drain after producer exit
}

}  // namespace

int main(int argc, char** argv) {
  Options o;
  if (!parse_args(argc, argv, o)) return 2;

  struct sigaction sa {};
  sa.sa_handler = on_signal;
  ::sigaction(SIGINT, &sa, nullptr);
  ::sigaction(SIGTERM, &sa, nullptr);

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

  std::fprintf(stderr,
               "wiretap_recv: %s:%u iface=%s mode=%s batch=%u ring=%zu "
               "SO_RCVBUF granted=%d\n",
               cfg.group.c_str(), cfg.port,
               cfg.iface.empty() ? "any" : cfg.iface.c_str(),
               o.mode == wiretap::RecvMode::BusyPoll ? "busy" : "epoll",
               o.batch, ring.capacity(), rx.granted_rcvbuf());

  wiretap::Decoder dec;
  std::unique_ptr<wiretap::BookBuilder> book;
  if (o.build_book) book = std::make_unique<wiretap::BookBuilder>();

  Counters c;
  std::atomic<bool> rx_running{true};

  std::thread rx_thread([&] {
    wiretap::set_current_thread_name("wiretap-rx");
    if (o.rx_core >= 0 && !wiretap::pin_cpu(o.rx_core) && !o.sched_fifo) {
      std::fprintf(stderr,
                   "wiretap_recv: warning: receive thread is not pinned; "
                   "busy-polling on an unpinned core can preempt.\n");
    }
    if (o.sched_fifo) wiretap::set_fifo(o.fifo_priority, "rx");
    rx.recv_loop(ring);
    rx_running.store(false, std::memory_order_release);
  });

  std::thread decode_thread([&] {
    if (o.decode_core >= 0) wiretap::pin_cpu(o.decode_core);
    if (o.sched_fifo) wiretap::set_fifo(o.fifo_priority, "decode");
    decode_loop(ring, book.get(), dec, rx_running, c);
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
    const std::uint64_t dec_now = c.packets_decoded.load(std::memory_order_relaxed);
    const std::uint64_t msgs_now =
        c.messages_decoded.load(std::memory_order_relaxed);
    std::fprintf(stderr,
                 "t=%6.1fs | rx %10llu (%8.0f pps) | dec %10llu | msgs %12llu "
                 "(%8.0f mps) | drops %5llu | oversize %4llu | errors %4llu | "
                 "orders %8llu\n",
                 t - t0, static_cast<unsigned long long>(rx_now),
                 static_cast<double>(rx_now - prev_rx) / dt,
                 static_cast<unsigned long long>(dec_now),
                 static_cast<unsigned long long>(msgs_now),
                 static_cast<double>(msgs_now - prev_msgs) / dt,
                 static_cast<unsigned long long>(ring.drops()),
                 static_cast<unsigned long long>(rx.oversize_dropped()),
                 static_cast<unsigned long long>(
                     c.decode_errors.load(std::memory_order_relaxed)),
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

  // Clean shutdown: stop the producer, then let the decoder drain the ring.
  g_stop.store(true, std::memory_order_relaxed);
  rx.request_stop();
  rx_thread.join();
  decode_thread.join();

  const double elapsed = now_s() - t0;
  const std::uint64_t rx_total = rx.packets_received();
  const std::uint64_t dec_total = c.packets_decoded.load(std::memory_order_relaxed);
  const std::uint64_t msgs_total =
      c.messages_decoded.load(std::memory_order_relaxed);
  std::fprintf(stderr,
               "summary: %.2fs | packets rx %llu (%.0f pps) | decoded %llu | "
               "messages %llu | ring drops %llu | oversize %llu | decode "
               "errors %llu\n",
               elapsed, static_cast<unsigned long long>(rx_total),
               elapsed > 0 ? static_cast<double>(rx_total) / elapsed : 0.0,
               static_cast<unsigned long long>(dec_total),
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
  return 0;
}
