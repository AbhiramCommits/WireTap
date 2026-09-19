// Receiver tests: unicast loopback round-trip through the SPSC ring for both
// receive modes, plus oversize-drop accounting and SO_RCVBUF reporting.
// (Multicast group joins are exercised end-to-end manually; loopback is what
// stays deterministic in CI containers.)

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "receiver.hpp"
#include "time_base.hpp"
#include "wiretap/spsc_ring.hpp"

namespace wt = wiretap;

namespace {

constexpr int kNumDatagrams = 100;

void run_loopback_test(wt::RecvMode mode) {
  wt::TimeBase::instance().initialize();
  wt::ReceiverConfig cfg;
  cfg.group = "239.1.1.1";
  cfg.port = 0;           // ephemeral
  cfg.join_group = false; // unicast loopback
  cfg.rcvbuf = 1 << 20;
  cfg.batch = 32;

  wt::Receiver rx(cfg, mode);
  std::string err;
  if (!rx.open_socket(err)) {
#if defined(__linux__)
    FAIL() << "open_socket failed: " << err;
#else
    GTEST_SKIP() << "receiver unavailable on this platform: " << err;
#endif
  }

  // SO_RCVBUF: the kernel must have granted at least what we asked for
  // (Linux typically doubles it; that's why the actual value is reported).
  EXPECT_GE(rx.granted_rcvbuf(), 1 << 20);
  EXPECT_NE(rx.local_port(), 0);

  wt::SpscRing<wt::Datagram> ring(256);
  std::thread rx_thread([&] { rx.recv_loop(ring); });

  // Give the receiver a moment to enter the recv path (datagrams sent before
  // that are buffered by the kernel anyway).
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  const int sfd = ::socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_GE(sfd, 0);
  struct sockaddr_in dst {};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(rx.local_port());
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  std::vector<std::size_t> sizes(kNumDatagrams);
  for (int i = 0; i < kNumDatagrams; ++i) {
    sizes[i] = 8 + (static_cast<std::size_t>(i) * 37) % 1000;
    std::vector<std::uint8_t> payload(sizes[i]);
    payload[0] = static_cast<std::uint8_t>(i >> 24);
    payload[1] = static_cast<std::uint8_t>(i >> 16);
    payload[2] = static_cast<std::uint8_t>(i >> 8);
    payload[3] = static_cast<std::uint8_t>(i);
    for (std::size_t j = 4; j < payload.size(); ++j) {
      payload[j] = static_cast<std::uint8_t>((j * 7 + i * 3) & 0xFF);
    }
    ASSERT_EQ(::sendto(sfd, payload.data(), payload.size(), 0,
                       reinterpret_cast<struct sockaddr*>(&dst), sizeof dst),
              static_cast<ssize_t>(payload.size()));
  }

  // One oversized datagram: must be counted and dropped, never pushed.
  std::vector<std::uint8_t> big(wt::kMaxDatagramBytes + 64, 0xEE);
  ASSERT_EQ(::sendto(sfd, big.data(), big.size(), 0,
                     reinterpret_cast<struct sockaddr*>(&dst), sizeof dst),
            static_cast<ssize_t>(big.size()));

  // Drain the ring, verifying every datagram byte for byte.
  wt::Datagram d;
  std::vector<int> got(kNumDatagrams, 0);
  int total = 0;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (total < kNumDatagrams && std::chrono::steady_clock::now() < deadline) {
    if (!ring.try_pop(d)) {
      std::this_thread::yield();
      continue;
    }
    const int i = (static_cast<int>(d.bytes[0]) << 24) |
                  (static_cast<int>(d.bytes[1]) << 16) |
                  (static_cast<int>(d.bytes[2]) << 8) |
                  static_cast<int>(d.bytes[3]);
    ASSERT_GE(i, 0);
    ASSERT_LT(i, kNumDatagrams) << "corrupted seq byte";
    ASSERT_EQ(got[i], 0) << "duplicate datagram " << i;
    got[i] = 1;
    ++total;
    EXPECT_EQ(d.length, sizes[i]);
    EXPECT_GT(d.recv_ts_ticks, 0u);
    EXPECT_GT(d.hw_ts_ticks, 0u);
    const std::uint64_t recv_ns =
        wt::TimeBase::instance().ticks_to_realtime_ns(d.recv_ts_ticks);
    EXPECT_GT(recv_ns, 1500000000000000000ull);  // sane wall-clock value
    for (std::size_t j = 4; j < sizes[i]; ++j) {
      EXPECT_EQ(d.bytes[j], static_cast<std::uint8_t>((j * 7 + i * 3) & 0xFF))
          << "datagram " << i << " byte " << j;
    }
  }

  rx.request_stop();
  rx_thread.join();
  ::close(sfd);

  EXPECT_EQ(total, kNumDatagrams);
  EXPECT_EQ(rx.packets_received(),
            static_cast<std::uint64_t>(kNumDatagrams) + 1);
  EXPECT_EQ(rx.oversize_dropped(), 1u);
  EXPECT_EQ(ring.drops(), 0u);
  EXPECT_TRUE(rx.last_error().empty());
#if defined(__linux__)
  // On Linux the SO_TIMESTAMPING mechanism is enabled, and loopback traffic
  // receives kernel software timestamps for every datagram.
  EXPECT_EQ(rx.timestamp_mechanism(), wt::TimestampMechanism::SofTimestamping);
  EXPECT_EQ(rx.hw_stamped() + rx.sw_stamped(),
            static_cast<std::uint64_t>(kNumDatagrams) + 1);
#else
  // Elsewhere SO_TIMESTAMPNS (kernel software) is requested; if the platform
  // kernel delivers them the counters reflect it, otherwise the userspace
  // fallback keeps hw_ts == recv_ts.
  EXPECT_LE(rx.hw_stamped() + rx.sw_stamped(),
            static_cast<std::uint64_t>(kNumDatagrams) + 1);
#endif
}

}  // namespace

TEST(Receiver, BusyPollLoopbackRoundTrip) { run_loopback_test(wt::RecvMode::BusyPoll); }

TEST(Receiver, EpollLoopbackRoundTrip) { run_loopback_test(wt::RecvMode::Epoll); }

TEST(Receiver, OpenFailureReportsError) {
  wt::ReceiverConfig cfg;
  cfg.iface = "definitely-not-a-real-interface";
  cfg.group = "not-an-ip";
  wt::Receiver rx(cfg, wt::RecvMode::BusyPoll);
  std::string err;
  EXPECT_FALSE(rx.open_socket(err));
  EXPECT_FALSE(err.empty());
}
