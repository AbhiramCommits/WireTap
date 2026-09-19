// wiretap/receiver.hpp - UDP multicast receive path.
//
// The receiver does NOT decode: it stamps datagram arrival time and pushes raw
// datagrams into an SpscRing for a separate decode thread. No allocation, no
// locking and no logging happens on the receive hot path (all buffers and
// msghdr arrays are preallocated in open_socket()).

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "wiretap/spsc_ring.hpp"

#include <sys/socket.h>  // struct msghdr, struct iovec, struct mmsghdr (Linux)
#include <sys/uio.h>

namespace wiretap {

// Maximum datagram payload we can hold in one ring slot. Datagrams larger
// than this are counted and dropped (oversize_dropped()).
inline constexpr std::size_t kMaxDatagramBytes = 8192;

// One raw datagram with its arrival timestamp. Fixed size so ring slots are
// uniform; alignas(64) keeps slots cache-line friendly.
struct alignas(64) Datagram {
  std::uint64_t recv_ts_ns = 0;  // CLOCK_REALTIME arrival stamp
  std::uint32_t length = 0;      // valid bytes in `bytes`
  std::array<std::uint8_t, kMaxDatagramBytes> bytes{};
};

enum class RecvMode {
  BusyPoll,  // recvmmsg(MSG_DONTWAIT) in a tight loop (pin a core!)
  Epoll,     // edge-triggered epoll_wait + recvmmsg drain (Linux only)
};

struct ReceiverConfig {
  std::string group = "239.1.1.1";
  std::uint16_t port = 31337;
  std::string iface;      // multicast interface name; "" = any
  bool join_group = true; // false for unicast/loopback testing
  int rcvbuf = 0;         // requested SO_RCVBUF; 0 = kernel default
  std::uint32_t batch = 32;  // recvmmsg batch size
};

class Receiver {
 public:
  Receiver(const ReceiverConfig& cfg, RecvMode mode) : cfg_(cfg), mode_(mode) {}
  ~Receiver();

  Receiver(const Receiver&) = delete;
  Receiver& operator=(const Receiver&) = delete;

  // Creates the socket, binds, joins the group, preallocates batch buffers.
  // On failure returns false and fills `err`.
  bool open_socket(std::string& err);

  int fd() const noexcept { return fd_; }
  int granted_rcvbuf() const noexcept { return granted_rcvbuf_; }
  std::uint16_t local_port() const noexcept { return local_port_; }
  const std::string& last_error() const noexcept { return last_error_; }

  // Blocks until request_stop(). Pushes stamped datagrams into `ring`;
  // try_push failures are counted inside the ring's drop counter. Returns
  // early on a fatal socket error (see last_error()).
  void recv_loop(SpscRing<Datagram>& ring);

  void request_stop() noexcept { stop_.store(true, std::memory_order_relaxed); }

  std::uint64_t packets_received() const noexcept {
    return packets_.load(std::memory_order_relaxed);
  }
  std::uint64_t bytes_received() const noexcept {
    return bytes_.load(std::memory_order_relaxed);
  }
  std::uint64_t oversize_dropped() const noexcept {
    return oversize_.load(std::memory_order_relaxed);
  }

 private:
  // Reads up to `batch` datagrams (one recvmmsg call on Linux, a recv loop
  // elsewhere) and pushes them into the ring. Returns false on EAGAIN (nothing
  // left to drain) or a fatal error.
  bool drain_once(SpscRing<Datagram>& ring) noexcept;
  void fail(std::string msg) { last_error_ = std::move(msg); }

  ReceiverConfig cfg_;
  RecvMode mode_;
  int fd_ = -1;
  int epfd_ = -1;
  int granted_rcvbuf_ = 0;
  std::uint16_t local_port_ = 0;
  std::atomic<bool> stop_{false};
  std::atomic<std::uint64_t> packets_{0};
  std::atomic<std::uint64_t> bytes_{0};
  std::atomic<std::uint64_t> oversize_{0};
  std::string last_error_;

#if defined(__linux__)
  std::vector<mmsghdr> msgs_;        // preallocated batch headers
  std::vector<iovec> iovs_;          // one iovec per batch slot
  std::unique_ptr<std::uint8_t[]> batch_buf_;
#else
  std::unique_ptr<std::uint8_t[]> buf_;
  struct iovec iov_ {};
  struct msghdr msg_ {};
#endif
};

}  // namespace wiretap
