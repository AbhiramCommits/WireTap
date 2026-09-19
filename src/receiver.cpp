#include "receiver.hpp"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // recvmmsg, if_nametoindex
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>

#if defined(__linux__)
#include <net/if.h>     // if_nametoindex
#include <sys/epoll.h>
#else
#include <sys/ioctl.h>  // SIOCGIFADDR
#endif

namespace wiretap {

namespace {

#if defined(__linux__)
constexpr int kEpollTimeoutMs = 200;
#endif
constexpr int kMaxDrainRounds = 1024;  // fairness cap per epoll wakeup

inline std::uint64_t realtime_ns() noexcept {
  struct timespec ts {};
  ::clock_gettime(CLOCK_REALTIME, &ts);
  return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull +
         static_cast<std::uint64_t>(ts.tv_nsec);
}

#if !defined(__linux__)
// Resolve an interface name to its IPv4 address (for IP_ADD_MEMBERSHIP on
// platforms without ip_mreqn). ioctl number differs between OSes; try both.
std::string iface_ipv4(const std::string& name) {
  struct ifreq ifr {};
  std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return {};
  bool ok = false;
  for (unsigned long req : {0x8915UL, 0xC0206921UL}) {  // SIOCGIFADDR
    if (::ioctl(fd, req, &ifr) == 0) {
      ok = true;
      break;
    }
  }
  ::close(fd);
  if (!ok) return {};
  return inet_ntoa(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr);
}
#endif

}  // namespace

Receiver::~Receiver() {
  if (epfd_ >= 0) ::close(epfd_);
  if (fd_ >= 0) ::close(fd_);
}

bool Receiver::open_socket(std::string& err) {
  err.clear();
#if !defined(__linux__)
  if (mode_ == RecvMode::Epoll) {
    err = "epoll mode is only supported on Linux; use --mode busy";
    return false;
  }
#endif

  fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd_ < 0) {
    err = std::string("socket: ") + std::strerror(errno);
    return false;
  }

  int yes = 1;
  ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

  struct sockaddr_in bind_addr {};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(cfg_.port);
  bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&bind_addr),
             sizeof bind_addr) != 0) {
    err = std::string("bind: ") + std::strerror(errno);
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  socklen_t alen = sizeof bind_addr;
  ::getsockname(fd_, reinterpret_cast<struct sockaddr*>(&bind_addr), &alen);
  local_port_ = ntohs(bind_addr.sin_port);

  if (cfg_.join_group) {
    struct in_addr mcast {};
    if (::inet_aton(cfg_.group.c_str(), &mcast) == 0) {
      err = "invalid multicast group address '" + cfg_.group + "'";
      ::close(fd_);
      fd_ = -1;
      return false;
    }
#if defined(__linux__)
    struct ip_mreqn mreq {};
    mreq.imr_multiaddr = mcast;
    if (!cfg_.iface.empty()) {
      mreq.imr_ifindex = static_cast<int>(::if_nametoindex(cfg_.iface.c_str()));
      if (mreq.imr_ifindex == 0) {
        err = "unknown interface '" + cfg_.iface + "'";
        ::close(fd_);
        fd_ = -1;
        return false;
      }
    } else {
      mreq.imr_address.s_addr = htonl(INADDR_ANY);
    }
    if (::setsockopt(fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof mreq) !=
        0) {
      err = std::string("IP_ADD_MEMBERSHIP: ") + std::strerror(errno);
      ::close(fd_);
      fd_ = -1;
      return false;
    }
#else
    struct ip_mreq mreq {};
    mreq.imr_multiaddr = mcast;
    if (cfg_.iface.empty()) {
      mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    } else {
      const std::string addr = iface_ipv4(cfg_.iface);
      if (addr.empty() ||
          ::inet_aton(addr.c_str(), &mreq.imr_interface) == 0) {
        err = "cannot resolve interface '" + cfg_.iface + "'";
        ::close(fd_);
        fd_ = -1;
        return false;
      }
    }
    if (::setsockopt(fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof mreq) !=
        0) {
      err = std::string("IP_ADD_MEMBERSHIP: ") + std::strerror(errno);
      ::close(fd_);
      fd_ = -1;
      return false;
    }
#endif
  }

  if (cfg_.rcvbuf > 0) {
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &cfg_.rcvbuf,
                 sizeof cfg_.rcvbuf);
  }
  socklen_t sz = sizeof granted_rcvbuf_;
  ::getsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &granted_rcvbuf_, &sz);

  const int flags = ::fcntl(fd_, F_GETFL, 0);
  ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

#if defined(__linux__)
  if (mode_ == RecvMode::Epoll) {
    epfd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epfd_ < 0) {
      err = std::string("epoll_create1: ") + std::strerror(errno);
      ::close(fd_);
      fd_ = -1;
      return false;
    }
    struct epoll_event ev {};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd_;
    if (::epoll_ctl(epfd_, EPOLL_CTL_ADD, fd_, &ev) != 0) {
      err = std::string("epoll_ctl: ") + std::strerror(errno);
      ::close(fd_);
      fd_ = -1;
      return false;
    }
  }

  const std::size_t n = cfg_.batch ? cfg_.batch : 1;
  msgs_.resize(n);
  iovs_.resize(n);
  batch_buf_.reset(new std::uint8_t[n * kMaxDatagramBytes]);
  for (std::size_t i = 0; i < n; ++i) {
    iovs_[i].iov_base = batch_buf_.get() + i * kMaxDatagramBytes;
    iovs_[i].iov_len = kMaxDatagramBytes;
    std::memset(&msgs_[i], 0, sizeof msgs_[i]);
    msgs_[i].msg_hdr.msg_iov = &iovs_[i];
    msgs_[i].msg_hdr.msg_iovlen = 1;
  }
#else
  buf_.reset(new std::uint8_t[kMaxDatagramBytes]);
  iov_.iov_base = buf_.get();
  iov_.iov_len = kMaxDatagramBytes;
  std::memset(&msg_, 0, sizeof msg_);
  msg_.msg_iov = &iov_;
  msg_.msg_iovlen = 1;
#endif

  return true;
}

bool Receiver::drain_once(SpscRing<Datagram>& ring) noexcept {
  const std::uint64_t ts = realtime_ns();

#if defined(__linux__)
  const int n = ::recvmmsg(fd_, msgs_.data(),
                           static_cast<unsigned int>(msgs_.size()),
                           MSG_DONTWAIT, nullptr);
  if (n < 0) {
    const int e = errno;
    if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR || e == ECONNREFUSED) {
      return false;  // drained (ICMP unreachable on UDP surfaces as ECONNREFUSED)
    }
    fail(std::string("recvmmsg: ") + std::strerror(e));
    return false;
  }
  if (n == 0) return false;

  packets_.fetch_add(static_cast<std::uint64_t>(n), std::memory_order_relaxed);
  for (int i = 0; i < n; ++i) {
    const std::size_t len = msgs_[i].msg_len;
    bytes_.fetch_add(len, std::memory_order_relaxed);
    if (len > kMaxDatagramBytes) {
      oversize_.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    Datagram d;
    d.recv_ts_ns = ts;  // one stamp per batch: all datagrams arrive together
    d.length = static_cast<std::uint32_t>(len);
    std::memcpy(d.bytes.data(), iovs_[i].iov_base, len);
    ring.try_push(d);
  }
  return true;
#else
  // Fallback for platforms without recvmmsg: recvmsg() up to `batch` times.
  // Truncation is detected via MSG_TRUNC in msg_flags (recv() with MSG_TRUNC
  // does not report the real length on all platforms).
  std::uint8_t* buf = buf_.get();
  bool any = false;
  const std::uint32_t max = cfg_.batch ? cfg_.batch : 1;
  for (std::uint32_t i = 0; i < max; ++i) {
    const ssize_t r = ::recvmsg(fd_, &msg_, MSG_DONTWAIT);
    if (r < 0) {
      const int e = errno;
      if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR || e == ECONNREFUSED) {
        break;
      }
      fail(std::string("recvmsg: ") + std::strerror(e));
      return any;
    }
    if (r == 0) break;
    packets_.fetch_add(1, std::memory_order_relaxed);
    bytes_.fetch_add(static_cast<std::uint64_t>(r), std::memory_order_relaxed);
    if ((msg_.msg_flags & MSG_TRUNC) != 0 ||
        static_cast<std::size_t>(r) > kMaxDatagramBytes) {
      oversize_.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    Datagram d;
    d.recv_ts_ns = ts;
    d.length = static_cast<std::uint32_t>(r);
    std::memcpy(d.bytes.data(), buf, static_cast<std::size_t>(r));
    ring.try_push(d);
    any = true;
  }
  return any;
#endif
}

void Receiver::recv_loop(SpscRing<Datagram>& ring) {
  while (!stop_.load(std::memory_order_relaxed)) {
#if defined(__linux__)
    if (mode_ == RecvMode::Epoll) {
      struct epoll_event ev {};
      const int n = ::epoll_wait(epfd_, &ev, 1, kEpollTimeoutMs);
      if (n < 0) {
        if (errno == EINTR) continue;
        fail(std::string("epoll_wait: ") + std::strerror(errno));
        return;
      }
      if (n == 0) continue;  // timeout: re-check stop
    }
#endif
    // Busy-poll: spin on drain_once. Epoll: drain until EAGAIN (edge
    // triggered), capped so one hot fd cannot starve shutdown checks.
    for (int round = 0; round < kMaxDrainRounds; ++round) {
      if (!drain_once(ring)) break;
    }
  }
}

}  // namespace wiretap
