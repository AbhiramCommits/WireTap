#include "recovery_client.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "decoder.hpp"  // packet_length
#include "time_base.hpp"

namespace wiretap {

namespace {

constexpr int kConnectTimeoutMs = 2000;
constexpr int kReadTimeoutMs = 5000;
constexpr std::size_t kMaxBufferedBytes = 64u << 20;  // sanity cap

int connect_timeout(const std::string& host, std::uint16_t port, int ms) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  struct sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return -1;
  }
  const int flags = ::fcntl(fd, F_GETFL, 0);
  ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  int rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr);
  if (rc != 0 && errno == EINPROGRESS) {
    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    rc = ::poll(&pfd, 1, ms);
    if (rc <= 0) {
      ::close(fd);
      return -1;
    }
    int err = 0;
    socklen_t el = sizeof err;
    ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err != 0) {
      ::close(fd);
      return -1;
    }
  } else if (rc != 0) {
    ::close(fd);
    return -1;
  }
  ::fcntl(fd, F_SETFL, flags);  // back to blocking
  return fd;
}

}  // namespace

void RecoveryClient::run(SpscRing<GapRequest>& requests,
                         SpscRing<Datagram>& recovered,
                         const std::atomic<bool>& stop) {
  GapRequest req;
  for (;;) {
    if (requests.try_pop(req)) {
      fetch_range(req.start, req.end, recovered);
      continue;
    }
    if (stop.load(std::memory_order_relaxed)) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  // Drain whatever was queued before shutdown so the decode thread sees the
  // data rather than timing the gap out.
  while (requests.try_pop(req)) fetch_range(req.start, req.end, recovered);
}

bool RecoveryClient::fetch_range(std::uint64_t start, std::uint64_t end,
                                 SpscRing<Datagram>& recovered) {
  requests_.fetch_add(1, std::memory_order_relaxed);

  const int fd = connect_timeout(host_, port_, kConnectTimeoutMs);
  if (fd < 0) {
    std::fprintf(stderr, "wiretap: recovery: connect to %s:%u failed: %s\n",
                 host_.c_str(), port_, std::strerror(errno));
    errors_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  const std::string req = "GET " + std::to_string(start) + " " +
                          std::to_string(end) + "\n";
  const ssize_t sent = ::send(fd, req.data(), req.size(), MSG_NOSIGNAL);
  if (sent != static_cast<ssize_t>(req.size())) {
    ::close(fd);
    errors_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  bool ok = true;
  std::vector<std::uint8_t> buf;
  char tmp[65536];
  for (;;) {
    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLIN;
    const int prc = ::poll(&pfd, 1, kReadTimeoutMs);
    if (prc <= 0) {
      ok = false;
      break;
    }
    const ssize_t r = ::recv(fd, tmp, sizeof tmp, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      ok = false;
      break;
    }
    if (r == 0) break;  // EOF: server sent the whole range (or an error)
    buf.insert(buf.end(), tmp, tmp + r);
    if (buf.size() > kMaxBufferedBytes) {
      ok = false;
      break;
    }
    if (buf.size() >= 6 && std::memcmp(buf.data(), "ERROR ", 6) == 0) {
      std::fprintf(stderr, "wiretap: recovery: server refused range %llu-%llu\n",
                   static_cast<unsigned long long>(start),
                   static_cast<unsigned long long>(end));
      ok = false;
      break;
    }
    // Consume complete frames; keep the (possibly partial) remainder.
    std::size_t off = 0;
    std::size_t plen = 0;
    while (packet_length(buf.data() + off, buf.size() - off, plen)) {
      Datagram d;
      d.recv_ts_ticks = TimeBase::instance().now_ticks();
      d.hw_ts_ticks = d.recv_ts_ticks;  // recovered: no kernel stamp
      d.length = static_cast<std::uint32_t>(plen);
      std::memcpy(d.bytes.data(), buf.data() + off, plen);
      if (!recovered.try_push(d)) {
        std::fprintf(stderr,
                     "wiretap: recovery: recovered ring full, dropped seq\n");
        errors_.fetch_add(1, std::memory_order_relaxed);
      } else {
        fetched_.fetch_add(1, std::memory_order_relaxed);
      }
      off += plen;
    }
    if (off > 0) buf.erase(buf.begin(), buf.begin() + static_cast<long>(off));
  }

  if (ok && !buf.empty()) {
    ok = false;  // trailing garbage after the frames
  }
  if (!ok) errors_.fetch_add(1, std::memory_order_relaxed);
  ::close(fd);
  return ok;
}

}  // namespace wiretap
