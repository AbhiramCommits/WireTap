// test_common.hpp - test-side ITCH encoder shared by decoder/malformed tests.

#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace testutil {

inline void put_be16(std::uint8_t* p, std::uint16_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 8);
  p[1] = static_cast<std::uint8_t>(v);
}

inline void put_be32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 24);
  p[1] = static_cast<std::uint8_t>(v >> 16);
  p[2] = static_cast<std::uint8_t>(v >> 8);
  p[3] = static_cast<std::uint8_t>(v);
}

inline void put_be48(std::uint8_t* p, std::uint64_t v) {
  for (int i = 5; i >= 0; --i) {
    p[i] = static_cast<std::uint8_t>(v);
    v >>= 8;
  }
}

inline void put_be64(std::uint8_t* p, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) {
    p[i] = static_cast<std::uint8_t>(v);
    v >>= 8;
  }
}

inline void put_stock(std::uint8_t* p, const char* sym) {
  std::memset(p, ' ', 8);
  std::memcpy(p, sym, std::strlen(sym));
}

inline std::vector<std::uint8_t> add_order(char side, std::uint64_t ref, std::uint32_t qty,
                                           const char* stock, std::uint32_t price) {
  std::vector<std::uint8_t> m(26);
  m[0] = 'A';
  put_be64(m.data() + 1, ref);
  m[9] = static_cast<std::uint8_t>(side);
  put_be32(m.data() + 10, qty);
  put_stock(m.data() + 14, stock);
  put_be32(m.data() + 22, price);
  return m;
}

inline std::vector<std::uint8_t> add_order_mpid(char side, std::uint64_t ref, std::uint32_t qty,
                                                const char* stock, std::uint32_t price,
                                                const char* mpid) {
  std::vector<std::uint8_t> m(30);
  m[0] = 'F';
  put_be64(m.data() + 1, ref);
  m[9] = static_cast<std::uint8_t>(side);
  put_be32(m.data() + 10, qty);
  put_stock(m.data() + 14, stock);
  put_be32(m.data() + 22, price);
  std::memset(m.data() + 26, ' ', 4);
  std::memcpy(m.data() + 26, mpid, std::strlen(mpid));
  return m;
}

inline std::vector<std::uint8_t> order_executed(std::uint64_t ref, std::uint32_t qty,
                                                std::uint64_t match) {
  std::vector<std::uint8_t> m(21);
  m[0] = 'E';
  put_be64(m.data() + 1, ref);
  put_be32(m.data() + 9, qty);
  put_be64(m.data() + 13, match);
  return m;
}

inline std::vector<std::uint8_t> order_cancel(std::uint64_t ref, std::uint32_t qty) {
  std::vector<std::uint8_t> m(13);
  m[0] = 'X';
  put_be64(m.data() + 1, ref);
  put_be32(m.data() + 9, qty);
  return m;
}

inline std::vector<std::uint8_t> order_delete(std::uint64_t ref) {
  std::vector<std::uint8_t> m(9);
  m[0] = 'D';
  put_be64(m.data() + 1, ref);
  return m;
}

inline std::vector<std::uint8_t> order_replace(std::uint64_t old_ref, std::uint64_t new_ref,
                                               std::uint32_t qty, std::uint32_t price) {
  std::vector<std::uint8_t> m(25);
  m[0] = 'U';
  put_be64(m.data() + 1, old_ref);
  put_be64(m.data() + 9, new_ref);
  put_be32(m.data() + 17, qty);
  put_be32(m.data() + 21, price);
  return m;
}

inline std::vector<std::uint8_t> trade_non_cross(std::uint64_t ref, char side, std::uint32_t qty,
                                                 const char* stock, std::uint32_t price,
                                                 std::uint64_t match) {
  std::vector<std::uint8_t> m(34);
  m[0] = 'P';
  put_be64(m.data() + 1, ref);
  m[9] = static_cast<std::uint8_t>(side);
  put_be32(m.data() + 10, qty);
  put_stock(m.data() + 14, stock);
  put_be32(m.data() + 22, price);
  put_be64(m.data() + 26, match);
  return m;
}

inline std::vector<std::uint8_t> system_event(std::uint64_t ts_ns, char code) {
  std::vector<std::uint8_t> m(8);
  m[0] = 'S';
  put_be48(m.data() + 1, ts_ns);
  m[7] = static_cast<std::uint8_t>(code);
  return m;
}

// Assembles a full MoldUDP64 packet from message payloads.
inline std::vector<std::uint8_t> packet(const std::vector<std::vector<std::uint8_t>>& msgs,
                                        std::uint64_t seq) {
  std::size_t total = 20;
  for (const auto& m : msgs)
    total += 2 + m.size();
  std::vector<std::uint8_t> p(total);
  std::memcpy(p.data(), "WIRETAP001", 10);
  put_be64(p.data() + 10, seq);
  put_be16(p.data() + 18, static_cast<std::uint16_t>(msgs.size()));
  std::size_t off = 20;
  for (const auto& m : msgs) {
    put_be16(p.data() + off, static_cast<std::uint16_t>(m.size()));
    off += 2;
    std::memcpy(p.data() + off, m.data(), m.size());
    off += m.size();
  }
  return p;
}

}  // namespace testutil
