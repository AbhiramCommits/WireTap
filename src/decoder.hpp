// wiretap/decoder.hpp - bounds-checked ITCH 5.0 (subset) packet decoder.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "wiretap/book.hpp"

namespace wiretap {

enum class DecodeError : std::uint8_t {
  Ok = 0,
  TruncatedHeader,   // fewer than 20 bytes available
  TruncatedMessage,  // length prefix / message body extends past the buffer
  BadMessageLength,  // zero length, or length != expected size for a known type
};

inline const char* decode_error_name(DecodeError e) noexcept {
  switch (e) {
    case DecodeError::Ok:
      return "Ok";
    case DecodeError::TruncatedHeader:
      return "TruncatedHeader";
    case DecodeError::TruncatedMessage:
      return "TruncatedMessage";
    case DecodeError::BadMessageLength:
      return "BadMessageLength";
  }
  return "Unknown";
}

struct DecodeResult {
  DecodeError error = DecodeError::Ok;
  std::uint64_t sequence_number = 0;
  std::uint16_t message_count = 0;   // as declared in the packet header
  std::uint16_t updates_decoded = 0; // BookUpdates appended to `out` (0 on error)
};

// Returns the on-wire length of the packet starting at `data` (MoldUDP64
// framing), or false if the buffer is malformed/short. Used to walk a capture
// file frame-by-frame.
bool packet_length(const std::uint8_t* data, std::size_t size,
                   std::size_t& length) noexcept;

class Decoder {
 public:
  // `recv_ts_ns` is stamped into every BookUpdate produced by this decoder.
  explicit Decoder(std::uint64_t recv_ts_ns = 0) noexcept : recv_ts_ns_(recv_ts_ns) {}
  void set_recv_ts_ns(std::uint64_t ns) noexcept { recv_ts_ns_ = ns; }

  // Decodes one packet. Never throws, never reads past `data + len`.
  // On success appends BookUpdates to `out`; on error, rolls back any partial
  // updates from this packet and reports the failure in the result.
  DecodeResult decode_packet(const std::uint8_t* data, std::size_t len,
                             std::vector<BookUpdate>& out) const noexcept;

 private:
  std::uint64_t recv_ts_ns_;
};

}  // namespace wiretap
