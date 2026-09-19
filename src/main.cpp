// wiretap-dump: decode a .bin capture file and print summary statistics.

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

#include "decoder.hpp"

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s <capture.bin>\n", argv[0]);
    return 2;
  }

  std::ifstream f(argv[1], std::ios::binary);
  if (!f) {
    std::fprintf(stderr, "wiretap-dump: cannot open '%s'\n", argv[1]);
    return 2;
  }
  std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());

  wiretap::Decoder decoder;
  std::size_t off = 0;
  std::size_t packets = 0;
  std::size_t updates = 0;
  std::size_t gaps = 0;
  std::uint64_t last_seq = 0;
  std::uint64_t first_seq = 0;
  std::uint64_t actions[static_cast<std::size_t>(wiretap::Action::kCount)] = {0};

  while (off < data.size()) {
    std::size_t plen = 0;
    if (!wiretap::packet_length(data.data() + off, data.size() - off, plen)) {
      std::fprintf(stderr, "wiretap-dump: malformed packet at offset %zu\n", off);
      return 1;
    }
    std::vector<wiretap::BookUpdate> upd;
    const auto r = decoder.decode_packet(data.data() + off, plen, upd);
    if (r.error != wiretap::DecodeError::Ok) {
      std::fprintf(stderr, "wiretap-dump: decode error at offset %zu: %s\n", off,
                   wiretap::decode_error_name(r.error));
      return 1;
    }
    ++packets;
    if (first_seq == 0) first_seq = r.sequence_number;
    if (last_seq != 0 && r.sequence_number != last_seq + 1) ++gaps;
    last_seq = r.sequence_number;
    updates += upd.size();
    for (const auto& u : upd) ++actions[static_cast<std::size_t>(u.action)];
    off += plen;
  }

  std::printf("packets:      %zu\n", packets);
  std::printf("sequence:     %llu .. %llu (%zu gaps)\n",
              static_cast<unsigned long long>(first_seq),
              static_cast<unsigned long long>(last_seq), gaps);
  std::printf("updates:      %zu\n", updates);
  for (std::size_t i = 1; i < static_cast<std::size_t>(wiretap::Action::kCount); ++i) {
    std::printf("  %-12s %llu\n", wiretap::action_name(static_cast<wiretap::Action>(i)),
                static_cast<unsigned long long>(actions[i]));
  }
  return 0;
}
