#!/usr/bin/env python3
"""TCP retransmission server for wiretap gap recovery.

Serves MoldUDP64 packet ranges out of a capture file. The capture is indexed
once at startup; each request is answered from memory.

Protocol (line-based, one request per connection):
  client -> "GET <start> <end>\\n"      (sequence numbers, inclusive)
  server -> raw packets back to back, then close (EOF signals completeness)
            or "ERROR <message>\\n" then close when the range is unavailable

Example:
  python3 tools/feedgen.py --out capture.bin --messages 2000000   # full feed
  python3 tools/retransmit_server.py --capture capture.bin --port 38899
  ./build/wiretap_recv --recover 127.0.0.1:38899 --mode busy
"""

from __future__ import annotations

import argparse
import socket
import socketserver
import sys

SESSION_LEN = 10
SEQ_OFF = 10
COUNT_OFF = 18
HEADER_LEN = 20
LEN_FIELD = 2


def build_index(path):
    """Returns (file_bytes, {seq: (offset, packet_length)})."""
    with open(path, "rb") as f:
        data = f.read()
    index = {}
    off = 0
    while off + HEADER_LEN <= len(data):
        seq = int.from_bytes(data[off + SEQ_OFF:off + SEQ_OFF + 8], "big")
        count = int.from_bytes(data[off + COUNT_OFF:off + COUNT_OFF + 2], "big")
        end = off + HEADER_LEN
        for _ in range(count):
            if end + LEN_FIELD > len(data):
                raise SystemExit(f"{path}: truncated message length at "
                                 f"offset {end}")
            mlen = int.from_bytes(data[end:end + LEN_FIELD], "big")
            end += LEN_FIELD + mlen
            if end > len(data):
                raise SystemExit(f"{path}: truncated message body at "
                                 f"offset {end}")
        index[seq] = (off, end - off)
        off = end
    if off != len(data):
        raise SystemExit(f"{path}: trailing garbage after offset {off}")
    return data, index


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            line = self.rfile.readline(4096).strip()
        except (ConnectionError, socket.timeout):
            return
        parts = line.split()
        if len(parts) != 3 or parts[0] != b"GET":
            self._error("bad request")
            return
        try:
            start, end = int(parts[1]), int(parts[2])
        except ValueError:
            self._error("bad range")
            return
        if end < start:
            self._error("bad range")
            return
        if start < self.server.min_seq or end > self.server.max_seq:
            self._error(f"range {start}-{end} outside capture "
                        f"{self.server.min_seq}-{self.server.max_seq}")
            return
        sent = 0
        try:
            for seq in range(start, end + 1):
                rec = self.server.index.get(seq)
                if rec is None:
                    self._error(f"hole in capture at seq {seq}")
                    return
                offset, length = rec
                self.wfile.write(self.server.data[offset:offset + length])
                sent += 1
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        print(f"retransmit: GET {start} {end} -> {sent} packets",
              file=sys.stderr)

    def _error(self, msg):
        try:
            self.wfile.write(f"ERROR {msg}\n".encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        print(f"retransmit: refused request: {msg}", file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Serve MoldUDP64 packet ranges over TCP for gap recovery.")
    p.add_argument("--capture", required=True, help="capture file to serve")
    p.add_argument("--host", default="127.0.0.1", help="bind address "
                   "(default: %(default)s)")
    p.add_argument("--port", type=int, default=38899, help="TCP port "
                   "(default: %(default)s)")
    args = p.parse_args(argv)

    data, index = build_index(args.capture)
    if not index:
        raise SystemExit(f"{args.capture}: no packets found")
    min_seq, max_seq = min(index), max(index)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server((args.host, args.port), Handler)
    server.data = data
    server.index = index
    server.min_seq = min_seq
    server.max_seq = max_seq
    print(f"retransmit: serving {args.capture} ({len(index)} packets, "
          f"seq {min_seq}-{max_seq}) on {args.host}:{args.port}",
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
