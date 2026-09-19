#!/usr/bin/env python3
"""Deterministic synthetic NASDAQ TotalView-ITCH 5.0 (subset) feed generator.

Wire format (MoldUDP64-style framing):
  packet header: session[10] | sequence_number u64 BE | message_count u16 BE
  then message_count messages, each: length u16 BE | payload

Supported message types (field layout matches ITCH 5.0):
  A  AddOrder        ref u64 | side c | shares u32 | stock 8s | price u32        (26)
  F  AddOrderMPID    ref u64 | side c | shares u32 | stock 8s | price u32 | mpid 4s (30)
  E  OrderExecuted   ref u64 | shares u32 | match u64                            (21)
  X  OrderCancel     ref u64 | shares u32                                       (13)
  D  OrderDelete     ref u64                                                    (9)
  U  OrderReplace    old u64 | new u64 | shares u32 | price u32                  (25)
  P  TradeNonCross   ref u64 | side c | shares u32 | stock 8s | price u32 | match u64 (34)
  S  SystemEvent     timestamp u48 BE (ns since midnight) | event code c        (8)

Prices are 4-byte unsigned with 4 implied decimal places (ticks).
Output is fully deterministic for a given --seed. --drop-rate omits whole
packets while sequence numbers keep advancing, so gap recovery can be tested.

Examples:
  python3 tools/feedgen.py --out capture.bin --messages 1000000
  python3 tools/feedgen.py --mode udp --group 239.1.1.1 --port 31337 --rate 100000
"""

from __future__ import annotations

import argparse
import fcntl
import random
import socket
import struct
import sys
import time

SESSION = b"WIRETAP001"  # 10 bytes
SESSION_LEN = 10
SEQ_LEN = 8
COUNT_LEN = 2
HEADER_LEN = SESSION_LEN + SEQ_LEN + COUNT_LEN  # 20
LEN_FIELD = 2
MAX_MSG_LEN = 34

DEFAULT_GROUP = "239.1.1.1"
DEFAULT_PORT = 31337
DEFAULT_TTL = 1
DEFAULT_MPP = 128          # messages per packet
DEFAULT_SEED = 42
FLUSH_BYTES = 1 << 20      # file sink flush threshold
NS_PER_DAY = 24 * 60 * 60 * 1_000_000_000

_HEADER = struct.Struct(">10sQH")
_MSG = {
    "A": struct.Struct(">cQcI8sI"),    # AddOrder
    "F": struct.Struct(">cQcI8sI4s"),  # AddOrderMPID
    "E": struct.Struct(">cQIQ"),       # OrderExecuted
    "X": struct.Struct(">cQI"),        # OrderCancel
    "D": struct.Struct(">cQ"),         # OrderDelete
    "U": struct.Struct(">cQQII"),      # OrderReplace
    "P": struct.Struct(">cQcI8sIQ"),   # TradeNonCross
    "S": struct.Struct(">c6sc"),       # SystemEvent
}
# Length-prefixed variants: pack_into writes "length u16 BE | payload" in one
# C-level call, which keeps message throughput up.
_FULL = {t: struct.Struct(">H" + st.format[1:]) for t, st in _MSG.items()}
_SIDE = {"B": b"B", "S": b"S"}


class Order:
    __slots__ = ("ref", "symbol", "side", "qty", "price")

    def __init__(self, ref, symbol, side, qty, price):
        self.ref = ref
        self.symbol = symbol
        self.side = side
        self.qty = qty
        self.price = price


class Feed:
    """Seeded synthetic order-lifecycle generator."""

    def __init__(self, seed, symbols, drop_rate, mpp):
        self.rng = random.Random(seed)
        self.symbols = symbols
        self.nsym = len(symbols)
        self.drop_rate = drop_rate
        self.mpp = mpp
        self.seq = 1
        self.next_ref = 1
        self.next_match = 1
        self.orders = {}  # ref -> Order
        self.open = []    # refs of open orders (swap-remove bookkeeping)
        self.pos = {}     # ref -> index in self.open
        # Rebind hot RNG helpers as locals (getrandbits avoids randint's
        # Python-level range machinery).
        self._bits = self.rng.getrandbits

    # -- order book state ---------------------------------------------------

    def _add(self, order):
        self.pos[order.ref] = len(self.open)
        self.open.append(order.ref)
        self.orders[order.ref] = order

    def _remove(self, order):
        idx = self.pos.pop(order.ref)
        last = self.open.pop()
        if idx != len(self.open):
            self.open[idx] = last
            self.pos[last] = idx
        del self.orders[order.ref]

    # -- event generation ---------------------------------------------------

    def tick(self, i, total):
        """Generate one message.

        Returns (type, manifest_row, args) where `args` are the arguments for
        the length-prefixed struct pack (length, type, fields...) and
        manifest_row holds (symbol, side, price_ticks, qty, order_ref,
        order_ref_old, action, exchange_ts_ns).
        """
        bits = self._bits
        orders = self.orders
        open_ = self.open
        add = self._add
        remove = self._remove

        if i == 0 or (total > 1 and i == total - 1):
            code = b"O" if i == 0 else b"E"  # start / end of messages
            ts = ((i + 1) * 123_456_789) % NS_PER_DAY
            ts6 = struct.pack(">Q", ts)[2:]
            return ("S", ("", "-", 0, 0, 0, 0, "SYSTEM_EVENT", ts),
                    (8, b"S", ts6, code))

        if not open_:
            typ = "A" if bits(8) < 230 else "F"  # p(A) = 0.9
        else:
            r = bits(32) % 100
            if r < 55:
                typ = "A"
            elif r < 60:
                typ = "F"
            elif r < 75:
                typ = "E"
            elif r < 85:
                typ = "X"
            elif r < 90:
                typ = "D"
            elif r < 95:
                typ = "U"
            else:
                typ = "P"

        if typ == "A" or typ == "F":
            symbol = self.symbols[bits(32) % self.nsym]
            side = "B" if bits(1) else "S"
            price = 10_000 + bits(32) % 990_001
            qty = 1 + bits(32) % 5_000
            ref = self.next_ref
            self.next_ref = ref + 1
            add(Order(ref, symbol, side, qty, price))
            if typ == "A":
                return ("A", (symbol, side, price, qty, ref, 0, "ADDED", 0),
                        (26, b"A", ref, _SIDE[side], qty, symbol.encode(), price))
            return ("F", (symbol, side, price, qty, ref, 0, "ADDED", 0),
                    (30, b"F", ref, _SIDE[side], qty, symbol.encode(), price,
                     b"WIRE"))
        if typ == "E":
            order = orders[open_[bits(32) % len(open_)]]
            qty = 1 + bits(32) % order.qty
            match = self.next_match
            self.next_match = match + 1
            order.qty -= qty
            if order.qty == 0:
                remove(order)
            return ("E", ("", "-", 0, qty, order.ref, 0, "EXECUTED", 0),
                    (21, b"E", order.ref, qty, match))
        if typ == "X":
            order = orders[open_[bits(32) % len(open_)]]
            qty = 1 + bits(32) % order.qty
            order.qty -= qty
            if order.qty == 0:
                remove(order)
            return ("X", ("", "-", 0, qty, order.ref, 0, "CANCELED", 0),
                    (13, b"X", order.ref, qty))
        if typ == "D":
            order = orders[open_[bits(32) % len(open_)]]
            remove(order)
            return ("D", ("", "-", 0, 0, order.ref, 0, "DELETED", 0),
                    (9, b"D", order.ref))
        if typ == "U":
            order = orders[open_[bits(32) % len(open_)]]
            new_price = max(1_000, order.price + (bits(32) % 4_001) - 2_000)
            new_qty = 1 + bits(32) % 5_000
            new_ref = self.next_ref
            self.next_ref = new_ref + 1
            remove(order)
            add(Order(new_ref, order.symbol, order.side, new_qty, new_price))
            return ("U", ("", "-", new_price, new_qty, new_ref, order.ref, "REPLACED", 0),
                    (25, b"U", order.ref, new_ref, new_qty, new_price))
        # typ == "P": full non-displayed execution
        order = orders[open_[bits(32) % len(open_)]]
        match = self.next_match
        self.next_match = match + 1
        remove(order)
        return ("P", (order.symbol, order.side, order.price, order.qty,
                      order.ref, 0, "EXECUTED", 0),
                (34, b"P", order.ref, _SIDE[order.side], order.qty,
                 order.symbol.encode(), order.price, match))

    # -- packet assembly / emission -----------------------------------------

    def run(self, total, rate, sink, manifest=None):
        """Emit `total` messages through `sink` (obj with .write(pkt)/.flush()).

        `manifest` is an optional text file receiving one TSV row per emitted
        update: seq, type, symbol, side, price_ticks, qty, order_ref,
        order_ref_old, action, exchange_ts_ns. Rows are only written for
        packets actually emitted (dropped packets stay out).
        """
        capacity = HEADER_LEN + self.mpp * (LEN_FIELD + MAX_MSG_LEN)
        buf = bytearray(capacity)
        interval = self.mpp / rate if rate > 0 else 0.0
        next_due = time.perf_counter()
        written = dropped = 0
        rng = self.rng

        count = 0
        off = HEADER_LEN
        pending = []

        def finish():
            nonlocal count, off, pending, next_due, written, dropped
            _HEADER.pack_into(buf, 0, SESSION, self.seq, count)
            packet = bytes(buf[:off])
            if self.drop_rate > 0 and rng.random() < self.drop_rate:
                dropped += 1
            else:
                sink.write(packet)
                if manifest is not None:
                    for typ, row in pending:
                        manifest.write("\t".join(
                            (str(self.seq), typ) + tuple(str(v) for v in row)) + "\n")
                written += 1
            self.seq += 1
            count = 0
            off = HEADER_LEN
            pending = []
            if interval > 0:
                next_due += interval
                now = time.perf_counter()
                if now < next_due:
                    time.sleep(next_due - now)

        for i in range(total):
            typ, row, args = self.tick(i, total)
            _FULL[typ].pack_into(buf, off, *args)
            off += LEN_FIELD + args[0]
            count += 1
            if manifest is not None:
                pending.append((typ, row))
            if count == self.mpp:
                finish()
        if count:
            finish()
        sink.flush()
        return written, dropped


class _FileSink:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.buf = bytearray()

    def write(self, packet):
        self.buf += packet
        if len(self.buf) >= FLUSH_BYTES:
            self.f.write(self.buf)
            self.buf.clear()

    def flush(self):
        if self.buf:
            self.f.write(self.buf)
            self.buf.clear()
        self.f.flush()

    def close(self):
        self.flush()
        self.f.close()


class _UdpSink:
    def __init__(self, group, port, iface, ttl):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        if iface:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                 socket.inet_aton(_iface_ip(iface)))
        self.dest = (group, port)

    def write(self, packet):
        self.sock.sendto(packet, self.dest)

    def flush(self):
        pass

    def close(self):
        self.sock.close()


def _iface_ip(name):
    """Resolve an interface name to its IPv4 address (POSIX ioctl)."""
    try:
        socket.inet_aton(name)
        return name  # already an address
    except OSError:
        pass
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        packed_req = struct.pack("256s", name.encode()[:15])
        for siocgifaddr in (0x8915, 0xC0206921):  # Linux, macOS
            try:
                packed = fcntl.ioctl(sock.fileno(), siocgifaddr, packed_req)
                return socket.inet_ntoa(packed[20:24])
            except OSError:
                continue
    raise SystemExit(f"cannot resolve interface '{name}'")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Generate a deterministic synthetic ITCH 5.0 feed.")
    p.add_argument("--seed", type=int, default=DEFAULT_SEED,
                   help="RNG seed (default: %(default)s)")
    p.add_argument("--symbols", type=int, default=20,
                   help="number of symbols SYM00000.. (default: %(default)s)")
    p.add_argument("--messages", type=int, default=10_000,
                   help="total messages to generate (default: %(default)s)")
    p.add_argument("--rate", type=float, default=0.0,
                   help="target messages/sec; 0 = as fast as possible")
    p.add_argument("--duration", type=float, default=0.0,
                   help="generate for N seconds (overrides --messages)")
    p.add_argument("--drop-rate", type=float, default=0.0,
                   help="probability a whole packet is dropped; sequence "
                        "numbers still advance (default: %(default)s)")
    p.add_argument("--mpp", type=int, default=DEFAULT_MPP,
                   help="messages per packet (default: %(default)s)")
    p.add_argument("--mode", choices=("file", "udp"), default="file",
                   help="output mode (default: %(default)s)")
    p.add_argument("--out", default="capture.bin",
                   help="capture file for --mode file (default: %(default)s)")
    p.add_argument("--manifest",
                   help="write a TSV manifest of decoded updates for "
                        "round-trip testing (10 columns, incl. old ref)")
    p.add_argument("--group", default=DEFAULT_GROUP, help="multicast group")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help="UDP port (default: %(default)s)")
    p.add_argument("--iface", default="",
                   help="outbound interface (name or IPv4) for multicast")
    p.add_argument("--ttl", type=int, default=DEFAULT_TTL,
                   help="IP_MULTICAST_TTL (default: %(default)s)")
    args = p.parse_args(argv)

    if args.duration > 0:
        rate = args.rate if args.rate > 0 else 100_000.0
        args.messages = int(args.duration * rate)
    if args.messages < 1:
        p.error("--messages must be >= 1")
    if args.symbols < 1:
        p.error("--symbols must be >= 1")
    if not 0.0 <= args.drop_rate < 1.0:
        p.error("--drop-rate must be in [0, 1)")
    if args.mode == "file" and args.iface:
        p.error("--iface only applies to --mode udp")
    return args


def main(argv=None):
    args = parse_args(argv)
    symbols = [f"SYM{i:05d}" for i in range(args.symbols)]
    feed = Feed(args.seed, symbols, args.drop_rate, args.mpp)

    if args.mode == "udp":
        sink = _UdpSink(args.group, args.port, args.iface, args.ttl)
        dest = f"udp {args.group}:{args.port}"
    else:
        sink = _FileSink(args.out)
        dest = f"file {args.out}"

    manifest = open(args.manifest, "w", newline="") if args.manifest else None

    t0 = time.perf_counter()
    try:
        written, dropped = feed.run(args.messages, args.rate, sink, manifest)
    finally:
        sink.close()
        if manifest is not None:
            manifest.close()

    elapsed = time.perf_counter() - t0
    rate = args.messages / elapsed if elapsed > 0 else 0.0
    print(f"feedgen: {args.messages} messages -> {dest}", file=sys.stderr)
    print(f"  packets written: {written}, dropped: {dropped}, "
          f"elapsed: {elapsed:.3f}s ({rate/1e6:.3f} M msgs/s)", file=sys.stderr)


if __name__ == "__main__":
    main()
