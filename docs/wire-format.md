# Wire Format

MoldUDP64-style framing carrying a simplified NASDAQ TotalView-ITCH 5.0
message subset. One UDP datagram (or capture-file record) = one packet.

## Packet

| Offset | Size | Field           | Endianness |
|--------|------|-----------------|------------|
| 0      | 10   | session         | alpha      |
| 10     | 8    | sequence_number | big        |
| 18     | 2    | message_count   | big        |
| 20     | ...  | messages        |            |

`session` is 10 alpha bytes (this generator writes `WIRETAP001`). Sequence
numbers are per-session, start at 1 and increment for every packet, including
dropped ones.

Each message is `length u16 BE | payload`, where `length` covers the payload
only (minimum 1).

## Messages (ITCH 5.0 field layout)

Alpha fields are left-justified and space padded. Prices are 4-byte unsigned
with 4 implied decimal places (ticks). Timestamps are 6-byte nanoseconds since
midnight.

| Type | Name           | Size | Fields                                                                 |
|------|----------------|------|------------------------------------------------------------------------|
| A    | AddOrder       | 26   | order_ref u64, side c, shares u32, stock 8s, price u32                  |
| F    | AddOrderMPID   | 30   | order_ref u64, side c, shares u32, stock 8s, price u32, attribution 4s |
| E    | OrderExecuted  | 21   | order_ref u64, exec_shares u32, match_number u64                       |
| X    | OrderCancel    | 13   | order_ref u64, canceled_shares u32                                     |
| D    | OrderDelete    | 9    | order_ref u64                                                          |
| U    | OrderReplace   | 25   | old_ref u64, new_ref u64, shares u32, price u32                        |
| P    | TradeNonCross  | 34   | order_ref u64, side c, shares u32, stock 8s, price u32, match_number u64 |
| S    | SystemEvent    | 8    | timestamp u48 (ns since midnight), event_code c                         |

System event codes: `O` start of messages, `S` start of system hours,
`C` end of system hours, `E` end of messages.

## Decoder behavior

`Decoder::decode_packet` is strictly bounds-checked: it never reads past the
buffer and returns `DecodeError::{TruncatedHeader,TruncatedMessage,
BadMessageLength}` on malformed input. Unknown message types are skipped using
their declared length, so the decoder stays forward-compatible with messages
outside the subset.

## Normalized updates

Each message maps to one `wiretap::BookUpdate` (see
`include/wiretap/book.hpp`):

| Wire | BookUpdate.action |
|------|-------------------|
| A, F | Added             |
| E, P | Executed          |
| X    | Canceled          |
| D    | Deleted           |
| U    | Replaced (order_ref = new ref) |
| S    | SystemEvent (exchange_ts_ns set) |

Fields a message does not carry (e.g. symbol on `D`/`U`/`S`) are zeroed.
