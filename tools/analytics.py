#!/usr/bin/env python3
"""DuckDB query layer over the wiretap Parquet archive.

Every query pushes filters and aggregation into DuckDB (partition pruning on
date/symbol/hour + columnar scans); no query materializes raw rows into
memory. Built for archives with hundreds of millions of updates.

Layout produced by the C++ ArchiveWriter:
  ARCHIVE/
    book/date=YYYY-MM-DD/symbol=SYMxxxxx/hour=H/part-*.parquet
    stats/stats-*.parquet     (per-second aggregates + latency percentiles)
    depth/part-*.parquet      (per-second per-symbol top-10 depth snapshots)
    gaps/part-*.parquet       (gap/recovery events)

Commands:
  rate         message rate over time (bucket seconds/minutes)
  top-symbols  top N symbols by update count
  depth        spread + depth time series per symbol (from pre-aggregated
               depth snapshots)
  latency      latency percentiles per minute (from per-second stats)
  gaps         gap/recovery timeline
"""

from __future__ import annotations

import argparse
import sys
import time

import duckdb

BOOK_GLOB = "book/**/*.parquet"


def _connect(archive):
    con = duckdb.connect()
    con.execute(f"SET home_directory='{archive}'")  # duckdb 1.x prefix
    return con


def _table(tbl):
    """Render a pyarrow Table as an aligned text table (no pandas)."""
    cols = tbl.column_names
    rows = tbl.to_pylist()
    widths = [len(c) for c in cols]
    for row in rows:
        for i, c in enumerate(cols):
            widths[i] = max(widths[i], len(str(row[c])))
    print("  ".join(c.ljust(widths[i]) for i, c in enumerate(cols)))
    print("  ".join("-" * widths[i] for i in range(len(cols))))
    for row in rows:
        print("  ".join(str(row[c]).ljust(widths[i]) for i, c in enumerate(cols)))
    print(f"({len(rows)} rows)")


def _time_filter_clause(frm, to):
    """Returns (SQL clause, params) for timestamp range filters. Numeric
    values are unix seconds (converted with to_timestamp); strings are
    duckdb timestamp literals."""
    if frm is None and to is None:
        return "", []
    parts = []
    params = []
    if frm is not None:
        parts.append("recv_ts_ns >= to_timestamp(?)" if isinstance(frm, float)
                     else "recv_ts_ns >= CAST(? AS TIMESTAMP)")
        params.append(frm)
    if to is not None:
        parts.append("recv_ts_ns < to_timestamp(?)" if isinstance(to, float)
                     else "recv_ts_ns < CAST(? AS TIMESTAMP)")
        params.append(to)
    return " WHERE " + " AND ".join(parts), params


def _parse_time(value):
    """Accepts duckdb timestamps ('2026-09-19 10:00:00'), ISO dates, or
    unix seconds."""
    if value is None:
        return None
    try:
        return float(value)  # unix seconds
    except ValueError:
        return value  # pass through as a duckdb timestamp literal


def _arg_ts(value):
    return _parse_time(value)


def cmd_rate(con, args):
    bucket = int(args.bucket)
    clause, params = _time_filter_clause(args.from_ts, args.to_ts)
    rel = con.execute(
        f"""
        SELECT time_bucket(INTERVAL '{bucket} second', recv_ts_ns) AS t,
               count(*) AS msgs
        FROM read_parquet('{args.archive}/{BOOK_GLOB}', hive_partitioning=true)
        {clause}
        GROUP BY t ORDER BY t
        """,
        params,
    ).fetch_arrow_table()
    _table(rel)


def cmd_top_symbols(con, args):
    clause, params = _time_filter_clause(args.from_ts, args.to_ts)
    n = int(args.n)
    rel = con.execute(
        f"""
        SELECT symbol, count(*) AS updates
        FROM read_parquet('{args.archive}/{BOOK_GLOB}', hive_partitioning=true)
        {clause}
        GROUP BY symbol ORDER BY updates DESC LIMIT {n}
        """,
        params,
    ).fetch_arrow_table()
    _table(rel)


def cmd_depth(con, args):
    # Spread/depth computed from the pre-aggregated per-second depth table:
    # best bid/ask = level-0 rows, depth = total qty of the top-10 ladder.
    symbol = args.symbol
    clause = " WHERE symbol = ?"
    params = [symbol]
    if args.from_ts is not None:
        clause += " AND sec >= to_timestamp(?)"
        params.append(args.from_ts)
    if args.to_ts is not None:
        clause += " AND sec < to_timestamp(?)"
        params.append(args.to_ts)
    rel = con.execute(
        f"""
        SELECT sec,
               max(CASE WHEN side='B' THEN price_ticks END)  AS best_bid,
               min(CASE WHEN side='A' THEN price_ticks END)  AS best_ask,
               min(CASE WHEN side='A' THEN price_ticks END)
                 - max(CASE WHEN side='B' THEN price_ticks END) AS spread,
               sum(CASE WHEN side='B' THEN qty ELSE 0 END)   AS bid_depth,
               sum(CASE WHEN side='A' THEN qty ELSE 0 END)   AS ask_depth
        FROM read_parquet('{args.archive}/depth/*.parquet')
        {clause}
        GROUP BY sec ORDER BY sec
        """,
        params,
    ).fetch_arrow_table()
    _table(rel)


def cmd_latency(con, args):
    # Percentiles per minute from the per-second stats table. p50/p99 are
    # averaged; the tails (p99.9/p99.99/max) are worst-case (max) per minute
    # so tail shape is never smoothed away.
    clause = " WHERE 1=1"
    params = []
    if args.from_ts is not None:
        clause += " AND sec >= to_timestamp(?)"
        params.append(args.from_ts)
    if args.to_ts is not None:
        clause += " AND sec < to_timestamp(?)"
        params.append(args.to_ts)
    rel = con.execute(
        f"""
        SELECT time_bucket(INTERVAL '1 minute', sec) AS minute,
               sum(wtb_count)                          AS samples,
               round(avg(wtb_p50))                     AS avg_p50,
               round(avg(wtb_p99))                     AS avg_p99,
               round(max(wtb_p999))                    AS max_p99_9,
               round(max(wtb_p9999))                   AS max_p99_99,
               round(max(wtb_max))                     AS max_max
        FROM read_parquet('{args.archive}/stats/*.parquet')
        {clause}
        GROUP BY minute ORDER BY minute
        """,
        params,
    ).fetch_arrow_table()
    _table(rel)


def cmd_gaps(con, args):
    clause = " WHERE 1=1"
    params = []
    if args.from_ts is not None:
        clause += " AND detected_ts_ns >= to_timestamp(?)"
        params.append(args.from_ts)
    if args.to_ts is not None:
        clause += " AND detected_ts_ns < to_timestamp(?)"
        params.append(args.to_ts)
    n = int(args.n)
    try:
        con.execute(f"SELECT count(*) FROM read_parquet('{args.archive}/gaps/*.parquet')")
    except Exception:
        print("(no gaps recorded)")
        return
    rel = con.execute(
        f"""
        SELECT detected_ts_ns, healed, start, "end", missing,
               (healed_ts_ns - detected_ts_ns) / 1000000 AS heal_ms
        FROM read_parquet('{args.archive}/gaps/*.parquet')
        {clause}
        ORDER BY detected_ts_ns DESC LIMIT {n}
        """,
        params,
    ).fetch_arrow_table()
    _table(rel)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="DuckDB queries over the wiretap Parquet archive.")
    p.add_argument("--archive", default="archive",
                   help="archive root directory (default: %(default)s)")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("rate", help="message rate over time")
    sp.add_argument("--bucket", default=1, help="bucket width in seconds "
                   "(default: %(default)s)")
    sp.add_argument("--from", dest="from_ts", default=None, type=_arg_ts)
    sp.add_argument("--to", dest="to_ts", default=None, type=_arg_ts)

    sp = sub.add_parser("top-symbols", help="top N symbols by update count")
    sp.add_argument("--n", default=10)
    sp.add_argument("--from", dest="from_ts", default=None, type=_arg_ts)
    sp.add_argument("--to", dest="to_ts", default=None, type=_arg_ts)

    sp = sub.add_parser("depth", help="spread + depth time series per symbol")
    sp.add_argument("--symbol", required=True)
    sp.add_argument("--from", dest="from_ts", default=None, type=_arg_ts)
    sp.add_argument("--to", dest="to_ts", default=None, type=_arg_ts)

    sp = sub.add_parser("latency", help="latency percentiles per minute")
    sp.add_argument("--from", dest="from_ts", default=None, type=_arg_ts)
    sp.add_argument("--to", dest="to_ts", default=None, type=_arg_ts)

    sp = sub.add_parser("gaps", help="gap/recovery timeline")
    sp.add_argument("--n", default=50)
    sp.add_argument("--from", dest="from_ts", default=None, type=_arg_ts)
    sp.add_argument("--to", dest="to_ts", default=None, type=_arg_ts)

    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    con = _connect(args.archive)
    t0 = time.time()
    handlers = {
        "rate": cmd_rate,
        "top-symbols": cmd_top_symbols,
        "depth": cmd_depth,
        "latency": cmd_latency,
        "gaps": cmd_gaps,
    }
    handlers[args.command](con, args)
    print(f"(query took {time.time() - t0:.2f}s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
