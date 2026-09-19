#!/usr/bin/env python3
"""WireTap live dashboard backend.

  - Reads live snapshots (10 Hz JSON over a Unix datagram socket) published by
    the C++ handler (cold path only; the hot path never talks HTTP).
  - Fans the latest snapshot + an accumulated latency histogram out to browser
    clients over WebSocket at 10 Hz.
  - Serves historical queries (DuckDB over the Parquet archive) over REST,
    always pre-aggregated server-side: raw rows are never shipped to the
    browser.
  - Serves the built React frontend (frontend/dist) as static files.

Run:
  uvicorn backend:app --host 0.0.0.0 --port 8000
Environment:
  WIRETAP_SOCKET   unix datagram path to read live snapshots from
                   (default /tmp/wiretap-dash.sock)
  WIRETAP_ARCHIVE  Parquet archive root (default ./archive)
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import threading
from contextlib import asynccontextmanager

import duckdb
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

SOCKET_PATH = os.environ.get("WIRETAP_SOCKET", "/tmp/wiretap-dash.sock")
ARCHIVE = os.environ.get("WIRETAP_ARCHIVE", "./archive")

@asynccontextmanager
async def lifespan(app):
    loop = asyncio.get_running_loop()
    stop = threading.Event()
    thread = threading.Thread(target=_uds_reader, args=(loop, stop), daemon=True)
    thread.start()
    yield
    stop.set()
    try:
        os.unlink(SOCKET_PATH)
    except OSError:
        pass


app = FastAPI(title="wiretap-dashboard", lifespan=lifespan)

# --------------------------------------------------------------------------
# Live state (written by the UDS reader task, read by the WS broadcaster).
# --------------------------------------------------------------------------

latest_snapshot: dict = {}
histogram: dict = {"sec": 0, "buckets": []}  # per-second bucket dumps
hist_total: dict = {}  # value -> cumulative count (session since backend start)


def merge_histogram(payload):
    """Merge the handler's per-second wire_to_book bucket dump into the
    cumulative histogram (dedup by second id)."""
    hist = payload.get("histogram") or {}
    sec = hist.get("sec", 0)
    if not sec or sec <= histogram["sec"]:
        return
    histogram["sec"] = sec
    for value, count in hist.get("buckets", []):
        hist_total[value] = hist_total.get(value, 0) + count


def percentile_from_counts(counts: dict, pct: float) -> int:
    """pct (0..100) over a {value: count} cumulative histogram."""
    if not counts:
        return 0
    total = sum(counts.values())
    if total == 0:
        return 0
    target = total * pct / 100.0
    acc = 0
    for value in sorted(counts):
        acc += counts[value]
        if acc >= target:
            return value
    return max(counts)


def ws_payload():
    return json.dumps({
        "live": latest_snapshot,
        "histogram": {
            "buckets": sorted(hist_total.items()),  # [[value, count], ...]
            "count": sum(hist_total.values()),
            "p50": percentile_from_counts(hist_total, 50.0),
            "p99": percentile_from_counts(hist_total, 99.0),
            "p99_9": percentile_from_counts(hist_total, 99.9),
        },
    })


# --------------------------------------------------------------------------
# UDS datagram reader (live snapshots from the C++ handler).
# --------------------------------------------------------------------------

def _on_snapshot(data: bytes):
    try:
        payload = json.loads(data.decode())
    except (ValueError, UnicodeDecodeError):
        return
    global latest_snapshot
    latest_snapshot = payload
    merge_histogram(payload)


def _uds_reader(loop, stop):
    """Plain-socket UDS datagram reader (loop-agnostic: works under uvloop)."""
    try:
        os.unlink(SOCKET_PATH)
    except OSError:
        pass
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        sock.bind(SOCKET_PATH)
        sock.settimeout(0.5)
        print(f"dashboard: reading live snapshots from {SOCKET_PATH}",
              flush=True)
    except OSError as exc:
        print(f"dashboard: WARNING: cannot bind {SOCKET_PATH}: {exc}; "
              "live data unavailable (historical queries still work)",
              flush=True)
        return
    while not stop.is_set():
        try:
            data, _ = sock.recvfrom(1 << 20)
        except socket.timeout:
            continue
        except OSError:
            break
        loop.call_soon_threadsafe(_on_snapshot, data)


# --------------------------------------------------------------------------
# WebSocket: 10 Hz live broadcast.
# --------------------------------------------------------------------------

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_text(ws_payload())
            # Ignore client messages (e.g. keepalives); we push at 10 Hz.
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.01)
            except (asyncio.TimeoutError, WebSocketDisconnect):
                pass
            await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        return


# --------------------------------------------------------------------------
# REST: historical queries over DuckDB (pre-aggregated, pushdown).
# --------------------------------------------------------------------------

def _con():
    return duckdb.connect()


def _time_params(query):
    from_ts = query.get("from")
    to_ts = query.get("to")
    clause, params = "", []
    if from_ts is not None:
        clause += "recv_ts_ns >= to_timestamp(?)"
        params.append(float(from_ts))
    if to_ts is not None:
        clause += (" AND " if clause else "") + "recv_ts_ns < to_timestamp(?)"
        params.append(float(to_ts))
    return (" WHERE " + clause) if clause else "", params


def _rows(con, sql, params):
    return con.execute(sql, params).fetchall()


@app.get("/api/rate")
def api_rate(from_: str | None = None, to: str | None = None,
             bucket: int = 1):
    con = _con()
    clause, params = _time_params({"from": from_, "to": to})
    rows = _rows(con, f"""
        SELECT time_bucket(INTERVAL '{int(bucket)} second', recv_ts_ns) AS t,
               count(*) AS msgs
        FROM read_parquet('{ARCHIVE}/book/**/*.parquet', hive_partitioning=true)
        {clause} GROUP BY t ORDER BY t
    """, params)
    return JSONResponse([[str(r[0]), int(r[1])] for r in rows])


@app.get("/api/top_symbols")
def api_top_symbols(n: int = 10, from_: str | None = None,
                   to: str | None = None):
    con = _con()
    clause, params = _time_params({"from": from_, "to": to})
    rows = _rows(con, f"""
        SELECT symbol, count(*) AS updates
        FROM read_parquet('{ARCHIVE}/book/**/*.parquet', hive_partitioning=true)
        {clause} GROUP BY symbol ORDER BY updates DESC LIMIT {int(n)}
    """, params)
    return JSONResponse([[r[0], int(r[1])] for r in rows])


@app.get("/api/depth")
def api_depth(symbol: str, from_: str | None = None, to: str | None = None):
    con = _con()
    clause = " WHERE symbol = ?"
    params = [symbol]
    if from_ is not None:
        clause += " AND sec >= to_timestamp(?)"
        params.append(float(from_))
    if to is not None:
        clause += " AND sec < to_timestamp(?)"
        params.append(float(to))
    rows = _rows(con, f"""
        SELECT sec, best_bid, best_ask, spread, bid_depth, ask_depth
        FROM (
            SELECT sec,
                   max(CASE WHEN side='B' THEN price_ticks END) AS best_bid,
                   min(CASE WHEN side='A' THEN price_ticks END) AS best_ask,
                   sum(CASE WHEN side='B' THEN qty ELSE 0 END) AS bid_depth,
                   sum(CASE WHEN side='A' THEN qty ELSE 0 END) AS ask_depth
            FROM read_parquet('{ARCHIVE}/depth/*.parquet')
            {clause} GROUP BY sec
        ) ORDER BY sec
    """, params)
    return JSONResponse([
        [str(r[0]), int(r[1] or 0), int(r[2] or 0),
         int(r[2] or 0) - int(r[1] or 0), int(r[3]), int(r[4])]
        for r in rows
    ])


@app.get("/api/latency")
def api_latency(from_: str | None = None, to: str | None = None):
    con = _con()
    clause = ""
    params = []
    if from_ is not None:
        clause += "sec >= to_timestamp(?)"
        params.append(float(from_))
    if to is not None:
        clause += (" AND " if clause else "") + "sec < to_timestamp(?)"
        params.append(float(to))
    if clause:
        clause = " WHERE " + clause
    rows = _rows(con, f"""
        SELECT time_bucket(INTERVAL '1 minute', sec) AS minute,
               round(avg(wtb_p50)), round(avg(wtb_p99)),
               round(max(wtb_p999)), round(max(wtb_p9999))
        FROM read_parquet('{ARCHIVE}/stats/*.parquet')
        {clause} GROUP BY minute ORDER BY minute
    """, params)
    return JSONResponse([[str(r[0]), *[int(v) for v in r[1:]]] for r in rows])


@app.get("/api/gaps")
def api_gaps(n: int = 200):
    con = _con()
    try:
        rows = _rows(con, f"""
            SELECT detected_ts_ns, healed, start, "end", missing
            FROM read_parquet('{ARCHIVE}/gaps/*.parquet')
            ORDER BY detected_ts_ns DESC LIMIT {int(n)}
        """)
    except Exception:
        return JSONResponse([])
    return JSONResponse([
        [str(r[0]), bool(r[1]), int(r[2]), int(r[3]), int(r[4])] for r in rows
    ])


@app.get("/api/health")
def health():
    return JSONResponse({"live": bool(latest_snapshot), "archive": ARCHIVE})


# --------------------------------------------------------------------------
# Static frontend (built with: cd tools/dashboard/frontend && npm run build).
# --------------------------------------------------------------------------

DIST = os.path.join(os.path.dirname(__file__), "frontend", "dist")


@app.get("/")
def index():
    index_path = os.path.join(DIST, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse(
        {"hint": "frontend not built; run `npm run build` in tools/dashboard/frontend"},
        status_code=404)


if os.path.isdir(DIST):
    app.mount("/", StaticFiles(directory=DIST, html=True), name="static")
