import { useMemo, useState } from "react";
import { BookLadder } from "./components/BookLadder";
import { MessageRate } from "./components/MessageRate";
import { LatencyHistogram } from "./components/LatencyHistogram";
import { GapLog } from "./components/GapLog";
import { useLive } from "./useLive";

const WS_URL =
  (window.location.protocol === "https:" ? "wss://" : "ws://") +
  window.location.host +
  "/ws";

export default function App() {
  const { payload, connected } = useLive(WS_URL);
  const [symbol, setSymbol] = useState("SYM00000");

  const live = payload?.live ?? null;
  const histogram = payload?.histogram ?? null;

  const symbols = useMemo(() => {
    const syms = Object.keys(live?.books ?? {});
    if (syms.length === 0) return ["SYM00000"];
    return syms.sort();
  }, [live]);

  return (
    <>
      <div className="header">
        <span className="title">WIRETAP</span>
        <select value={symbol} onChange={(e) => setSymbol(e.target.value)}>
          {symbols.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <span className={`live-dot ${connected ? "" : "off"}`}>
          {connected ? "● live" : "○ offline"}
        </span>
        <span className="stat">
          msgs/s <b>{live?.stats?.messages.toLocaleString() ?? "—"}</b>
        </span>
        <span className="stat">
          wire→book p99 <b>{(live?.wire_to_book?.p99 ?? 0).toLocaleString()} ns</b>
        </span>
        <span className="stat">
          ring drops <b>{live?.ring_drops?.toLocaleString() ?? "—"}</b>
        </span>
      </div>
      <div className="grid">
        <div className="panel">
          <h2>order book · top 10 depth</h2>
          <div className="body">
            <BookLadder book={live?.books?.[symbol]} symbol={symbol} />
          </div>
        </div>
        <div className="panel">
          <h2>message rate</h2>
          <div className="body">
            <MessageRate live={live?.stats ?? null} />
          </div>
        </div>
        <div className="panel">
          <h2>wire→book latency · log-x</h2>
          <LatencyHistogram histogram={histogram} />
        </div>
        <div className="panel">
          <h2>gap / recovery log</h2>
          <div className="body">
            <GapLog gaps={live?.gaps ?? null} />
          </div>
        </div>
      </div>
    </>
  );
}
