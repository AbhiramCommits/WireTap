import { useEffect, useState } from "react";
import { fetchGaps } from "../api";
import type { GapStats } from "../types";

export function GapLog({ gaps }: { gaps: GapStats | null }) {
  const [history, setHistory] = useState<unknown[][]>([]);

  useEffect(() => {
    fetchGaps(200).then(setHistory).catch(() => setHistory([]));
  }, []);

  const recent = gaps?.recent ?? [];
  return (
    <div className="scroll" style={{ height: "100%" }}>
      <div style={{ fontSize: 11, color: "#8b949e", marginBottom: 4 }}>
        detected <b>{gaps?.detected ?? 0}</b> · healed <b>{gaps?.healed ?? 0}</b> ·
        permanently lost <b>{gaps?.lost ?? 0}</b> · recovered packets{" "}
        <b>{gaps?.recovered ?? 0}</b>
      </div>
      {recent.length === 0 && history.length === 0 && <div>no gaps yet</div>}
      {[...recent].reverse().map((g, i) => (
        <div className="gap-row" key={`live-${i}`}>
          <span className={g.healed ? "healed" : "lost"}>
            {g.healed ? "healed" : "LOST"}
          </span>{" "}
          seq {g.start}-{g.end} ({g.missing} pkts, {Math.round(g.heal_ns / 1e6)} ms)
        </div>
      ))}
      {recent.length === 0 &&
        history.map((r, i) => (
          <div className="gap-row" key={`hist-${i}`}>
            <span className={r[1] ? "healed" : "lost"}>{r[1] ? "healed" : "LOST"}</span>{" "}
            seq {String(r[2])}-{String(r[3])} ({String(r[4])} pkts) @ {String(r[0])}
          </div>
        ))}
    </div>
  );
}
