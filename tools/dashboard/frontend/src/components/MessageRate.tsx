import { useEffect, useMemo, useState } from "react";
import type { EChartsOption } from "echarts";
import { Chart } from "./Chart";
import { fetchRate } from "../api";

interface Point {
  t: number; // seconds
  msgs: number;
}

export function MessageRate({ live }: { live: { sec: number; messages: number } | null }) {
  const [history, setHistory] = useState<Point[]>([]);
  const [livePoints, setLivePoints] = useState<Point[]>([]);
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    fetchRate(15)
      .then((rows) =>
        setHistory(rows.map(([t, msgs]) => ({ t: Date.parse(t) / 1000, msgs }))),
      )
      .catch(() => setLoadError(true));
  }, []);

  useEffect(() => {
    if (!live) return;
    setLivePoints((prev) => {
      const last = prev[prev.length - 1];
      if (last && last.t === live.sec) return prev;
      const next = [...prev, { t: live.sec, msgs: live.messages }];
      return next.slice(-900); // keep 15 min
    });
  }, [live]);

  const option = useMemo<EChartsOption>(() => {
    const series = history.length ? history : livePoints;
    const overlay = livePoints.length
      ? [{ name: "live", data: livePoints, color: "#58a6ff" }]
      : [];
    return {
      backgroundColor: "transparent",
      grid: { left: 60, right: 16, top: 20, bottom: 30 },
      xAxis: { type: "time", axisLabel: { color: "#8b949e" } },
      yAxis: { type: "value", name: "msgs/s", nameTextStyle: { color: "#8b949e" }, axisLabel: { color: "#8b949e" } },
      tooltip: { trigger: "axis" },
      series: [
        {
          name: "message rate",
          type: "line",
          showSymbol: false,
          data: series.map((p) => [p.t * 1000, p.msgs]),
          lineStyle: { color: "#3fb950" },
        },
        ...overlay.map((s) => ({
          name: s.name,
          type: "line" as const,
          showSymbol: false,
          data: s.data.map((p: Point) => [p.t * 1000, p.msgs]),
          lineStyle: { color: s.color, width: 2 },
        })),
      ],
    };
  }, [history, livePoints]);

  return loadError && !livePoints.length ? (
    <div>historical data unavailable (archive empty?)</div>
  ) : (
    <Chart option={option} />
  );
}
