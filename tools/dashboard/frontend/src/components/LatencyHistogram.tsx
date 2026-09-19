import { useMemo } from "react";
import type { EChartsOption } from "echarts";
import { Chart } from "./Chart";
import type { HistogramPayload } from "../types";

// Renders the FULL histogram distribution (log-x buckets), not a
// downsampled mean: tail shape is the point of this project.
export function LatencyHistogram({ histogram }: { histogram: HistogramPayload | null }) {
  const option = useMemo<EChartsOption>(() => {
    const buckets = histogram?.buckets ?? [];
    const data = buckets.map(([value, count]) => [value, count]);
    const markers = [];
    if (histogram && histogram.count > 0) {
      for (const [label, value] of [
        ["p50", histogram.p50],
        ["p99", histogram.p99],
        ["p99.9", histogram.p99_9],
      ] as [string, number][]) {
        if (value > 0) {
          markers.push({
            name: label,
            xAxis: value,
            lineStyle: { color: label === "p99.9" ? "#f85149" : "#d29922", width: 1.5 },
            label: { formatter: label, color: "#8b949e", fontSize: 10 },
          });
        }
      }
    }
    return {
      backgroundColor: "transparent",
      grid: { left: 60, right: 16, top: 24, bottom: 40 },
      xAxis: {
        type: "log",
        name: "wire_to_book (ns)",
        min: 1,
        nameTextStyle: { color: "#8b949e" },
        axisLabel: { color: "#8b949e" },
      },
      yAxis: { type: "value", name: "count", nameTextStyle: { color: "#8b949e" }, axisLabel: { color: "#8b949e" } },
      tooltip: {
        trigger: "axis",
        formatter: (params: unknown) => {
          const p = (params as { data: [number, number] }[])[0];
          if (!p) return "";
          const [value, count] = p.data;
          return `${value.toLocaleString()} ns<br/>${count.toLocaleString()} samples`;
        },
      },
      series: [
        {
          name: "wire_to_book",
          type: "bar",
          data,
          barWidth: "70%",
          itemStyle: { color: "#58a6ff" },
        },
      ],
      markLine: markers.length ? { silent: true, symbol: "none", data: markers } : undefined,
    };
  }, [histogram]);

  const count = histogram?.count ?? 0;
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ fontSize: 11, color: "#8b949e", marginBottom: 2 }}>
        full HdrHistogram distribution · {count.toLocaleString()} samples ·
        p50={histogram?.p50 ?? 0}ns p99={histogram?.p99 ?? 0}ns p99.9={histogram?.p99_9 ?? 0}ns
      </div>
      <div className="body">
        <Chart option={option} />
      </div>
    </div>
  );
}
