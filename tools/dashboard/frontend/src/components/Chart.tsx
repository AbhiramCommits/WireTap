import * as echarts from "echarts";
import { useEffect, useRef } from "react";

export function Chart({
  option,
  height,
}: {
  option: echarts.EChartsOption;
  height?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current);
    chartRef.current = chart;
    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
    };
  }, []);

  useEffect(() => {
    chartRef.current?.setOption(option, { notMerge: false });
  }, [option]);

  return <div ref={ref} style={{ width: "100%", height: height ?? "100%" }} />;
}
