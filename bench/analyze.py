#!/usr/bin/env python3
"""Aggregate a wiretap benchmark run into a Markdown report + ECharts plots.

For every cell x stage x percentile, the point estimate is the MEDIAN of the
repeats (never a single run); the 95% confidence interval is a bias-corrected
percentile bootstrap over the repeats' medians (10,000 resamples).

Outputs:
  bench/REPORT.md         Markdown tables (wire_to_book + all stages)
  bench/plots.html        self-contained ECharts page (per-config p50/p99/p99.9)
  bench/results/latest.json  machine-readable aggregation

Usage:
  python3 bench/analyze.py [--results bench/results/20260919-...] [--reps N]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

STAGES = ("wire_to_userspace", "queue_delay", "decode_time", "wire_to_book")
PERCENTILES = ("p50", "p90", "p99", "p99_9", "p99_99", "max")
HEADLINE = "wire_to_book"
BOOTSTRAP_RESAMPLES = 10000
SEED = 424242


def load_rep_summary(rep_dir: Path) -> dict:
    """Reads a rep's wiretap-latency.json (written by wiretap_recv)."""
    path = rep_dir / "wiretap-latency.json"
    if not path.exists():
        return {}
    with open(path) as f:
        data = json.load(f)
    out = {}
    for stage, stats in data.get("stages", {}).items():
        out[stage] = {k: float(stats.get(k, 0)) for k in ("count", "p50_ns", "p90_ns",
                                                          "p99_ns", "p99_9_ns",
                                                          "p99_99_ns", "max_ns")}
    summary = rep_dir / "summary.txt"
    if summary.exists():
        line = summary.read_text().strip()
        # "summary: 12.34s | packets rx N (...) | messages M | ring drops D | ..."
        try:
            msgs = int(line.split("messages ")[1].split(" ")[0])
            out["messages"] = msgs
        except (IndexError, ValueError):
            pass
    return out


def load_rep_throughput(rep_dir: Path, measure_s: float) -> float:
    data = load_rep_summary(rep_dir)
    msgs = data.get("messages", 0)
    return msgs / measure_s if measure_s > 0 else 0.0


def bootstrap_ci(values: list[float], percentile=50.0) -> tuple[float, float, float]:
    """Median point estimate + 95% CI of the median via percentile bootstrap."""
    if not values:
        return 0.0, 0.0, 0.0
    rng = random.Random(SEED)
    n = len(values)
    medians = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        sample.sort()
        medians.append(sample[n // 2])
    medians.sort()
    lo = medians[int(0.025 * len(medians))]
    hi = medians[int(0.975 * len(medians)) - 1]
    values_sorted = sorted(values)
    med = values_sorted[n // 2]
    return med, lo, hi


def fmt_ns(value: float) -> str:
    if value >= 1e6:
        return f"{value / 1e6:.1f}ms"
    if value >= 1e3:
        return f"{value / 1e3:.1f}us"
    return f"{value:.0f}ns"


def analyze(results_dir: Path, min_reps: int, out_report: Path, out_plots: Path,
            out_json: Path) -> dict:
    with open(results_dir / "cells.json") as f:
        meta = json.load(f)
    measure_s = float(meta.get("measure_s", 10))

    aggregation = {"measure_s": measure_s, "cells": []}
    for cell in meta["cells"]:
        cell_dir = results_dir / cell["id"]
        reps = [cell_dir / f"rep{i}" for i in range(1, cell["repeats"] + 1)]
        if len(reps) < min_reps:
            continue
        rep_data = [load_rep_summary(r) for r in reps]
        entry = {"id": cell["id"], **cell}
        entry["stages"] = {}
        for stage in STAGES:
            percs = {}
            for key, json_key in (("p50", "p50_ns"), ("p90", "p90_ns"),
                                  ("p99", "p99_ns"), ("p99_9", "p99_9_ns"),
                                  ("p99_99", "p99_99_ns"), ("max", "max_ns")):
                values = [d.get(stage, {}).get(json_key, 0) for d in rep_data]
                med, lo, hi = bootstrap_ci(values)
                percs[key] = {"median": med, "ci_low": lo, "ci_high": hi}
            counts = [d.get(stage, {}).get("count", 0) for d in rep_data]
            entry["stages"][stage] = {"percentiles": percs,
                                      "median_samples": sorted(counts)[len(counts) // 2]}
        thr = [load_rep_throughput(r, measure_s) for r in reps]
        med_thr, lo_thr, hi_thr = bootstrap_ci(thr)
        entry["msgs_per_sec"] = {"median": med_thr, "ci_low": lo_thr, "ci_high": hi_thr}
        aggregation["cells"].append(entry)

    aggregation["cells"].sort(key=lambda c: (c["mode"], c["batch"], not c["pinned"],
                                             c["rcvbuf"], c["rate"]))
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(out_json, "w") as f:
        json.dump(aggregation, f, indent=2)
    return aggregation


def cell_label(cell: dict) -> str:
    pin = "pin" if cell["pinned"] else "nopin"
    rbuf = "64MB" if cell["rcvbuf"] else "def"
    return (f"{cell['mode']} b{cell['batch']} {pin} {rbuf} "
            f"{int(cell['rate'] / 1000)}k")


def write_markdown(agg: dict, out: Path):
    lines = []
    lines.append("# WireTap benchmark report\n")
    lines.append(f"Point estimates are medians across repeats; intervals are "
                 f"95% bootstrap CIs of the median "
                 f"({BOOTSTRAP_RESAMPLES} resamples). Generated by "
                 f"`bench/analyze.py` from `bench/run_bench.sh`.\n")
    lines.append("## wire_to_book (headline)\n")
    lines.append("| config | msgs/s (median) | p50 | p99 | p99.9 | p99.99 | max |")
    lines.append("|---|---|---|---|---|---|---|")
    for cell in agg["cells"]:
        s = cell["stages"].get(HEADLINE, {})
        p = s.get("percentiles", {})
        thr = cell["msgs_per_sec"]
        lines.append(
            f"| {cell_label(cell)} "
            f"| {thr['median'] / 1e6:.2f}M "
            f"| {fmt_ns(p.get('p50', {}).get('median', 0))} "
            f"| {fmt_ns(p.get('p99', {}).get('median', 0))} "
            f"| {fmt_ns(p.get('p99_9', {}).get('median', 0))} "
            f"| {fmt_ns(p.get('p99_99', {}).get('median', 0))} "
            f"| {fmt_ns(p.get('max', {}).get('median', 0))} |")
    lines.append("")
    lines.append("## all stages (median ns; [95% CI])\n")
    for stage in STAGES:
        lines.append(f"### {stage}\n")
        lines.append("| config | p50 | p99 | p99.9 |")
        lines.append("|---|---|---|---|")
        for cell in agg["cells"]:
            p = cell["stages"].get(stage, {}).get("percentiles", {})
            lines.append(
                f"| {cell_label(cell)} "
                f"| {p['p50']['median']:.0f} "
                f"[{p['p50']['ci_low']:.0f}-{p['p50']['ci_high']:.0f}] "
                f"| {p['p99']['median']:.0f} "
                f"[{p['p99']['ci_low']:.0f}-{p['p99']['ci_high']:.0f}] "
                f"| {p['p99_9']['median']:.0f} "
                f"[{p['p99_9']['ci_low']:.0f}-{p['p99_9']['ci_high']:.0f}] |")
        lines.append("")
    out.write_text("\n".join(lines))


def write_plots(agg: dict, out: Path):
    configs = [cell_label(c) for c in agg["cells"]]
    series = []
    colors = {"p50": "#3fb950", "p99": "#d29922", "p99_9": "#f85149"}
    for key in ("p50", "p99", "p99_9"):
        series.append({
            "name": key,
            "type": "bar",
            "data": [c["stages"][HEADLINE]["percentiles"][key]["median"]
                     for c in agg["cells"]],
            "itemStyle": {"color": colors[key]},
        })
    chart = {
        "title": {"text": "wire_to_book latency per configuration (median of repeats)",
                  "textStyle": {"color": "#e6edf3"}},
        "tooltip": {"trigger": "axis"},
        "legend": {"textStyle": {"color": "#e6edf3"}},
        "grid": {"left": 80, "right": 20, "bottom": 160, "top": 40},
        "xAxis": {"type": "category", "data": configs,
                  "axisLabel": {"rotate": 45, "color": "#8b949e"}},
        "yAxis": {"type": "log", "name": "ns", "nameTextStyle": {"color": "#8b949e"},
                  "axisLabel": {"color": "#8b949e"}},
        "series": series,
        "backgroundColor": "#0d1117",
    }
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>wiretap benchmark</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js"></script>
</head><body style="margin:0;background:#0d1117">
<div id="chart" style="width:100vw;height:100vh"></div>
<script>
const data = {json.dumps(chart)};
const c = echarts.init(document.getElementById('chart'));
c.setOption(data);
window.addEventListener('resize', () => c.resize());
</script></body></html>
"""
    out.write_text(html)


def main(argv=None):
    p = argparse.ArgumentParser(description="Aggregate wiretap benchmark results.")
    p.add_argument("--results", default=None,
                   help="bench/results/<run> dir (default: most recent)")
    p.add_argument("--reps", type=int, default=3,
                   help="minimum repeats a cell needs to be included")
    p.add_argument("--report", default="bench/REPORT.md")
    p.add_argument("--plots", default="bench/plots.html")
    p.add_argument("--json-out", default="bench/results/latest.json")
    args = p.parse_args(argv)

    if args.results:
        results_dir = Path(args.results)
    else:
        parent = Path("bench/results")
        runs = [d for d in parent.iterdir() if d.is_dir()] if parent.exists() else []
        if not runs:
            print("no benchmark runs found; run bench/run_bench.sh first", file=sys.stderr)
            return 1
        results_dir = max(runs, key=lambda d: d.stat().st_mtime)
    print(f"analyzing {results_dir}")

    agg = analyze(results_dir, args.reps, Path(args.report), Path(args.plots),
                  Path(args.json_out))
    write_markdown(agg, Path(args.report))
    write_plots(agg, Path(args.plots))
    print(f"cells: {len(agg['cells'])}")
    print(f"report: {args.report}")
    print(f"plots:  {args.plots}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
