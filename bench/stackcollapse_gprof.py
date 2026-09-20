#!/usr/bin/env python3
"""Fold `gprof -b` call-graph output into FlameGraph folded-stack format.

Each function block in gprof's call graph lists its callers (parent lines)
before the `[idx] ... name [idx]` header and its callees (child lines) after.
Edges are weighted by the caller->callee call count, and each edge is emitted
as `ancestors;caller;callee <count>` so the resulting flamegraph shows the
call-volume hotspot paths (matching the flat profile's hot functions).

Usage: gprof -b <binary> gmon.out | python3 bench/stackcollapse_gprof.py
"""

from __future__ import annotations

import re
import sys

HEADER_RE = re.compile(r"^index % time\s+self\s+children\s+called\s+name$")
ENTRY_RE = re.compile(
    r"^\s*(?P<self>[\d.]+)\s+(?P<children>[\d.]+)\s+(?P<called>[\d]+|[\d]+/[\d]+)"
    r"\s+(?P<name>.*?)\s+\[(?P<idx>\d+)\]\s*$")
FUNC_RE = re.compile(
    r"^\[(?P<idx>\d+)\]\s+[\d.]+\s+[\d.]+\s+[\d.]+\s+[\d]+"
    r"\s+(?P<name>.*?)\s+\[\d+\]\s*$")
SPONT = "<spontaneous>"
SEP = re.compile(r"^-+$")


def main() -> None:
    lines = sys.stdin.read().splitlines()
    start = None
    for i, line in enumerate(lines):
        if HEADER_RE.match(line):
            start = i + 1
            break
    if start is None:
        print("error: gprof call-graph header not found", file=sys.stderr)
        sys.exit(2)

    funcs = {}          # idx -> name
    parents = []        # pending parent edges for the current function
    stack_cache = {}    # idx -> ancestor path (str)
    visiting = set()    # cycle guard (recursive call graphs)

    def stack_of(idx, depth=0):
        path = stack_cache.get(idx)
        if path is not None:
            return path
        if idx in visiting or depth > 200:
            return ""
        visiting.add(idx)
        best = ""
        for p_idx, _count in incoming.get(idx, []):
            if p_idx is None:
                continue
            p_path = stack_of(p_idx, depth + 1)
            joined = f"{p_path};{funcs[p_idx]}" if p_path else funcs[p_idx]
            if not best or len(joined) < len(best):
                best = joined
        visiting.discard(idx)
        stack_cache[idx] = best
        return best

    incoming = {}       # idx -> list of (parent_idx, count)
    out = []

    for line in lines[start:]:
        if SEP.match(line):
            continue
        m = FUNC_RE.match(line)
        if m:
            idx = int(m.group("idx"))
            name = m.group("name").strip()
            funcs[idx] = name
            # This function's parents are the previously seen parent lines.
            incoming.setdefault(idx, [])
            for p_idx, count in parents:
                incoming[idx].append((p_idx, count))
            parents = []
            continue
        m = ENTRY_RE.match(line)
        if m:
            name = m.group("name").strip()
            idx = int(m.group("idx"))
            funcs[idx] = name
            called = m.group("called")
            count = called.split("/")[0]  # calls from this caller
            if name == SPONT:
                parents.append((None, int(count)))
            else:
                parents.append((idx, int(count)))
            continue
        # Anything else is ignored (trailing summary lines etc).

    # Emit folded edges weighted by caller->callee call counts.
    for idx, edges in incoming.items():
        for p_idx, count in edges:
            callee = funcs.get(idx, str(idx))
            if p_idx is None:
                out.append((callee, count))
            else:
                caller = funcs.get(p_idx, str(p_idx))
                path = stack_of(p_idx)
                full = f"{path};{caller};{callee}" if path else f"{caller};{callee}"
                out.append((full, count))

    # Collapse duplicate paths.
    totals = {}
    for path, count in out:
        totals[path] = totals.get(path, 0) + count
    for path, count in sorted(totals.items(), key=lambda kv: -kv[1]):
        print(f"{path} {count}")


if __name__ == "__main__":
    main()
