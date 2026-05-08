#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Diff two criterion output trees and emit a markdown summary.

Criterion writes per-benchmark JSON under
`target/criterion/<group>/<bench>/new/estimates.json`. Each file holds the
median, mean, and slope estimates. We walk both trees, line them up by
relative path, and emit a markdown table of the percent change with a
threshold-based icon (✓ within band, ⚠️ regression, 🚀 improvement).

Used by `.github/workflows/bench.yml`. Stdlib-only — no pip install on CI.
"""

from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional


def load_estimates(root: Path) -> dict[str, float]:
    """Walk a criterion tree and return {bench_id: median_ns}.

    `bench_id` is the relative path from `root` up to the bench directory,
    e.g. `traceparent/valid/rfc_example`. Criterion's `estimates.json`
    records times in nanoseconds via `point_estimate`.
    """
    out: dict[str, float] = {}
    for est in root.rglob("new/estimates.json"):
        # estimates.json sits at <root>/<group>/<bench>/new/estimates.json
        bench_dir = est.parent.parent
        rel = bench_dir.relative_to(root).as_posix()
        # Skip criterion's report-aggregation directories.
        if rel.endswith("/report") or rel == "report":
            continue
        try:
            with est.open() as fh:
                data = json.load(fh)
            median = data.get("median", {}).get("point_estimate")
            if median is None:
                continue
            out[rel] = float(median)
        except (json.JSONDecodeError, OSError):
            continue
    return out


def fmt_ns(ns: float) -> str:
    if ns < 1_000:
        return f"{ns:.2f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} µs"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    return f"{ns / 1_000_000_000:.2f} s"


def icon(delta_pct: float, threshold: float) -> str:
    if abs(delta_pct) <= threshold:
        return "✓"
    return "⚠️" if delta_pct > 0 else "🚀"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--head", required=True, type=Path, help="head criterion tree")
    p.add_argument("--base", required=True, type=Path, help="base criterion tree")
    p.add_argument(
        "--threshold-pct",
        type=float,
        default=5.0,
        help="percent change considered noise; below this counts as no change",
    )
    p.add_argument("--out", type=Path, default=None, help="markdown output path")
    args = p.parse_args(argv)

    head = load_estimates(args.head)
    base = load_estimates(args.base)

    if not head:
        print(f"no criterion output under {args.head}", file=sys.stderr)
        return 1

    rows: list[tuple[str, Optional[float], float, Optional[float]]] = []
    for bench_id in sorted(set(head) | set(base)):
        h = head.get(bench_id)
        b = base.get(bench_id)
        if h is None or b is None:
            rows.append((bench_id, h, b if b is not None else 0.0, None))
            continue
        if b == 0:
            rows.append((bench_id, h, b, None))
            continue
        delta = (h - b) / b * 100.0
        rows.append((bench_id, h, b, delta))

    md: list[str] = []
    md.append("### Criterion delta — head vs master")
    md.append("")
    md.append("| Bench | Head | Master | Δ% |")
    md.append("|-------|------|--------|----|")
    regressions = 0
    improvements = 0
    for bench_id, h, b, delta in rows:
        if h is None:
            md.append(f"| `{bench_id}` | _missing_ | {fmt_ns(b)} | — |")
            continue
        if delta is None:
            md.append(f"| `{bench_id}` | {fmt_ns(h)} | _new_ | — |")
            continue
        sign = "+" if delta >= 0 else ""
        ic = icon(delta, args.threshold_pct)
        md.append(
            f"| `{bench_id}` | {fmt_ns(h)} | {fmt_ns(b)} | {ic} {sign}{delta:.1f}% |"
        )
        if abs(delta) > args.threshold_pct:
            if delta > 0:
                regressions += 1
            else:
                improvements += 1

    md.append("")
    md.append(
        f"_Summary: {regressions} regression(s), {improvements} improvement(s) outside ±{args.threshold_pct:.0f}%._"
    )
    md.append("")
    md.append(
        "Microbench numbers are signals, not gates. GitHub-hosted runners are noisy; reproduce locally before reacting to a single run."
    )
    out_text = "\n".join(md) + "\n"

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(out_text)
    else:
        sys.stdout.write(out_text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
