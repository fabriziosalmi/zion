#!/usr/bin/env python3
"""Compare two results of run.py.

    python3 benchmarks/regress/compare.py base.json new.json [--tolerance 5]

For every scenario and metric it prints the two medians, the change, and a verdict.
A change counts only when it is larger than both the tolerance (default 5 %) and the
noise of the two sessions (three times the larger spread, as a share of the median),
so a verdict is never a difference the harness itself produces. Exit status 1 when a
scenario got worse in CPU per request or in throughput (`--judge cpu`: in CPU per request).

`rps` is only a verdict when both sessions kept the server's cores busy (above 80 %):
otherwise the load generator was the limit and the number is not about zion; it is
shown, marked, and not judged. `cpu_us_per_req` is always judged.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# metric -> (label, higher is better, judged for the exit status, judged only when saturated)
METRICS = {
    "cpu_us_per_req": ("cpu us/req", False, True, False),
    "rps": ("req/s", True, True, True),
    "mean_ms": ("mean ms", False, False, True),
}
SATURATED_PCT = 80.0
MAD_TO_SIGMA = 1.4826
SIGMAS = 3.0
NOISE_FLOOR_PCT = 1.0


def verdict(base: dict, new: dict, higher_is_better: bool, tolerance: float) -> tuple[float, float, str]:
    """(change %, threshold %, 'worse' | 'better' | 'same')."""
    change = 100.0 * (new["median"] - base["median"]) / base["median"]
    noise = max(
        100.0 * SIGMAS * MAD_TO_SIGMA * base["mad"] / base["median"],
        100.0 * SIGMAS * MAD_TO_SIGMA * new["mad"] / new["median"],
        NOISE_FLOOR_PCT,
    )
    threshold = max(tolerance, noise)
    if abs(change) <= threshold:
        return change, threshold, "same"
    improved = change > 0 if higher_is_better else change < 0
    return change, threshold, "better" if improved else "worse"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("base", type=Path)
    p.add_argument("new", type=Path)
    p.add_argument("--tolerance", type=float, default=5.0, help="percent (default 5)")
    p.add_argument("--judge", choices=("all", "cpu"), default="all",
                   help="what sets the exit status: CPU per request and throughput (default), or CPU "
                        "per request alone (for a machine shared with other jobs, where throughput "
                        "says more about the neighbours than about zion)")
    args = p.parse_args()
    base, new = (json.loads(f.read_text()) for f in (args.base, args.new))

    for side, doc in (("base", base), ("new", new)):
        m = doc["meta"]
        print(f"{side}: {m['zion']} [{m.get('label', '')}] on {m['host']}, {m['cpu']}, "
              f"{m['trials']} trials of {m['duration_s']} s, {m['date']}")
    if base["meta"]["host"] != new["meta"]["host"] or base["meta"]["cpu"] != new["meta"]["cpu"]:
        print("WARNING: the two results come from different machines; the comparison is not valid")
    if base["meta"]["pinned"] != new["meta"]["pinned"]:
        print("WARNING: one result was pinned to CPUs and the other not")
    print()

    worse = False
    shared = [s for s in base["scenarios"] if s in new["scenarios"]]
    for name in shared:
        b, n = base["scenarios"][name], new["scenarios"][name]
        saturated = (min(b["summary"]["server_cpu_pct"]["median"],
                         n["summary"]["server_cpu_pct"]["median"]) >= SATURATED_PCT)
        print(name)
        for key, (label, higher, judged, needs_sat) in METRICS.items():
            bs, ns = b["summary"][key], n["summary"][key]
            change, threshold, v = verdict(bs, ns, higher, args.tolerance)
            note = ""
            if needs_sat and not saturated:
                v, note = "not judged", "  (server cores below 80 %: the load generator was the limit)"
            elif v == "worse" and judged and (args.judge == "all" or key == "cpu_us_per_req"):
                worse = True
            print(f"  {label:11} {bs['median']:>12,.1f} -> {ns['median']:>12,.1f}   {change:+6.1f} %"
                  f"   (beyond {threshold:.1f} %)   {v}{note}")
        rss_b, rss_n = b["rss_hwm_mib"], n["rss_hwm_mib"]
        print(f"  {'rss MiB':11} {rss_b:>12,.0f} -> {rss_n:>12,.0f}   {100.0 * (rss_n - rss_b) / max(rss_b, 1):+6.1f} %   (information)")
    missing = sorted(set(base["scenarios"]) ^ set(new["scenarios"]))
    if missing:
        print(f"\nnot in both results, skipped: {', '.join(missing)}")
    print("\nRESULT:", "REGRESSION" if worse else "no regression beyond the noise")
    return 1 if worse else 0


if __name__ == "__main__":
    sys.exit(main())
