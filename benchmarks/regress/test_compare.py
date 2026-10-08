#!/usr/bin/env python3
"""Offline tests for compare.py's verdicts: which differences it calls real.

    python3 benchmarks/regress/test_compare.py
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("compare", HERE / "compare.py")
cmp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cmp)


def stat(median, mad=0.5):
    return dict(median=median, mad=mad, min=median, max=median)


def test_a_change_inside_the_tolerance_is_not_a_result():
    base = stat(100.0)
    assert cmp.verdict(base, stat(104.9), False, 5.0)[2] == "same"
    assert cmp.verdict(base, stat(95.1), False, 5.0)[2] == "same"


def test_direction_depends_on_the_metric():
    base = stat(100.0)
    # lower is better (cpu, latency): up is worse
    assert cmp.verdict(base, stat(105.1), False, 5.0)[2] == "worse"
    assert cmp.verdict(base, stat(94.9), False, 5.0)[2] == "better"
    # higher is better (throughput): down is worse
    assert cmp.verdict(base, stat(94.9), True, 5.0)[2] == "worse"
    assert cmp.verdict(base, stat(105.1), True, 5.0)[2] == "better"


def test_a_noisy_result_needs_a_bigger_difference():
    base, noisy = stat(100.0), stat(100.0, mad=5.0)  # 3 sigma is about 22 %
    assert cmp.verdict(base, stat(120.0), False, 5.0)[2] == "worse"
    assert cmp.verdict(noisy, stat(120.0), False, 5.0)[2] == "same"
    assert cmp.verdict(noisy, stat(130.0), False, 5.0)[2] == "worse"
    # the noise of the second result counts too
    # (its own noise is relative to its own median: 3 sigma of mad 5 on 115 is 19 %)
    assert cmp.verdict(base, stat(115.0, mad=5.0), False, 5.0)[2] == "same"
    assert cmp.verdict(base, stat(125.0, mad=5.0), False, 5.0)[2] == "worse"


def test_a_change_exactly_at_the_threshold_is_not_a_result():
    change, threshold, v = cmp.verdict(stat(100.0, mad=0.0), stat(105.0, mad=0.0), False, 5.0)
    assert (change, threshold, v) == (5.0, 5.0, "same")


def test_the_tolerance_is_the_floor():
    change, threshold, _ = cmp.verdict(stat(100.0, mad=0.0), stat(100.0, mad=0.0), False, 5.0)
    assert (change, threshold) == (0.0, 5.0)
    assert cmp.verdict(stat(100.0, mad=0.0), stat(103.0, mad=0.0), False, 2.0)[2] == "worse"


def result(rps, cpu, busy=97.0, host="box"):
    s = {m: stat(v) for m, v in (("rps", rps), ("cpu_us_per_req", cpu), ("mean_ms", 4.0))}
    s["server_cpu_pct"] = stat(busy)
    return dict(
        meta=dict(zion="zion x", label="", host=host, cpu="cpu", trials=3, duration_s=1,
                  date="d", pinned=True),
        scenarios=dict(s1=dict(summary=s, rss_hwm_mib=40.0)),
    )


def run(base, new, *extra):
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for name, doc in (("base", base), ("new", new)):
            p = Path(d) / f"{name}.json"
            p.write_text(json.dumps(doc))
            paths.append(str(p))
        out = subprocess.run([sys.executable, str(HERE / "compare.py"), *paths, *extra],
                             capture_output=True, text=True)
        return out.returncode, out.stdout


def test_exit_status_follows_cpu_and_throughput():
    assert run(result(1000, 50), result(1000, 50))[0] == 0
    assert run(result(1000, 50), result(1000, 60))[0] == 1       # cpu per request up 20 %
    assert run(result(1000, 50), result(800, 50))[0] == 1        # throughput down 20 %
    assert run(result(1000, 50), result(1300, 40))[0] == 0       # better is not a failure


def test_throughput_is_not_judged_when_the_server_was_not_busy():
    code, out = run(result(1000, 50, busy=60.0), result(800, 50, busy=60.0))
    assert code == 0 and "not judged" in out
    # one busy result and one idle one: still not judged (both must have been saturated)
    code, out = run(result(1000, 50, busy=97.0), result(800, 50, busy=60.0))
    assert code == 0 and "not judged" in out
    # but CPU per request always is
    assert run(result(1000, 50, busy=60.0), result(1000, 60, busy=60.0))[0] == 1


def test_judging_cpu_alone_ignores_throughput():
    # a shared runner: throughput moves with the neighbours, CPU per request does not
    assert run(result(1000, 50), result(800, 50), "--judge", "cpu")[0] == 0
    assert run(result(1000, 50), result(1000, 60), "--judge", "cpu")[0] == 1
    # the verdict is still printed
    assert "worse" in run(result(1000, 50), result(800, 50), "--judge", "cpu")[1]


def test_two_machines_are_flagged():
    code, out = run(result(1000, 50), result(1000, 50, host="other"))
    assert "different machines" in out


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(tests)} passed")
