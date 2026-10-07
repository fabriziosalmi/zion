#!/usr/bin/env python3
"""Offline tests for run.py's validity gate and statistics.

    python3 benchmarks/regress/test_run.py

`parse_h2load` is what decides that a trial is a measurement and not the benchmark of
an error path, so each way a trial can be invalid is pinned here against a real h2load
output (nghttp2 1.59, captured on the CI box).
"""

import importlib.util
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("regress_run", HERE / "run.py")
run = importlib.util.module_from_spec(_spec)
sys.modules["regress_run"] = run
_spec.loader.exec_module(run)

SAMPLE = """\
starting benchmark...
TLS Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Application protocol: h2

finished in 1.00s, 41449.00 req/s, 42.88MB/s
requests: 41449 total, 41609 started, 41449 done, 41449 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 41449 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 42.88MB (44957722) total, 1.69MB (1766984) headers (space savings 90.15%), 40.48MB (42443776) data
                     min         max         mean         sd        +/- sd
time for request:       58us      9.58ms      3.79ms      1.65ms    65.92%
time for connect:     1.96ms      6.51ms      4.24ms      1.44ms    62.50%
"""


def invalid(text: str) -> str:
    try:
        run.parse_h2load(text)
    except RuntimeError as e:
        return str(e)
    raise AssertionError("an invalid trial was accepted")


def test_a_real_output_is_read():
    r = run.parse_h2load(SAMPLE)
    assert r["requests"] == 41449 and r["rps"] == 41449.0
    assert abs(r["mean_ms"] - 3.79) < 1e-9 and abs(r["max_ms"] - 9.58) < 1e-9


def test_latency_units_are_converted_to_milliseconds():
    us = SAMPLE.replace("58us      9.58ms      3.79ms", "58us      9580us      900us")
    assert abs(run.parse_h2load(us)["mean_ms"] - 0.9) < 1e-9
    assert abs(run.parse_h2load(us)["max_ms"] - 9.58) < 1e-9
    s = SAMPLE.replace("58us      9.58ms      3.79ms", "58us      2.00s      1.50s")
    assert run.parse_h2load(s)["mean_ms"] == 1500.0 and run.parse_h2load(s)["max_ms"] == 2000.0


def test_a_duration_in_milliseconds_is_read():
    r = run.parse_h2load(SAMPLE.replace("finished in 1.00s, 41449.00", "finished in 950.35ms, 41449.00"))
    assert r["rps"] == 41449.0


def test_every_kind_of_failure_invalidates_the_trial():
    ok = "41449 failed" not in SAMPLE
    assert ok
    cases = {
        "failed": ("0 failed, 0 errored, 0 timeout", "3 failed, 0 errored, 0 timeout"),
        "errored": ("0 failed, 0 errored, 0 timeout", "0 failed, 2 errored, 0 timeout"),
        "timeout": ("0 failed, 0 errored, 0 timeout", "0 failed, 0 errored, 1 timeout"),
        "3xx": ("41449 2xx, 0 3xx, 0 4xx, 0 5xx", "41448 2xx, 1 3xx, 0 4xx, 0 5xx"),
        "4xx": ("41449 2xx, 0 3xx, 0 4xx, 0 5xx", "41448 2xx, 0 3xx, 1 4xx, 0 5xx"),
        "5xx": ("41449 2xx, 0 3xx, 0 4xx, 0 5xx", "41447 2xx, 0 3xx, 0 4xx, 2 5xx"),
        "2xx short of done": ("41449 2xx, 0 3xx, 0 4xx, 0 5xx", "41448 2xx, 0 3xx, 0 4xx, 0 5xx"),
    }
    for name, (old, new) in cases.items():
        assert old in SAMPLE, name
        assert "not a valid trial" in invalid(SAMPLE.replace(old, new)), name


def test_an_error_status_invalidates_even_when_every_request_also_got_a_2xx():
    # Streams that finished with an error while others were still open: 2xx is not short of
    # `done`, so only the status counters themselves can refuse this trial.
    for old, new, name in (("0 3xx, 0 4xx, 0 5xx", "2 3xx, 0 4xx, 0 5xx", "3xx"),
                           ("0 3xx, 0 4xx, 0 5xx", "0 3xx, 2 4xx, 0 5xx", "4xx"),
                           ("0 3xx, 0 4xx, 0 5xx", "0 3xx, 0 4xx, 2 5xx", "5xx")):
        assert old in SAMPLE
        assert "not a valid trial" in invalid(SAMPLE.replace(old, new)), name


def test_no_requests_is_not_a_trial():
    zero = SAMPLE.replace("41449 total, 41609 started, 41449 done, 41449 succeeded",
                          "0 total, 0 started, 0 done, 0 succeeded").replace(
        "41449 2xx", "0 2xx")
    assert "not a valid trial" in invalid(zero)


def test_streams_still_open_at_the_end_are_not_an_error():
    # Large bodies: responses whose headers arrived are counted as 2xx before they are done.
    text = SAMPLE.replace("41449 2xx, 0 3xx", "41470 2xx, 0 3xx")
    assert run.parse_h2load(text)["requests"] == 41449


def test_output_that_is_not_h2load_is_refused_not_guessed():
    assert "not understood" in invalid("Segmentation fault")
    assert "not understood" in invalid(SAMPLE.replace("status codes:", "codes:"))
    assert "not understood" in invalid(SAMPLE.replace("time for request:", "time of request:"))


def test_the_spread_is_the_median_absolute_deviation():
    assert run.mad([10.0, 10.0, 10.0]) == 0.0
    assert run.mad([1.0, 2.0, 3.0, 4.0, 100.0]) == 1.0  # one outlier does not move it
    assert run.mad([1.0, 2.0, 3.0, 4.0]) == statistics.median([1.5, 0.5, 0.5, 1.5])


def test_the_summary_has_median_extremes_and_spread_for_each_metric():
    trials = [dict(rps=r, cpu_us_per_req=c, mean_ms=m, server_cpu_pct=p)
              for r, c, m, p in ((100.0, 10.0, 1.0, 90.0), (120.0, 12.0, 1.2, 95.0),
                                 (110.0, 11.0, 1.1, 99.0))]
    s = run.summarise(trials)
    assert set(s) == {"rps", "cpu_us_per_req", "mean_ms", "server_cpu_pct"}
    assert s["rps"] == dict(median=110.0, min=100.0, max=120.0, mad=10.0)
    assert s["cpu_us_per_req"]["median"] == 11.0 and s["server_cpu_pct"]["max"] == 99.0
    # skewed: the median is not the mean
    skew = [dict(rps=r, cpu_us_per_req=1.0, mean_ms=1.0, server_cpu_pct=90.0) for r in (100.0, 100.0, 130.0)]
    assert run.summarise(skew)["rps"]["median"] == 100.0


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(tests)} passed")
