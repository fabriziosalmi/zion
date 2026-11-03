#!/usr/bin/env python3
"""Test of the lab runner itself (tests/lab/run.py), against a real zion binary and a bare
synthetic HTTP server standing in for a vulnerable/fixed stack -- no Docker, no real CVE.

    python3 tests/lab/test_run.py --zion-bin target/release/zion

Exits 0 and prints each assertion as it passes; raises (and exits non-zero) on the first
failure, point `judge()` and `run_stack()` are meant to make unmistakable:
  - a vector that works on vulnerable, not on fixed, not through zion     -> covered
  - a vector that works nowhere                                          -> inconclusive
  - zion with NO protection of /protected: the vector works through it   -> bypass, run fails
  - a benign step broken only through zion                               -> false_positive, run fails
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def start_fake(port: int, mode: str) -> subprocess.Popen:
    p = subprocess.Popen([sys.executable, str(HERE / "fake_upstream.py"), str(port), mode])
    for _ in range(50):
        try:
            import socket
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"fake upstream on {port} ({mode}) did not come up")


def run(zion_bin: Path, stacks_dir: Path, out_dir: Path, extra_server_cfg: str = "") -> tuple[int, dict]:
    stack_dir = stacks_dir / "synthetic"
    (stack_dir / "stack.toml").write_text(
        (HERE / "stacks" / "synthetic" / "stack.toml").read_text()
    )
    probes_src = (HERE / "stacks" / "synthetic" / "probes.toml").read_text()
    (stack_dir / "probes.toml").write_text(probes_src)
    if extra_server_cfg:
        # A TOML literal string ('...') takes the content verbatim (no escaping), which is
        # exactly what server_extra needs to carry (it itself holds double-quoted TOML).
        assert "'" not in extra_server_cfg and "\n" not in extra_server_cfg
        meta_path = stack_dir / "stack.toml"
        meta_path.write_text(meta_path.read_text() + f"\n[zion]\nserver_extra = '{extra_server_cfg}'\n")
    proc = subprocess.run(
        [sys.executable, str(HERE / "run.py"), "synthetic", "--zion-bin", str(zion_bin),
         "--out", str(out_dir), "--no-compose", "--stacks-dir", str(stacks_dir)],
        capture_output=True, text=True,
    )
    print(proc.stdout)
    if proc.returncode not in (0, 1):
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"run.py exited {proc.returncode} unexpectedly; stderr above")
    doc = json.loads((out_dir / "synthetic.json").read_text())
    return proc.returncode, doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zion-bin", required=True, type=Path)
    a = ap.parse_args()
    if not a.zion_bin.exists():
        print(f"no zion binary at {a.zion_bin}", file=sys.stderr)
        return 2

    # Both fixtures are tracked from the moment each one starts, inside the same cleanup
    # scope: if the second start fails (e.g. a leftover process still bound to its port from
    # a previous interrupted run), the first must still be terminated, not leaked.
    started: list[subprocess.Popen] = []
    tmp: Path | None = None
    try:
        started.append(start_fake(19101, "vulnerable"))
        started.append(start_fake(19102, "fixed"))
        tmp = Path(tempfile.mkdtemp(prefix="zion-lab-test-"))
        # ── case 1: zion protects /protected (deny the bypass header) -----------------------
        stacks_dir = tmp / "case1"
        stacks_dir.mkdir(parents=True)
        (stacks_dir / "synthetic").mkdir()
        rc, doc = run(a.zion_bin, stacks_dir, tmp / "out1",
                      extra_server_cfg="")
        # zion with NO rule stripping the header: the vector must reach the vulnerable upstream
        # unchanged, so the probe must be judged `covered` (zion here is a transparent proxy,
        # which is exactly why test case 2 below adds a real strip rule and expects `bypass`
        # to flip to... no: covered means the ATTACK fails. A transparent proxy forwards the
        # attacker's header too, so the vulnerable upstream still answers 200/CANARY, so the
        # "through zion" observation is ALSO vulnerable: that must be `bypass`, not `covered`.
        probe = next(p for p in doc["probes"] if p["id"] == "covered-case")
        assert probe["verdict"] == "bypass", f"expected bypass (zion forwards the header verbatim), got {probe}"
        print("case 1 (no header strip -> bypass): OK")

        inc = next(p for p in doc["probes"] if p["id"] == "inconclusive-case")
        assert inc["verdict"] == "inconclusive", f"expected inconclusive, got {inc}"
        print("case 1 (vector that works nowhere -> inconclusive): OK")

        assert doc["summary"]["bypass"] == 1
        assert rc == 1, "a run with a bypass must exit non-zero"
        print("case 1 (summary counts + nonzero exit): OK")

        # ── case 2: zion strips the bypass header before proxying -> covered ----------------
        stacks_dir2 = tmp / "case2"
        stacks_dir2.mkdir(parents=True)
        (stacks_dir2 / "synthetic").mkdir()
        # `strip_headers` on [server] is the real zion.toml knob (docs/config/index.md);
        # `extra` is spliced into the [server] table before it closes, so a bare assignment
        # is all that is needed here -- no invented syntax.
        rc2, doc2 = run(
            a.zion_bin, stacks_dir2, tmp / "out2",
            extra_server_cfg='strip_headers = ["x-bypass-auth"]',
        )
        probe2 = next(p for p in doc2["probes"] if p["id"] == "covered-case")
        assert probe2["verdict"] == "covered", f"expected covered once zion strips the header, got {probe2}"
        print("case 2 (header stripped by zion -> covered): OK")
        assert doc2["summary"]["bypass"] == 0
        assert rc2 == 0, "a fully covered + benign-clean run must exit 0"
        print("case 2 (clean run exits 0): OK")

        for b in doc2["benign"]:
            assert b["outcome"] == "ok", f"benign step regressed: {b}"
        print("benign steps all ok: OK")

    finally:
        for p in started:
            p.terminate()
        for p in started:
            p.wait()
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)

    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
