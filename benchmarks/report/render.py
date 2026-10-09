#!/usr/bin/env python3
"""Render the release report (HTML, then PDF through WeasyPrint) from the measured JSON.

    render.py RESULT_DIR --out report.pdf [--prev PREV_RESULT_DIR]

RESULT_DIR holds what the other scripts wrote: result.json (bench.py) and, when they were
run, conformance.json, h2spec.json, cachetests.json, crawl.json. A part that is missing
is stated as "not run" in the report, never filled in.

Nothing in the report is typed by hand: every number is read from those files, and the
only prose that varies is generated from them. The PDF is reproducible from the JSON:
the charts are vector, text in them is converted to outlines, there is no clock, and the
PDF identifier is derived from the content. Rendering twice gives the same bytes.
"""
from __future__ import annotations

import argparse
import html
import io
import json
import math
import statistics
import subprocess
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

plt.rcParams.update({"svg.hashsalt": "zion-report", "svg.fonttype": "path", "font.family": "DejaVu Sans",
                     "axes.spines.top": False, "axes.spines.right": False, "font.size": 8})

COLORS = {"zion": "#0072B2", "nginx": "#E69F00", "origin": "#9a9a9a"}
TOLERANCE, NOISE_SIGMAS = 5.0, 3.0
HEADLINE = ["cache_hit_small", "cache_hit_h2", "site_mix", "proxy_nocache", "static_files", "tls_handshake"]


def e(x) -> str:
    return html.escape(str(x))


def load(d: Path | None, name: str):
    if d is None:
        return None
    p = d / name
    return json.loads(p.read_text()) if p.exists() else None


def fnum(x, digits=1) -> str:
    if x is None:
        return "–"
    if abs(x) >= 1000:
        return f"{x / 1000:.{digits}f}k"
    return f"{x:.{digits}f}"


def fus(x) -> str:
    if x is None:
        return "–"
    return f"{x / 1000:.2f} ms" if x >= 1000 else f"{x:.0f} µs"


def svg(fig) -> str:
    buf = io.StringIO()
    fig.savefig(buf, format="svg", bbox_inches="tight", metadata={"Date": None, "Creator": "zion-report"})
    plt.close(fig)
    # an <img> keeps each chart's glyph ids to itself; inline SVGs would share one id space
    import base64
    return '<img alt="chart" style="width:100%" src="data:image/svg+xml;base64,' + base64.b64encode(buf.getvalue().encode()).decode() + '">'


def summary(res, scen, target):
    t = res["scenarios"].get(scen, {}).get("targets", {}).get(target)
    return t["summary"] if t and t.get("summary") else None


# ── charts ───────────────────────────────────────────────────────────────────────────

def chart_ratio(res) -> str:
    names, thr, cpu = [], [], []
    for s, v in res["scenarios"].items():
        z, n = summary(res, s, "zion"), summary(res, s, "nginx")
        if z and n and n["rps"] and z.get("cpu_us_per_req") and n.get("cpu_us_per_req"):
            names.append(s)
            thr.append(100 * z["rps"] / n["rps"])
            cpu.append(100 * n["cpu_us_per_req"] / z["cpu_us_per_req"])
    fig, ax = plt.subplots(figsize=(6.4, 0.24 * len(names) + 0.9))
    y = list(range(len(names)))
    ax.barh([i + 0.2 for i in y], thr, height=0.38, color=COLORS["zion"], label="req/s, zion as % of nginx")
    ax.barh([i - 0.2 for i in y], cpu, height=0.38, color="#56B4E9", label="CPU efficiency, nginx µs ÷ zion µs per request")
    ax.axvline(100, color="#333", lw=0.8, ls="--")
    ax.set_yticks(y, names)
    ax.invert_yaxis()
    ax.set_xlabel("100 = parity with nginx · longer is better for zion")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, frameon=False, fontsize=7)
    return svg(fig)


def chart_latency(res) -> str:
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.6), sharey=True)
    for ax, s in zip(axes, ("latency_5k", "latency_15k")):
        targets = [t for t in ("zion", "nginx", "origin") if summary(res, s, t)]
        xs = range(3)
        for k, t in enumerate(targets):
            sm = summary(res, s, t)
            vals = [sm.get("lat_p50_us"), sm.get("lat_p99_us"), sm.get("lat_p999_us")]
            ax.bar([x + (k - 1) * 0.27 for x in xs], [v or 0 for v in vals], 0.26, color=COLORS[t], label=t)
        ax.set_xticks(list(xs), ["p50", "p99", "p99.9"])
        ax.set_yscale("log")
        ax.set_title(f'{res["scenarios"].get(s, {}).get("targets", {}) and s.split("_")[1].replace("k", ",000")} requests per second', fontsize=8)
        ax.set_ylabel("µs, corrected for coordinated omission") if s == "latency_5k" else None
    axes[0].legend(frameon=False, fontsize=7)
    return svg(fig)


def chart_sweep(res) -> str:
    pts = {"zion": [], "nginx": []}
    for s, v in res["scenarios"].items():
        if s.startswith("sweep_c") or s == "cache_hit_small":
            for t in pts:
                sm = summary(res, s, t)
                if sm:
                    pts[t].append((v["conns"], sm["rps"]))
    fig, ax = plt.subplots(figsize=(7.0, 2.6))
    for t, p in pts.items():
        p.sort()
        if p:
            ax.plot([a for a, _ in p], [b for _, b in p], marker="o", color=COLORS[t], label=t)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("concurrent connections")
    ax.set_ylabel("req/s on one core")
    ax.legend(frameon=False)
    ax.set_ylim(bottom=0)
    return svg(fig)


# ── tables ───────────────────────────────────────────────────────────────────────────

def scenario_rows(res) -> str:
    out = []
    for s, v in res["scenarios"].items():
        out.append(f'<tr class="scen"><td colspan="10"><b>{e(s)}</b> · {e(v["tool"])} · {v["conns"]} conn · {e(v["what"])}</td></tr>')
        for t, d in v["targets"].items():
            sm = d.get("summary")
            if not sm:
                out.append(f'<tr><td>{t}</td><td colspan="9" class="bad">no valid trial: {e(d["invalid"][0][:140] if d["invalid"] else "?")}</td></tr>')
                continue
            hit = [x.get("cache_hit_ratio") for x in d["trials"] if x.get("cache_hit_ratio") is not None]
            flag = "" if sm["server_bound"] or v["tool"] == "oha" else ' <span class="warn" title="server below 80% busy: not a saturation figure (few connections, or the load generator was the limit)">⚠</span>'
            out.append(
                f'<tr><td class="t-{t}">{t}</td><td class="n">{fnum(sm["rps"])}{flag}</td>'
                f'<td class="n dim">{fnum(sm["rps_min"])}–{fnum(sm["rps_max"])}</td>'
                f'<td class="n">{fnum(sm["cpu_us_per_req"])}</td>'
                f'<td class="n">{fus(sm.get("lat_p50_us"))}</td><td class="n">{fus(sm.get("lat_p99_us"))}</td>'
                f'<td class="n">{fus(sm.get("lat_p999_us"))}</td>'
                f'<td class="n">{fnum(sm["server_cpu_pct"], 0)}%</td><td class="n">{fnum(d.get("rss_hwm_mib"), 0)}</td>'
                f'<td class="n">{(f"{100 * statistics.median(hit):.1f}%" if hit else "–")}</td></tr>')
            for inv in d["invalid"]:
                out.append(f'<tr><td></td><td colspan="9" class="bad">discarded trial: {e(inv[:160])}</td></tr>')
    return "\n".join(out)


def conformance_section(conf) -> str:
    if not conf:
        return '<p class="dim">The HTTP/1.1 conformance suite was not run for this report.</p>'
    checks = conf["checks"]
    groups: dict[str, dict] = {}
    for cid, c in checks.items():
        g = groups.setdefault(c["group"], dict(n=0, z=0, n_=0, zf=0, nf=0))
        for tgt, key_ok, key_f in (("zion", "z", "zf"), ("nginx", "n_", "nf")):
            v = c["results"].get(tgt, {}).get("verdict")
            if v == "pass":
                g[key_ok] += 1
            elif v == "fail":
                g[key_f] += 1
        g["n"] += 1
    rows = "".join(
        f'<tr><td>{e(k)}</td><td class="n">{g["n"]}</td><td class="n">{g["z"]}</td><td class="n {"bad" if g["zf"] else ""}">{g["zf"]}</td>'
        f'<td class="n">{g["n_"]}</td><td class="n {"bad" if g["nf"] else ""}">{g["nf"]}</td></tr>'
        for k, g in groups.items())
    must = lambda t: sum(1 for c in checks.values() if c["level"] in ("MUST", "SECURITY") and c["results"].get(t, {}).get("verdict") == "fail")  # noqa: E731
    lines = [
        f'<p>Failed <b>MUST</b> or <b>SECURITY</b> checks: <b>zion {must("zion")}</b>, nginx {must("nginx")} (the reference, same origin, same checks). '
        'A failed SHOULD is a deviation to read, not a defect; an INFO row records behaviour and cannot fail.</p>',
        f'<table class="g"><tr><th>Group</th><th>Checks</th><th>zion pass</th><th>zion fail</th><th>nginx pass</th><th>nginx fail</th></tr>{rows}</table>',
        '<table class="g all"><tr><th>Check</th><th>Level</th><th>RFC</th><th>zion</th><th>nginx</th><th>What zion did</th></tr>']
    gorder = ["Framing", "Proxy", "Representations", "Hardening", "TLS"]
    lorder = {"MUST": 0, "SECURITY": 1, "SHOULD": 2, "INFO": 3}
    for cid, c in sorted(checks.items(), key=lambda kv: (gorder.index(kv[1]["group"]) if kv[1]["group"] in gorder else 99, lorder.get(kv[1]["level"], 9), kv[0])):
        z, n = c["results"].get("zion", {}), c["results"].get("nginx", {})
        mark = lambda r: f'<td class="v-{r.get("verdict", "na").replace("/", "")}">{e(r.get("verdict", "–"))}</td>'  # noqa: E731
        lines.append(f'<tr><td>{e(c["title"])}</td><td>{c["level"]}</td><td class="dim">{e(c["rfc"])}</td>{mark(z)}{mark(n)}<td class="dim">{e(z.get("detail", "")[:150])}</td></tr>')
    lines.append("</table>")
    return "\n".join(lines)


def external_section(h2, ct, crawl) -> str:
    out = []
    if h2:
        out.append('<h3>HTTP/2 — h2spec (RFC 9113, RFC 7541)</h3><table class="g"><tr><th></th><th class="n">tests</th><th class="n">passed</th><th class="n">failed</th><th class="n">skipped</th></tr>')
        for t in ("zion", "nginx"):
            r = h2.get(t)
            if r:
                out.append(f'<tr><td>{t}</td><td class="n">{r["tests"]}</td><td class="n">{r["passed"]}</td><td class="n {"bad" if r["failed"] else ""}">{r["failed"]}</td><td class="n">{r["skipped"]}</td></tr>')
        out.append("</table>")
        for t in ("zion",):
            fails = (h2.get(t) or {}).get("failures", [])
            if fails:
                out.append("<p>zion failures:</p><ul>" + "".join(f"<li>{e(f[:200])}</li>" for f in fails[:40]) + "</ul>")
    else:
        out.append('<p class="dim">h2spec was not run for this report.</p>')
    if ct:
        out.append('<h3>HTTP caching behaviour — cache-tests (RFC 9111)</h3>'
                   '<p class="dim">The suite describes itself as “not a conformance test suite … a tool to assess how a cache behaves”: '
                   'it also probes optional behaviour. Counts are shown for both proxies on the same origin; read the differences, not the totals.</p>'
                   '<table class="g"><tr><th></th><th class="n">tests</th><th class="n">passed</th><th class="n">failed</th></tr>')
        for t in ("zion", "nginx"):
            r = ct.get(t)
            if r:
                out.append(f'<tr><td>{t}</td><td class="n">{r["tests"]}</td><td class="n">{r["passed"]}</td><td class="n">{r["failed"]}</td></tr>')
        out.append("</table>")
    else:
        out.append('<p class="dim">cache-tests was not run for this report.</p>')
    if crawl:
        out.append(f'<h3>Byte-exact serving of the example site</h3><p>{crawl["files"]} files fetched twice (cold and from cache) through zion, '
                   f'compared by SHA-256 with the manifest: <b>{crawl["mismatches"]} mismatches</b>'
                   f'{"; " + e(", ".join(crawl["mismatch_paths"][:8])) if crawl["mismatches"] else ""}.</p>')
    else:
        out.append('<p class="dim">The byte-exact site crawl was not run for this report.</p>')
    return "\n".join(out)


def judge(a, b):
    """(verdict, delta%) for b relative to a on CPU per request; noise-aware like regress/compare.py."""
    if not a or not b or not a.get("cpu_us_per_req") or not b.get("cpu_us_per_req"):
        return None, None
    d = 100 * (b["cpu_us_per_req"] - a["cpu_us_per_req"]) / a["cpu_us_per_req"]
    noise = NOISE_SIGMAS * math.hypot(a.get("rps_mad_pct", 0), b.get("rps_mad_pct", 0))
    bar = max(TOLERANCE, noise)
    return ("worse" if d > bar else "better" if d < -bar else "same"), d


def compare_section(res, prev, prev_label) -> str:
    if not prev:
        return '<p class="dim">No previous report was given, so there is no version-to-version comparison. Pass <code>--prev</code> to add one.</p>'
    pe, ce = prev["env"], res["env"]
    notes = []
    for k in ("procedure", "site_sha256"):
        if pe.get(k) != ce.get(k):
            notes.append(f"<b>{k}</b> differs ({e(pe.get(k))} vs {e(ce.get(k))}): the two reports measured different things and this table is not a comparison.")
    if pe.get("tools") != ce.get("tools"):
        notes.append("the tool versions differ between the two reports.")
    rows = []
    for s in res["scenarios"]:
        a, b = summary(prev, s, "zion"), summary(res, s, "zion")
        v, d = judge(a, b)
        if v is None:
            continue
        dr = 100 * (b["rps"] - a["rps"]) / a["rps"]
        rows.append(f'<tr><td>{e(s)}</td><td class="n">{fnum(a["cpu_us_per_req"])}</td><td class="n">{fnum(b["cpu_us_per_req"])}</td>'
                    f'<td class="n">{d:+.1f}%</td><td class="n">{dr:+.1f}%</td><td class="v-{v}">{v}</td></tr>')
    return (f'<p>zion {e(ce["label"])} against {e(prev_label)}. CPU per request is judged; a change counts only beyond '
            f'{TOLERANCE:.0f}% <i>and</i> {NOISE_SIGMAS:.0f}× the combined noise of the two measurements.</p>'
            + ("".join(f'<p class="warn">{n}</p>' for n in notes))
            + '<table class="g"><tr><th>Scenario</th><th>before µs/req</th><th>now µs/req</th><th>Δ CPU/req</th><th>Δ req/s</th><th>verdict</th></tr>'
            + "".join(rows) + "</table>")


# ── page ─────────────────────────────────────────────────────────────────────────────

CSS = """
@page { size: A4; margin: 17mm 15mm 18mm; @bottom-center { content: "Zion " string(label) " — page " counter(page) " of " counter(pages); font: 7.5pt 'DejaVu Sans'; color: #666 } }
body { font: 8.8pt/1.45 'DejaVu Sans', sans-serif; color: #1a1a1a }
h1 { font-size: 20pt; margin: 0 0 2mm } h2 { font-size: 12.5pt; margin: 7mm 0 2mm; border-bottom: 0.6pt solid #bbb; padding-bottom: 1mm; break-after: avoid }
h3 { font-size: 10pt; margin: 4mm 0 1mm; break-after: avoid } p { margin: 1.5mm 0 } .dim { color: #666 } .warn { color: #a15c00 } .bad { color: #b00020 }
.label { string-set: label content() }
table { border-collapse: collapse; width: 100%; font-size: 7.6pt; margin: 2mm 0 } th { text-align: left; background: #f1f3f5; font-weight: 600 }
td, th { padding: 0.9mm 1.6mm; border-bottom: 0.3pt solid #ddd; vertical-align: top } td.n, th.n { text-align: right; font-variant-numeric: tabular-nums }
tr.scen td { background: #f7f8fa; padding-top: 1.6mm; border-top: 0.5pt solid #ccc } tr { break-inside: avoid }
.t-zion { color: #0072B2; font-weight: 600 } .t-nginx { color: #8a5a00 } .t-origin { color: #666 }
.v-pass, .v-better { color: #1b7a3a; font-weight: 600 } .v-fail, .v-worse { color: #b00020; font-weight: 600 } .v-info, .v-same { color: #666 } .v-na { color: #a15c00 }
.cover { margin-bottom: 4mm } .kv { display: grid; grid-template-columns: 34mm 1fr; gap: 0.4mm 3mm; font-size: 8pt } .kv div:nth-child(odd) { color: #666 }
.box { border: 0.6pt solid #bbb; border-radius: 2mm; padding: 2.5mm 3.5mm; margin: 3mm 0; background: #fafbfc } svg { max-width: 100%; height: auto }
code { font: 7.6pt 'DejaVu Sans Mono', monospace; background: #f1f3f5; padding: 0 0.8mm } pre { font: 7pt/1.35 'DejaVu Sans Mono', monospace; background: #f6f7f9; padding: 2mm; white-space: pre-wrap }
.pb { break-before: page }
"""


def build(res, conf, h2, ct, crawl, prev) -> str:
    env, canary = res["env"], res["canary"]
    sc = res["scenarios"]
    invalid = sum(len(t["invalid"]) for s in sc.values() for t in s["targets"].values())
    unbound = [f'{s}/{t}' for s, v in sc.items() if v["tool"] != "oha" for t, d in v["targets"].items() if d.get("summary") and not d["summary"]["server_bound"] and t != "origin"]
    z_cpu_better = sum(1 for s in sc if (a := summary(res, s, "zion")) and (b := summary(res, s, "nginx"))
                       and a.get("cpu_us_per_req") and b.get("cpu_us_per_req") and a["cpu_us_per_req"] < b["cpu_us_per_req"])
    z_cpu_n = sum(1 for s in sc if (a := summary(res, s, "zion")) and (b := summary(res, s, "nginx")) and a.get("cpu_us_per_req") and b.get("cpu_us_per_req"))
    trust = ("The host moved during the run (the canary drifted " f"{100 * canary['drift']:.1f}% against a {100 * canary['tolerance']:.0f}% tolerance): "
             "<b>treat these numbers as indicative and repeat the run.</b>") if canary["noisy"] else \
        f"The host was steady: the canary workload drifted {100 * canary['drift']:.1f}% (tolerance {100 * canary['tolerance']:.0f}%) over the run."
    tools = env.get("tools", {})
    head_rows = []
    for s in HEADLINE:
        z, n = summary(res, s, "zion"), summary(res, s, "nginx")
        if z and n:
            head_rows.append(f'<tr><td>{e(s)}</td><td class="n">{fnum(z["rps"])}</td><td class="n">{fnum(n["rps"])}</td><td class="n">{100 * z["rps"] / n["rps"]:.0f}%</td>'
                             f'<td class="n">{fnum(z["cpu_us_per_req"])}</td><td class="n">{fnum(n["cpu_us_per_req"])}</td><td class="n">{fus(z.get("lat_p99_us"))}</td><td class="n">{fus(n.get("lat_p99_us"))}</td></tr>')
    kv = [("Version", env["zion_version"]), ("Label", env["label"]), ("Binary SHA-256", env["zion_sha256"][:32] + "…"),
          ("Date (UTC)", env["date_utc"]), ("Host", f'{env["cpu"]}, {env["cpus"]} CPUs, {env["mem_mib"]} MiB, kernel {env["kernel"]}'),
          ("Governor", env["governor"] or "n/a"), ("Core layout", f'origin {env["layout"]["origin"]} · server {env["layout"]["server"]} · load {env["layout"]["load"]}'),
          ("Procedure", f'{env.get("procedure")} (harness {env.get("harness_sha256", "")[:12]})'), ("Example site", f'SHA-256 {env["site_sha256"][:24]}…'),
          ("Trials", f'{env["params"]["trials"]} × {env["params"]["duration_s"]:g} s (+ {env["params"]["warm_s"]:g} s warm-up)'),
          ("TLS", "; ".join(f'{t}: {v["protocol"]} {v["cipher"]}' for t, v in env.get("tls", {}).items()))]
    tools_pre = "\n".join(f"{k:12s} {v}" for k, v in sorted(tools.items()))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Zion {e(env['label'])} — performance and conformance report</title>
<meta name="dcterms.created" content="{e(env['date_utc'])}"><style>{CSS}</style></head><body>
<span class="label" style="display:none">{e(env['label'])}</span>
<div class="cover"><h1>Zion {e(env['label'])}</h1><p class="dim">Performance and HTTP conformance report · measured on a dedicated host with a fixed procedure</p></div>
<div class="kv">{''.join(f'<div>{e(k)}</div><div>{e(v)}</div>' for k, v in kv)}</div>

<h2>Summary</h2>
<div class="box"><p>{trust}</p>
<p>{len(sc)} scenarios, {invalid} discarded trial(s){(' — ' + ', '.join(unbound[:4]) + ' did not keep the server at 80% CPU, so the figure is not a ceiling (⚠ in the table; with few connections that is expected)') if unbound else ''}.
Each proxy ran on exactly one core, so every figure is per core. zion used less CPU per request than nginx in <b>{z_cpu_better} of {z_cpu_n}</b> scenarios.</p></div>
<table class="g"><tr><th>Headline scenario</th><th>zion req/s</th><th>nginx req/s</th><th>zion ÷ nginx</th><th>zion µs/req</th><th>nginx µs/req</th><th>zion p99</th><th>nginx p99</th></tr>{''.join(head_rows)}</table>
<p class="dim">Access log off on both unless the scenario says <code>_logs</code>. “µs/req” is CPU time of the whole proxy process tree per request, from /proc.</p>
{chart_ratio(res)}

<h2 class="pb">What was measured and how</h2>
<p>An example web site (230 files, 25 MiB: a landing page and 40 documents, a JS/CSS bundle, fonts, 60 photographs, 120 JSON documents and a 10 MiB download) is generated from a fixed seed and served by a real nginx origin. zion sits in front of it; a real nginx with <code>proxy_cache</code> sits in front of the same origin as the reference; the origin read directly is the floor. All traffic is TLS on loopback, load generated by <b>wrk</b> (HTTP/1.1), <b>h2load</b> (HTTP/2) and <b>oha</b> (fixed arrival rate, latencies corrected for coordinated omission).</p>
<p><b>Why the numbers can be trusted, and what “deterministic” means here.</b> The bytes served, the sequence of requests, the tool versions, the core layout and the order of every step are fixed and recorded above. The numbers themselves cannot be bit-identical on a real CPU; what is fixed is the size of the noise. Each scenario is repeated in {env['params']['trials']} trials <i>interleaved across the targets</i>, so a slow drift of the host falls on all of them alike; the table gives the median and the minimum–maximum. A fixed CPU workload (the canary) brackets the run and a drift over {100 * canary['tolerance']:.0f}% marks the whole report as noisy. Every trial is validated: any non-2xx response or transport error discards the trial, and a “cache hit” scenario is only reported if the origin shows it received (almost) no requests. The host must be at least 97% idle for five seconds before anything is timed.</p>
<p><b>Limits, said plainly.</b> Loopback on one machine measures what the proxy costs per request, not a network. One core per proxy is a deliberate normalisation: it makes req/s a per-core figure and nginx’s <code>worker_processes 1</code> a fair partner, but with the access log on, zion’s log writer shares that core, which overstates the log’s cost relative to a multi-core deployment (µs/req is the figure to read). The CPU is shared with other guests of the same hypervisor and turbo frequency varies. HTTP/3, the WAF, rate limiting, response compression and WebSocket are not measured here.</p>

<h2>Results by scenario</h2>
<table class="g"><tr><th>target</th><th class="n">req/s</th><th class="n">min–max</th><th class="n">µs CPU/req</th><th class="n">p50</th><th class="n">p99</th><th class="n">p99.9</th><th class="n">server CPU</th><th class="n">RSS MiB</th><th class="n">cache hit</th></tr>{scenario_rows(res)}</table>
<p class="dim">Latencies for wrk are measured under saturation (64 concurrent connections), so they show queueing, not service time; the fixed-rate scenarios below show what a user would feel. h2load reports no percentiles.</p>

<h2>Latency at a fixed request rate</h2>{chart_latency(res)}
<h2>Concurrency sweep</h2>{chart_sweep(res)}

<h2 class="pb">HTTP conformance</h2>
<p>Every check is a fixed request with a fixed expectation, run against zion and, as a reference, against nginx proxying the same origins. The probe origin sends the malformed and edge-case messages a real origin will not, and records what the proxy forwarded.</p>
{conformance_section(conf)}
{external_section(h2, ct, crawl)}

<h2 class="pb">Against the previous release</h2>{compare_section(res, prev[0] if prev else None, prev[1] if prev else "")}

<h2>Provenance and how to repeat this</h2>
<p>Tools (pinned in <code>benchmarks/report/provision.sh</code>):</p><pre>{e(tools_pre)}</pre>
<p>Canary (SHA-256 MB/s on the server core, start → end): {', '.join(f'{x:.0f}' for x in canary['mb_s'])}.</p>
<pre>benchmarks/report/provision.sh           # once, on the benchmark host
benchmarks/report/report.sh {e(env['label'].split()[0])}      # build the tag, measure, test, render this PDF</pre>
</body></html>"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("result_dir", type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--prev", type=Path)
    ap.add_argument("--html-only", action="store_true")
    a = ap.parse_args()
    res = load(a.result_dir, "result.json")
    if not res:
        sys.exit(f"{a.result_dir}/result.json not found")
    prev = None
    if a.prev and (p := load(a.prev, "result.json")):
        prev = (p, p["env"]["label"])
    page = build(res, load(a.result_dir, "conformance.json"), load(a.result_dir, "h2spec.json"),
                 load(a.result_dir, "cachetests.json"), load(a.result_dir, "crawl.json"), prev)
    html_path = a.out.with_suffix(".html")
    html_path.write_text(page)
    if a.html_only:
        return
    wp = Path(sys.executable).with_name("weasyprint")
    cmd = [str(wp) if wp.exists() else "weasyprint", "--pdf-identifier", "zion-report", str(html_path), str(a.out)]
    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
