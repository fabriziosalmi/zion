#!/usr/bin/env python3
"""
Zion vs nginx — Single-page A4 PDF benchmark report.
Reads results.json from bench-fair.sh (format: {system}_{endpoint}).
"""
import json, sys, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.gridspec as gridspec
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────
SYSTEMS = [
    ("nginx",     "#C0392B", "nginx 1.27", "s"),
    ("zion_tls",  "#2980B9", "Zion TLS",   "o"),
    ("zion_waf",  "#27AE60", "Zion WAF",   "D"),
    ("zion_full", "#E67E22", "Zion Full",  "^"),
]
ENDPOINTS = ["api_get", "html", "js_4k", "png_8k", "waf_post", "css_cached"]
EP_LABELS = ["API GET\n1KB", "HTML\n5KB", "JS\n4KB", "PNG\n8KB", "WAF POST\nJSON", "CSS\ncached"]
EP_SHORT  = ["API", "HTML", "JS", "PNG", "WAF", "CSS"]

BG = "#FAFAFA"
GRID = "#E0E0E0"
DARK = "#1A1A2E"
MUTED = "#95A5A6"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 8,
    "axes.facecolor": BG,
    "axes.edgecolor": GRID,
    "axes.grid": True,
    "axes.axisbelow": True,
    "grid.color": GRID,
    "grid.linewidth": 0.5,
    "figure.facecolor": "white",
})

def fmt_k(v):
    return f"{v/1000:.1f}k" if v >= 1000 else f"{v:.0f}"

def main():
    rdir = sys.argv[1]
    with open(os.path.join(rdir, "results.json")) as f:
        data = json.load(f)
    outpath = os.path.join(rdir, "zion-benchmark-report.pdf")

    # ── Extract data ──────────────────────────────────────────
    def get(system, endpoint, field="rps"):
        key = f"{system}_{endpoint}"
        return data.get(key, {}).get(field, 0)

    fig = plt.figure(figsize=(8.27, 11.69))  # A4

    # Title
    fig.text(0.50, 0.975, "ZION EDGE GATEWAY", ha="center", fontsize=16,
             fontweight="bold", color=DARK)
    fig.text(0.50, 0.960, "Performance Benchmark — Zion vs nginx (Fair Docker Test)",
             ha="center", fontsize=9, color="#2C3E50")
    date_str = datetime.now().strftime("%Y-%m-%d")
    fig.text(0.50, 0.945,
             f"{date_str}  ·  Docker 1 CPU / 256MB per proxy  ·  c=100  ·  10s/test  ·  wrk",
             ha="center", fontsize=6, color=MUTED)

    gs = gridspec.GridSpec(3, 2, figure=fig,
                           top=0.925, bottom=0.10, left=0.09, right=0.96,
                           hspace=0.50, wspace=0.28)

    # ═══════════════════════════════════════════════════════════
    # CHART 1: Throughput bars (full width)
    # ═══════════════════════════════════════════════════════════
    ax1 = fig.add_subplot(gs[0, :])
    x = np.arange(len(ENDPOINTS))
    n = len(SYSTEMS)
    w = 0.8 / n

    for j, (skey, color, label, _) in enumerate(SYSTEMS):
        vals = [get(skey, ep) for ep in ENDPOINTS]
        offset = (j - n/2 + 0.5) * w
        bars = ax1.bar(x + offset, vals, w, label=label, color=color,
                       alpha=0.85, edgecolor="white", linewidth=0.5)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 300,
                         fmt_k(v), ha="center", va="bottom", fontsize=5.5,
                         fontweight="bold", color=color)

    ax1.set_ylabel("Requests/sec", fontsize=9)
    ax1.set_title("Throughput by Endpoint (c=100)", fontsize=11, fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(EP_LABELS, fontsize=7)
    ax1.legend(fontsize=7, ncol=4, loc="upper right")
    ax1.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: fmt_k(v)))

    # ═══════════════════════════════════════════════════════════
    # CHART 2: P99 Latency bars
    # ═══════════════════════════════════════════════════════════
    ax2 = fig.add_subplot(gs[1, 0])

    for j, (skey, color, label, _) in enumerate(SYSTEMS):
        vals = [get(skey, ep, "p99_ms") for ep in ENDPOINTS]
        offset = (j - n/2 + 0.5) * w
        ax2.bar(x + offset, vals, w, label=label, color=color,
                alpha=0.85, edgecolor="white", linewidth=0.5)

    ax2.set_ylabel("P99 Latency (ms)", fontsize=8)
    ax2.set_title("P99 Tail Latency", fontsize=10, fontweight="bold")
    ax2.set_xticks(x)
    ax2.set_xticklabels(EP_SHORT, fontsize=7)
    ax2.legend(fontsize=6, ncol=2)

    # ═══════════════════════════════════════════════════════════
    # CHART 3: Delta % vs nginx (horizontal bars)
    # ═══════════════════════════════════════════════════════════
    ax3 = fig.add_subplot(gs[1, 1])

    delta_labels = []
    delta_vals = []
    delta_colors = []

    for ep, ep_short in zip(ENDPOINTS, EP_SHORT):
        nginx_rps = get("nginx", ep)
        if nginx_rps <= 0:
            continue
        # Use best Zion variant
        best_rps = 0
        best_color = "#333"
        for skey, color, _, _ in SYSTEMS[1:]:  # skip nginx
            v = get(skey, ep)
            if v > best_rps:
                best_rps = v
                best_color = color
        pct = ((best_rps / nginx_rps) - 1) * 100
        delta_labels.append(ep_short)
        delta_vals.append(pct)
        delta_colors.append(best_color)

    y_pos = np.arange(len(delta_labels))
    bars = ax3.barh(y_pos, delta_vals, color=delta_colors, alpha=0.85,
                    edgecolor="white", linewidth=0.5, height=0.6)
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels(delta_labels, fontsize=8)
    ax3.set_xlabel("% vs nginx", fontsize=7)
    ax3.set_title("Best Zion vs nginx", fontsize=10, fontweight="bold")
    ax3.axvline(x=0, color=DARK, linewidth=0.8)
    ax3.invert_yaxis()

    for bar, val in zip(bars, delta_vals):
        ax3.text(bar.get_width() + 3, bar.get_y() + bar.get_height()/2,
                 f"+{val:.0f}%", ha="left", va="center", fontsize=7, fontweight="bold")

    # ═══════════════════════════════════════════════════════════
    # TABLE: Raw numbers (bottom half)
    # ═══════════════════════════════════════════════════════════
    ax4 = fig.add_subplot(gs[2, :])
    ax4.axis("off")

    # Throughput table
    header = ["Endpoint", "nginx 1.27", "Zion TLS", "Zion WAF", "Zion Full", "Best vs nginx"]
    rows = []
    for ep, ep_short in zip(ENDPOINTS, EP_SHORT):
        nginx_v = get("nginx", ep)
        tls_v = get("zion_tls", ep)
        waf_v = get("zion_waf", ep)
        full_v = get("zion_full", ep)
        best = max(tls_v, waf_v, full_v)
        delta = f"+{((best/nginx_v)-1)*100:.0f}%" if nginx_v > 0 else "n/a"
        rows.append([ep_short,
                     f"{nginx_v:,.0f}", f"{tls_v:,.0f}", f"{waf_v:,.0f}", f"{full_v:,.0f}",
                     delta])

    # Spacer + latency table
    rows.append(["", "", "", "", "", ""])
    rows.append(["P99 Latency", "nginx", "Zion TLS", "Zion WAF", "Zion Full", ""])
    for ep, ep_short in zip(ENDPOINTS, EP_SHORT):
        row = [ep_short]
        for skey, _, _, _ in SYSTEMS:
            v = get(skey, ep, "p99_ms")
            row.append(f"{v:.1f}ms" if v > 0 else "—")
        row.append("")
        rows.append(row)

    table = ax4.table(cellText=[header] + rows, loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(7)
    table.scale(1.0, 1.3)

    # Style header
    for j in range(len(header)):
        table[0, j].set_facecolor("#2C3E50")
        table[0, j].set_text_props(color="white", fontweight="bold")
    # Style latency header
    lat_row = len(rows) - len(ENDPOINTS)
    for j in range(len(header)):
        table[lat_row, j].set_facecolor("#34495E")
        table[lat_row, j].set_text_props(color="white", fontweight="bold")

    # ── Footer ────────────────────────────────────────────────
    fig.text(0.09, 0.03,
             "Methodology: All proxies in Docker with identical constraints (1 CPU, 256MB RAM). "
             "Same Go backend (2 CPU, 512MB). Both terminate TLS 1.3. "
             "nginx: 1.27-alpine, 1 worker, access_log off, keepalive 64. "
             "Zion WAF: Aho-Corasick 70+ patterns + Shannon entropy + simd-json. "
             "Zion Full: WAF + DashMap RAM cache.",
             fontsize=5, color=MUTED, fontstyle="italic", wrap=True)

    with PdfPages(outpath) as pdf:
        pdf.savefig(fig, dpi=200)
    plt.close(fig)
    print(f"Report saved: {outpath}")

if __name__ == "__main__":
    main()
