#!/usr/bin/env python3
"""Generate Zion Benchmark Report PDF."""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, black, white, Color
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas
import os

OUTPUT = os.path.join(os.path.dirname(__file__), "zion-benchmark-report.pdf")

# Colors
ZION_BLUE = HexColor("#0ea5e9")
ZION_DARK = HexColor("#0c4a6e")
DARK_BG = HexColor("#1e293b")
LIGHT_BG = HexColor("#f1f5f9")
GREEN = HexColor("#22c55e")
RED = HexColor("#ef4444")
ORANGE = HexColor("#f97316")
GRAY = HexColor("#64748b")
WHITE = white
TEXT = HexColor("#1e293b")

styles = getSampleStyleSheet()

# Custom styles
styles.add(ParagraphStyle(
    'DocTitle', parent=styles['Title'],
    fontSize=26, leading=32, textColor=ZION_DARK,
    spaceAfter=4, fontName='Helvetica-Bold'
))
styles.add(ParagraphStyle(
    'DocSubtitle', parent=styles['Normal'],
    fontSize=13, leading=18, textColor=GRAY,
    spaceAfter=2, fontName='Helvetica'
))
styles.add(ParagraphStyle(
    'SectionHead', parent=styles['Heading1'],
    fontSize=18, leading=24, textColor=ZION_DARK,
    spaceBefore=20, spaceAfter=10, fontName='Helvetica-Bold',
    borderWidth=0, borderPadding=0,
))
styles.add(ParagraphStyle(
    'SubHead', parent=styles['Heading2'],
    fontSize=13, leading=18, textColor=ZION_DARK,
    spaceBefore=14, spaceAfter=6, fontName='Helvetica-Bold'
))
styles.add(ParagraphStyle(
    'Body', parent=styles['Normal'],
    fontSize=10, leading=14, textColor=TEXT,
    spaceAfter=6, fontName='Helvetica'
))
styles.add(ParagraphStyle(
    'BulletItem', parent=styles['Normal'],
    fontSize=9.5, leading=13, textColor=TEXT,
    spaceAfter=3, fontName='Helvetica',
    leftIndent=16, bulletIndent=6
))
styles.add(ParagraphStyle(
    'KeyStat', parent=styles['Normal'],
    fontSize=11, leading=15, textColor=ZION_DARK,
    spaceAfter=3, fontName='Helvetica-Bold'
))
styles.add(ParagraphStyle(
    'TableHeader', parent=styles['Normal'],
    fontSize=9, leading=12, textColor=WHITE,
    fontName='Helvetica-Bold', alignment=TA_CENTER
))
styles.add(ParagraphStyle(
    'TableCell', parent=styles['Normal'],
    fontSize=9, leading=12, textColor=TEXT,
    fontName='Helvetica', alignment=TA_CENTER
))
styles.add(ParagraphStyle(
    'TableCellLeft', parent=styles['Normal'],
    fontSize=9, leading=12, textColor=TEXT,
    fontName='Helvetica', alignment=TA_LEFT
))
styles.add(ParagraphStyle(
    'Footer', parent=styles['Normal'],
    fontSize=7.5, leading=10, textColor=GRAY,
    fontName='Helvetica'
))
styles.add(ParagraphStyle(
    'TagCritical', parent=styles['Normal'],
    fontSize=10, textColor=RED, fontName='Helvetica-Bold',
    spaceBefore=10, spaceAfter=4
))
styles.add(ParagraphStyle(
    'TagHigh', parent=styles['Normal'],
    fontSize=10, textColor=ORANGE, fontName='Helvetica-Bold',
    spaceBefore=10, spaceAfter=4
))
styles.add(ParagraphStyle(
    'TagMedium', parent=styles['Normal'],
    fontSize=10, textColor=ZION_BLUE, fontName='Helvetica-Bold',
    spaceBefore=10, spaceAfter=4
))


def header_footer(canvas_obj, doc):
    canvas_obj.saveState()
    # Footer
    canvas_obj.setFont('Helvetica', 7.5)
    canvas_obj.setFillColor(GRAY)
    canvas_obj.drawString(2 * cm, 1.2 * cm, "Zion Edge Gateway - Benchmark Report v0.1.1")
    canvas_obj.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    # Top line
    canvas_obj.setStrokeColor(ZION_BLUE)
    canvas_obj.setLineWidth(2)
    canvas_obj.line(2 * cm, A4[1] - 1.5 * cm, A4[0] - 2 * cm, A4[1] - 1.5 * cm)
    canvas_obj.restoreState()


def make_table(headers, rows, col_widths=None):
    """Create a styled table."""
    data = [[Paragraph(h, styles['TableHeader']) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(c), styles['TableCell'] if i > 0 else styles['TableCellLeft'])
                      for i, c in enumerate(row)])

    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), ZION_DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
        ('TOPPADDING', (0, 1), (-1, -1), 5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    return t


def build():
    doc = SimpleDocTemplate(
        OUTPUT, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2.2 * cm, bottomMargin=2 * cm
    )
    story = []

    # ─── TITLE PAGE ───
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("ZION EDGE GATEWAY", styles['DocTitle']))
    story.append(Paragraph("Benchmark Report v0.1.1", ParagraphStyle(
        'BigSub', parent=styles['DocSubtitle'], fontSize=16, leading=22, textColor=ZION_BLUE
    )))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Security Audit + Performance Optimization Results", styles['DocSubtitle']))
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="60%", thickness=1, color=ZION_BLUE, spaceAfter=12))
    story.append(Paragraph("April 14, 2026", styles['Body']))
    story.append(Paragraph("Apple M4  |  Darwin arm64  |  10 cores  |  16 GB RAM", styles['Body']))
    story.append(Spacer(1, 2 * cm))

    # Key stats box
    stats = [
        ["233,341 req/s", "Peak HTML throughput (TLS 1.3 e2e)"],
        ["209,381 req/s", "Cache hit throughput (4KB JS from RAM)"],
        ["91,893 req/s", "WAF POST throughput (70+ patterns)"],
        ["28 bugs fixed", "Critical, High, Medium severity"],
        ["20 optimizations", "Applied across all hot paths"],
        ["0 errors", "Across all benchmark runs"],
    ]
    stat_data = [[Paragraph(f"<b>{s[0]}</b>", ParagraphStyle('x', parent=styles['Body'],
                  fontSize=12, textColor=ZION_DARK, fontName='Helvetica-Bold')),
                  Paragraph(s[1], styles['Body'])] for s in stats]
    stat_table = Table(stat_data, colWidths=[4.5 * cm, 11 * cm])
    stat_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, HexColor("#e2e8f0")),
    ]))
    story.append(stat_table)
    story.append(PageBreak())

    # ─── SECTION 1: EXECUTIVE SUMMARY ───
    story.append(Paragraph("1. Executive Summary", styles['SectionHead']))
    story.append(Paragraph(
        "Zion is a high-performance TLS reverse proxy with built-in Web Application Firewall (WAF), "
        "written entirely in Rust. This report covers the results of a comprehensive security audit "
        "(28 bugs fixed across 3 severity levels) and a performance optimization sprint (20 optimizations "
        "applied) on the v0.1.1 codebase.", styles['Body']))
    story.append(Paragraph(
        "The codebase was audited across all 17 modules (~8,600 lines of Rust) with focus on "
        "request smuggling, cache poisoning, WAF bypass vectors, memory safety, concurrency correctness, "
        "and RFC compliance. All fixes maintain backward compatibility with 154 unit tests passing.", styles['Body']))
    story.append(Spacer(1, 6 * mm))

    # ─── SECTION 2: BENCHMARK RESULTS ───
    story.append(Paragraph("2. Benchmark Results", styles['SectionHead']))
    story.append(Paragraph(
        "Final benchmark run on commit <font color='#0ea5e9'><b>9c107f6</b></font> with all 28 security fixes "
        "and 20 performance optimizations applied. Native release build with target-cpu=native.", styles['Body']))

    bench_headers = ["Endpoint", "Median req/s", "CV%", "Best Run", "Errors"]
    bench_rows = [
        ["HTML SSR 5KB", "233,341", "2.0%", "236,755", "0"],
        ["Cache Hit JS 4KB (RAM)", "209,381", "9.8%", "214,546", "0"],
        ["CSS 3KB (cached)", "191,574", "4.5%", "203,969", "0"],
        ["TLS Proxy API GET 1KB", "93,253", "3.0%", "97,019", "0"],
        ["WAF POST JSON", "91,893", "3.1%", "93,415", "0"],
        ["JS 4KB (no cache)", "81,470", "2.3%", "82,723", "0"],
        ["PNG 8KB (no cache)", "66,753", "2.7%", "68,020", "0"],
        ["WOFF2 16KB (no cache)", "59,262", "3.0%", "60,679", "0"],
    ]
    story.append(make_table(bench_headers, bench_rows,
                            col_widths=[5.5 * cm, 3 * cm, 2 * cm, 2.8 * cm, 2 * cm]))
    story.append(Spacer(1, 4 * mm))

    sec_headers = ["Security Check", "Result"]
    sec_rows = [
        ["SQLi Injection (query parameter)", "Blocked (HTTP 400)"],
        ["XSS Injection (query parameter)", "Blocked (HTTP 400)"],
    ]
    story.append(make_table(sec_headers, sec_rows, col_widths=[7 * cm, 8 * cm]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "<i>Methodology: wrk 4.2.0, 2 threads, 100 connections, 5 runs x 10s each. "
        "Self-signed TLS 1.3 certs (rustls 0.23). Go test backend on localhost:9090. "
        "Release build: opt-level=3, LTO=fat, codegen-units=1, panic=abort, mimalloc allocator.</i>",
        ParagraphStyle('fn', parent=styles['Body'], fontSize=8, textColor=GRAY)))
    story.append(PageBreak())

    # ─── SECTION 3: SECURITY AUDIT ───
    story.append(Paragraph("3. Security Audit", styles['SectionHead']))
    story.append(Paragraph(
        "28 bugs identified and fixed across all severity levels. Every fix includes a regression "
        "test. All 154 tests pass after each commit.", styles['Body']))

    # Critical
    story.append(Paragraph("Critical (7)", styles['TagCritical']))
    criticals = [
        "Request smuggling via forwarded Transfer-Encoding header (proxy.rs)",
        "Cache poisoning: cache key ignored query string (dispatch.rs)",
        "WebSocket 101 response missing Sec-WebSocket-Accept (proxy.rs)",
        "WAF bypass via quadruple URL encoding, normalization only 3 passes (waf.rs)",
        "WAF POST/PUT/PATCH early return skipped CORS headers and metrics (dispatch.rs)",
        "Vary header check disabled cache for all gzip-enabled upstreams (dispatch.rs)",
        "HTTP/80 handler had no rate limiting or URI length check (main.rs)",
    ]
    for c in criticals:
        story.append(Paragraph(f"\u2013  {c}", styles['BulletItem']))

    # High
    story.append(Paragraph("High (8)", styles['TagHigh']))
    highs = [
        "L1/L2 cache coherence gap: stale data served for up to TTL duration (1 year default)",
        "DELETE request body bypassed WAF inspection entirely",
        "CORS preflight from disallowed origins proxied to upstream",
        "Cache hit missing Content-Encoding header (garbled gzip responses)",
        "SSRF detection only matched http:// prefix (missed https, hex/decimal IP encoding)",
        "EWMA latency update not atomic: lost updates under concurrent health checks",
        "TLS CERT_GENERATION counter used Relaxed ordering (stale certs on ARM/Graviton)",
        "Client cert fingerprint XOR fold mislabeled as SHA256 in comments",
    ]
    for h in highs:
        story.append(Paragraph(f"\u2013  {h}", styles['BulletItem']))

    # Medium
    story.append(Paragraph("Medium (13)", styles['TagMedium']))
    mediums = [
        "URI length check ignored query string; command injection patterns required spaces",
        "Path traversal only caught 3-level; Content-Type prefix matching too permissive",
        "Bearer token extraction case-sensitive (violated RFC 6750)",
        "JWKS refresh task died permanently on first HTTP client build failure",
        "auth_profile references not validated in config (panic at runtime)",
        "Connection timeout killed entire HTTP/2 mux and WebSocket connections",
        "TLS prewarm + watcher race condition on cert store",
        "setsockopt failures silently ignored; SNI cert dirs not watched",
        "CORS origin comparison case-sensitive (violated RFC 6454)",
    ]
    for m in mediums:
        story.append(Paragraph(f"\u2013  {m}", styles['BulletItem']))
    story.append(Spacer(1, 4 * mm))

    # ─── SECTION 4: PERFORMANCE OPTIMIZATIONS ───
    story.append(Paragraph("4. Performance Optimizations", styles['SectionHead']))
    story.append(Paragraph(
        "20 optimizations implemented across 6 categories. Estimated cumulative impact: "
        "-700ns per request on hot path, 14 fewer atomic operations per histogram observation, "
        "O(1) cache LRU (was O(N)), and thundering herd protection.", styles['Body']))

    cats = [
        ("Compiler / Build", [
            "target-cpu=native via .cargo/config.toml - unlocks NEON/AES-CE on Apple Silicon",
            "PGO build script for additional 10-20% (benchmarks/bench-pgo.sh)",
        ]),
        ("Allocation Elimination", [
            "Traceparent: 3x format!() replaced with [u8;55] stack buffer (-500ns/req)",
            "CORS origin: HeaderValue clone instead of String allocation",
            "WAF content-type: borrow from parts.headers instead of pre-clone",
            "Cache key: Arc::from() direct instead of String intermediate",
        ]),
        ("Lock / Contention Reduction", [
            "WebSocket TLS config: OnceLock, built once instead of per-upgrade",
            "Metrics render: ArcSwap replaces RwLock (lock-free /metrics)",
            "Histogram observe: 3 atomics instead of 17 (non-cumulative differential buckets)",
            "HTTP builder: Arc wrap (ref-count bump instead of deep struct clone)",
        ]),
        ("Data Structures", [
            "L1 cache: O(1) LRU via index-based doubly-linked list (was O(N) VecDeque scan)",
            "Host validation: single-pass byte scan (was 8 separate contains() calls)",
            "CORS origin: FNV hash set O(1) lookup (was Vec linear scan)",
        ]),
        ("WAF Pipeline", [
            "SIMD pre-filter: memchr3 fast-reject before Aho-Corasick (-200-500ns clean bodies)",
            "Normalization iterations capped at 2 (was 7, convergence check handles early exit)",
            "Thread-local buffer shrink-to-fit above 64KB (prevents OOM under attack)",
        ]),
        ("Innovative", [
            "Request coalescing (singleflight): N concurrent cache misses = 1 upstream fetch",
            "Health probe inline fast-path: /healthz responds in ~1us, bypasses full pipeline",
            "SO_BUSY_POLL on Linux: spin-poll NIC queue for -5-15us p99 latency",
        ]),
    ]
    for cat_name, items in cats:
        story.append(Paragraph(cat_name, styles['SubHead']))
        for item in items:
            story.append(Paragraph(f"\u2013  {item}", styles['BulletItem']))
    story.append(PageBreak())

    # ─── SECTION 5: ARCHITECTURE ───
    story.append(Paragraph("5. Architecture Overview", styles['SectionHead']))
    story.append(Paragraph("Request Processing Pipeline", styles['SubHead']))
    flow = (
        "Client  &#8594;  TLS 1.3 Handshake  &#8594;  Rate Limit  &#8594;  "
        "Radix Route Lookup  &#8594;  WAF 6-Gate Pipeline  &#8594;  "
        "Dispatch (proxy / cache / stream / websocket)  &#8594;  "
        "Security Headers  &#8594;  Client"
    )
    story.append(Paragraph(flow, ParagraphStyle('flow', parent=styles['Body'],
                 fontSize=9, textColor=ZION_DARK, fontName='Helvetica-Bold',
                 backColor=LIGHT_BG, borderPadding=8, spaceAfter=10)))

    story.append(Paragraph("Key Design Choices", styles['SubHead']))
    design = [
        "Lock-free concurrency: ArcSwap for TLS hot-reload, DashMap for cache/rate-limit, "
        "sharded atomic counters for metrics",
        "Two-level cache: L1 thread-local (~5ns, O(1) LRU) + L2 shared DashMap (~30ns, TTL eviction) "
        "with generation-based coherence",
        "Zero-regex WAF: Aho-Corasick O(N) single-pass over 70+ patterns, SIMD pre-filter bypass "
        "for clean traffic, entropy analysis for obfuscated payloads",
        "Hardware-aware bootstrap: CPU affinity pinning, L1d cache sizing, AES-NI/NEON detection, "
        "SO_REUSEPORT, TCP_FASTOPEN, io_uring multishot accept",
        "Graceful shutdown: 30s connection drain via semaphore-based tracking",
        "Request coalescing (singleflight): prevents thundering herd on cache cold starts",
    ]
    for d in design:
        story.append(Paragraph(f"\u2013  {d}", styles['BulletItem']))

    story.append(Paragraph("Module Map", styles['SubHead']))
    mod_headers = ["Module", "Lines", "Purpose"]
    mod_rows = [
        ["dispatch.rs", "~700", "Request pipeline, routing, cache, CORS, WAF gate"],
        ["waf.rs", "~1,150", "6-gate WAF: Aho-Corasick, entropy, simd-json"],
        ["config.rs", "~1,050", "TOML parsing, validation, radix router build"],
        ["tls.rs", "~640", "rustls config, SNI resolution, hot-reload, pre-warm"],
        ["proxy.rs", "~560", "Upstream forwarding, WebSocket, SSE streaming"],
        ["cache.rs", "~550", "Two-level L1/L2 cache with O(1) LRU"],
        ["metrics.rs", "~580", "Lock-free sharded counters, differential histogram"],
        ["security.rs", "~475", "CORS (FNV O(1)), rate limiter, header hardening"],
        ["main.rs", "~770", "Accept loop, TLS, graceful shutdown, health fast-path"],
    ]
    story.append(make_table(mod_headers, mod_rows, col_widths=[3.5 * cm, 2 * cm, 10 * cm]))
    story.append(PageBreak())

    # ─── SECTION 6: METHODOLOGY ───
    story.append(Paragraph("6. Methodology", styles['SectionHead']))
    meth = [
        ("Benchmark tool", "wrk 4.2.0 [kqueue], 2 threads, 100 concurrent connections"),
        ("Runs", "5 measurement runs x 10 seconds each, median reported"),
        ("Statistics", "Median, CI95 (1.96 x stderr), coefficient of variation (CV%)"),
        ("TLS", "Self-signed certificates, TLS 1.3, rustls 0.23, session tickets + 0-RTT"),
        ("Backend", "Go test server on localhost:9090 (1KB JSON, 5KB HTML, 4-16KB assets)"),
        ("Build profile", "opt-level=3, LTO=fat, codegen-units=1, panic=abort, strip=true"),
        ("Allocator", "mimalloc (global)"),
        ("Platform", "Apple M4, macOS 15, arm64, 10 cores, 16 GB RAM"),
        ("Reproducibility", "bash benchmarks/bench-native.sh"),
    ]
    meth_data = [[Paragraph(f"<b>{k}</b>", styles['Body']),
                   Paragraph(v, styles['Body'])] for k, v in meth]
    meth_table = Table(meth_data, colWidths=[4 * cm, 12 * cm])
    meth_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, HexColor("#e2e8f0")),
    ]))
    story.append(meth_table)
    story.append(Spacer(1, 1 * cm))

    # Commits
    story.append(Paragraph("Commit History (this session)", styles['SubHead']))
    commits = [
        ("9c107f6", "perf: batch 5 - O(1) LRU, singleflight, Arc builder, SO_BUSY_POLL, PGO"),
        ("ab0867a", "perf: CORS O(1) FNV hash set + security header cleanup"),
        ("1ae9d6c", "perf: batch 4 - eliminate allocations, lock-free metrics, health fast-path"),
        ("551dc05", "perf: batch 1-3 - target-cpu, zero-alloc, SIMD pre-filter"),
        ("be4c311", "fix(bench): accept HTTP 400 as WAF block status"),
        ("a7ea0fd", "fix: patch 13 medium-severity bugs"),
        ("b915f7b", "fix(security): patch 8 high-severity bugs"),
        ("95556a4", "fix(security): patch 7 critical bugs"),
    ]
    c_data = [[Paragraph(f"<font color='#0ea5e9'><b>{h}</b></font>", styles['Body']),
                Paragraph(m, styles['Body'])] for h, m in commits]
    c_table = Table(c_data, colWidths=[2.5 * cm, 13.5 * cm])
    c_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(c_table)

    story.append(Spacer(1, 1.5 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=ZION_BLUE, spaceAfter=8))
    story.append(Paragraph(
        "Generated by Claude Code  |  MIT License  |  github.com/fabriziosalmi/zion",
        ParagraphStyle('end', parent=styles['Body'], fontSize=8, textColor=GRAY, alignment=TA_CENTER)))

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"PDF generated: {OUTPUT}")


if __name__ == "__main__":
    build()
