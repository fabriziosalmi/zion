//! `zion top` — live TUI dashboard.
//!
//! Polls `/_zion/snapshot.json` from a running Zion instance and renders a
//! single-screen htop-style dashboard with traffic counters, latency
//! quantiles, status-class breakdown, cache hit rate, an RPS sparkline, and
//! per-upstream health rows.
//!
//! Architecture:
//!  - main thread: ratatui draw loop + crossterm event loop (~30 fps, idle)
//!  - poll thread: blocking HTTP GET on the snapshot endpoint at the user's
//!    interval, drops results into an mpsc channel
//!
//! The HTTP client is intentionally written against std::net::TcpStream so
//! the binary picks up no new dependencies on the daemon side. Only the
//! presentation crates (ratatui + crossterm) are pulled in, gated by the
//! `tui` feature.

use crate::cli::TopOpts;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Row, Sparkline, Table},
    Frame, Terminal,
};
use serde::Deserialize;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const HISTORY_LEN: usize = 120;
const FRAME_INTERVAL: Duration = Duration::from_millis(100);
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

// ───────────────────────────────────────────────────────────────────
// SNAPSHOT TYPES (mirror the JSON emitted by metrics::snapshot_json)
// ───────────────────────────────────────────────────────────────────

#[derive(Deserialize, Clone, Debug)]
struct Snapshot {
    version: String,
    #[allow(dead_code)]
    timestamp_ms: u64,
    uptime_secs: u64,
    platform: PlatformSnap,
    metrics: MetricsSnap,
    upstreams: Vec<UpstreamSnap>,
}

#[derive(Deserialize, Clone, Debug)]
struct PlatformSnap {
    os: String,
    arch: String,
    cores: u64,
    ram_mb: u64,
    tier: String,
    tier_score: u64,
    projected_kreqs_cached: u64,
    projected_kreqs_dynamic: u64,
    has_aes_ni: bool,
    #[allow(dead_code)]
    has_sha256: bool,
    #[allow(dead_code)]
    has_avx2: bool,
    #[allow(dead_code)]
    has_neon: bool,
    has_so_reuseport: bool,
    has_tcp_fastopen: bool,
    has_tcp_quickack: bool,
    worker_threads: u64,
    conn_limit: u64,
}

#[derive(Deserialize, Clone, Debug, Default)]
struct MetricsSnap {
    requests_total: u64,
    requests_2xx: u64,
    requests_4xx: u64,
    requests_5xx: u64,
    waf_denied: u64,
    rate_limited: u64,
    cache_hits: u64,
    cache_misses: u64,
    #[allow(dead_code)]
    websocket_upgrades: u64,
    active_connections: i64,
    connections_total: u64,
    tls_handshake_errors: u64,
    request_p50_us: u64,
    request_p95_us: u64,
    request_p99_us: u64,
    #[allow(dead_code)]
    upstream_p50_us: u64,
    #[allow(dead_code)]
    upstream_p95_us: u64,
    #[allow(dead_code)]
    upstream_p99_us: u64,
    tls_p50_us: u64,
    #[allow(dead_code)]
    tls_p95_us: u64,
}

#[derive(Deserialize, Clone, Debug)]
struct UpstreamSnap {
    url: String,
    healthy: bool,
    latency_us: u64,
}

// ───────────────────────────────────────────────────────────────────
// APP STATE
// ───────────────────────────────────────────────────────────────────

struct App {
    opts: TopOpts,
    last: Option<Snapshot>,
    last_fetch_at: Option<Instant>,
    /// Successful fetches since startup (used for status line).
    fetch_ok: u64,
    /// Last error message, if any.
    last_error: Option<String>,
    /// Sparkline history of req/s (most recent at the back).
    rps_history: VecDeque<u64>,
    /// Local startup instant for "watching for N seconds" line.
    started_at: Instant,
    paused: bool,
}

impl App {
    fn new(opts: TopOpts) -> Self {
        Self {
            opts,
            last: None,
            last_fetch_at: None,
            fetch_ok: 0,
            last_error: None,
            rps_history: VecDeque::with_capacity(HISTORY_LEN),
            started_at: Instant::now(),
            paused: false,
        }
    }

    fn ingest(&mut self, snap: Snapshot) {
        // Compute RPS from delta vs the previous snapshot.
        if let (Some(prev), Some(prev_at)) = (self.last.as_ref(), self.last_fetch_at) {
            let dt = prev_at.elapsed().as_secs_f64();
            if dt > 0.05 {
                let delta = snap
                    .metrics
                    .requests_total
                    .saturating_sub(prev.metrics.requests_total);
                let rps = (delta as f64 / dt).round() as u64;
                self.push_rps(rps);
            }
        } else {
            self.push_rps(0);
        }
        self.last = Some(snap);
        self.last_fetch_at = Some(Instant::now());
        self.fetch_ok = self.fetch_ok.saturating_add(1);
        self.last_error = None;
    }

    fn ingest_error(&mut self, err: String) {
        self.last_error = Some(err);
    }

    fn push_rps(&mut self, rps: u64) {
        if self.rps_history.len() >= HISTORY_LEN {
            self.rps_history.pop_front();
        }
        self.rps_history.push_back(rps);
    }

    fn current_rps(&self) -> u64 {
        self.rps_history.back().copied().unwrap_or(0)
    }
}

// ───────────────────────────────────────────────────────────────────
// PUBLIC ENTRY POINT
// ───────────────────────────────────────────────────────────────────

pub fn run(opts: TopOpts) -> Result<(), Box<dyn std::error::Error>> {
    // Spawn the poll thread. We deliberately use a blocking std::net client
    // so the daemon picks up zero new deps from this feature.
    let (tx, rx) = mpsc::channel::<FetchResult>();
    let url = opts.url.clone();
    let interval = Duration::from_millis(opts.interval_ms);
    thread::Builder::new()
        .name("zion-top-poller".into())
        .spawn(move || poll_loop(url, interval, tx))?;

    // Switch to the alt screen and enter raw mode.
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;

    // Trampoline so we always restore the terminal even on panic.
    let result = run_loop(&mut terminal, &mut App::new(opts), &rx);

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

enum FetchResult {
    Ok(Box<Snapshot>),
    Err(String),
}

fn poll_loop(url: String, interval: Duration, tx: mpsc::Sender<FetchResult>) {
    loop {
        let result = match fetch_snapshot(&url) {
            Ok(s) => FetchResult::Ok(Box::new(s)),
            Err(e) => FetchResult::Err(e),
        };
        if tx.send(result).is_err() {
            return; // main loop dropped — exit silently
        }
        thread::sleep(interval);
    }
}

fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    rx: &mpsc::Receiver<FetchResult>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_draw = Instant::now() - FRAME_INTERVAL;
    loop {
        // Drain all pending poll results so we always render the freshest.
        while let Ok(r) = rx.try_recv() {
            if app.paused {
                continue;
            }
            match r {
                FetchResult::Ok(s) => app.ingest(*s),
                FetchResult::Err(e) => app.ingest_error(e),
            }
        }

        // Block on user input briefly so the loop is event-driven, not spinning.
        let timeout = FRAME_INTERVAL
            .checked_sub(last_draw.elapsed())
            .unwrap_or(Duration::ZERO);
        if event::poll(timeout)? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match (k.code, k.modifiers) {
                    (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => return Ok(()),
                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(()),
                    (KeyCode::Char(' '), _) | (KeyCode::Char('p'), _) => {
                        app.paused = !app.paused;
                    }
                    (KeyCode::Char('r'), _) => {
                        // Force a redraw immediately — not a refetch (poller drives that).
                        last_draw = Instant::now() - FRAME_INTERVAL;
                    }
                    _ => {}
                }
            }
        }

        if last_draw.elapsed() >= FRAME_INTERVAL {
            terminal.draw(|f| draw(f, app))?;
            last_draw = Instant::now();
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// LAYOUT + DRAW
// ───────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    // Vertical: header (3) | body (flex) | footer (1)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(f, chunks[0], app);
    draw_body(f, chunks[1], app);
    draw_footer(f, chunks[2], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let line = match app.last.as_ref() {
        Some(s) => header_line(s, &app.opts),
        None => Line::from(vec![
            Span::styled(
                "ZION top",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("connecting…", Style::default().fg(Color::Yellow)),
            Span::raw("  "),
            Span::styled(
                format!("→ {}", app.opts.url),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    };

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray));
    let p = Paragraph::new(line).alignment(Alignment::Left).block(block);
    f.render_widget(p, area);
}

fn header_line<'a>(s: &'a Snapshot, opts: &'a TopOpts) -> Line<'a> {
    let tier_color = match s.platform.tier.as_str() {
        "S" => Color::Magenta,
        "A" => Color::Cyan,
        "B" => Color::Green,
        _ => Color::Yellow,
    };
    Line::from(vec![
        Span::styled(
            "ZION",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("★ TIER ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            s.platform.tier.clone(),
            Style::default().fg(tier_color).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("v{}", s.version),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("    "),
        Span::styled("uptime ", Style::default().fg(Color::DarkGray)),
        Span::raw(fmt_uptime(s.uptime_secs)),
        Span::raw("    "),
        Span::styled("host ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!(
            "{} {} cores · {} MB",
            s.platform.os, s.platform.cores, s.platform.ram_mb
        )),
        Span::raw("    "),
        Span::styled("poll ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{} ms", opts.interval_ms)),
    ])
}

fn draw_body(f: &mut Frame, area: Rect, app: &App) {
    if app.last.is_none() {
        // Connecting / error splash.
        let mut lines = vec![Line::from(vec![Span::styled(
            "Trying to reach the snapshot endpoint…",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )])];
        lines.push(Line::from(format!("URL: {}", app.opts.url)));
        lines.push(Line::from(format!(
            "Watching for {} s…",
            app.started_at.elapsed().as_secs()
        )));
        if let Some(e) = &app.last_error {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "last error: ",
                Style::default().fg(Color::DarkGray),
            )]));
            lines.push(Line::from(vec![Span::styled(
                e.clone(),
                Style::default().fg(Color::Red),
            )]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "tips:",
            Style::default().fg(Color::DarkGray),
        )]));
        lines.push(Line::from(
            "  • the snapshot endpoint is /_zion/snapshot.json on the HTTP listener",
        ));
        lines.push(Line::from(
            "  • it's restricted to internal IPs — run zion top from the same host",
        ));
        lines.push(Line::from(
            "  • override with: zion top --url http://10.0.0.5:80/_zion/snapshot.json",
        ));
        let p = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    " connecting ",
                    Style::default().fg(Color::Yellow),
                )),
        );
        f.render_widget(p, area);
        return;
    }

    let snap = app.last.as_ref().unwrap();

    // Top row: TRAFFIC | LATENCY | STATUS
    // Then sparkline strip
    // Then bottom row: CACHE | UPSTREAMS
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Min(7),
        ])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(rows[0]);

    draw_traffic(f, top[0], app, snap);
    draw_latency(f, top[1], snap);
    draw_status(f, top[2], snap);

    draw_sparkline(f, rows[1], app, snap);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(rows[2]);

    draw_cache(f, bottom[0], snap);
    draw_upstreams(f, bottom[1], snap);
}

fn draw_traffic(f: &mut Frame, area: Rect, app: &App, snap: &Snapshot) {
    let lines = vec![
        kv("requests", &fmt_int(snap.metrics.requests_total)),
        kv_styled("rps", &fmt_int(app.current_rps()), Color::Cyan),
        kv("active conn", &snap.metrics.active_connections.to_string()),
        kv("total conn", &fmt_int(snap.metrics.connections_total)),
        kv("tls errors", &fmt_int(snap.metrics.tls_handshake_errors)),
    ];
    let p = Paragraph::new(lines).block(panel(" traffic "));
    f.render_widget(p, area);
}

fn draw_latency(f: &mut Frame, area: Rect, snap: &Snapshot) {
    let lines = vec![
        kv("p50", &fmt_us(snap.metrics.request_p50_us)),
        kv_styled("p95", &fmt_us(snap.metrics.request_p95_us), Color::Yellow),
        kv_styled("p99", &fmt_us(snap.metrics.request_p99_us), Color::Red),
        kv("tls p50", &fmt_us(snap.metrics.tls_p50_us)),
    ];
    let p = Paragraph::new(lines).block(panel(" latency "));
    f.render_widget(p, area);
}

fn draw_status(f: &mut Frame, area: Rect, snap: &Snapshot) {
    let total = snap.metrics.requests_total.max(1);
    let pct2 = pct(snap.metrics.requests_2xx, total);
    let pct4 = pct(snap.metrics.requests_4xx, total);
    let pct5 = pct(snap.metrics.requests_5xx, total);

    let lines = vec![
        bar_line("2xx", pct2, snap.metrics.requests_2xx, Color::Green),
        bar_line("4xx", pct4, snap.metrics.requests_4xx, Color::Yellow),
        bar_line("5xx", pct5, snap.metrics.requests_5xx, Color::Red),
        kv_styled(
            "waf blocks",
            &fmt_int(snap.metrics.waf_denied),
            if snap.metrics.waf_denied > 0 {
                Color::Magenta
            } else {
                Color::DarkGray
            },
        ),
        kv_styled(
            "rate limited",
            &fmt_int(snap.metrics.rate_limited),
            if snap.metrics.rate_limited > 0 {
                Color::Yellow
            } else {
                Color::DarkGray
            },
        ),
    ];
    let p = Paragraph::new(lines).block(panel(" status "));
    f.render_widget(p, area);
}

fn draw_sparkline(f: &mut Frame, area: Rect, app: &App, snap: &Snapshot) {
    let data: Vec<u64> = app.rps_history.iter().copied().collect();
    let max_seen = data.iter().copied().max().unwrap_or(0);
    let projected = snap.platform.projected_kreqs_cached.saturating_mul(1000);
    let title = format!(
        " req/s   peak {}   ceiling ~{}/s   projected {}K/s ",
        fmt_int(max_seen),
        fmt_int(projected),
        snap.platform.projected_kreqs_cached
    );
    let s = Sparkline::default()
        .block(panel_titled(&title))
        .data(&data)
        .style(Style::default().fg(Color::Cyan))
        .max(max_seen.max(projected.max(1)));
    f.render_widget(s, area);
}

fn draw_cache(f: &mut Frame, area: Rect, snap: &Snapshot) {
    let total = snap.metrics.cache_hits + snap.metrics.cache_misses;
    let hit_ratio = if total > 0 {
        (snap.metrics.cache_hits as f64 / total as f64 * 100.0).round() as u16
    } else {
        0
    };
    // Vertical sub-layout: hits/misses paragraph + gauge
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let lines = vec![
        kv("hits", &fmt_int(snap.metrics.cache_hits)),
        kv("misses", &fmt_int(snap.metrics.cache_misses)),
    ];
    let p = Paragraph::new(lines).block(panel(" cache "));
    f.render_widget(p, inner[0]);

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(" hit rate ", Style::default().fg(Color::Cyan))),
        )
        .gauge_style(Style::default().fg(Color::Green).bg(Color::Black))
        .percent(hit_ratio.min(100))
        .label(format!("{}%", hit_ratio));
    f.render_widget(gauge, inner[1]);
}

fn draw_upstreams(f: &mut Frame, area: Rect, snap: &Snapshot) {
    let header = Row::new(vec!["", "upstream", "status", "latency"])
        .style(Style::default().fg(Color::DarkGray))
        .height(1);

    let rows: Vec<Row> = if snap.upstreams.is_empty() {
        vec![Row::new(vec!["", "no upstreams configured", "", ""])
            .style(Style::default().fg(Color::DarkGray))]
    } else {
        snap.upstreams
            .iter()
            .map(|u| {
                let dot = if u.healthy { "●" } else { "○" };
                let dot_color = if u.healthy { Color::Green } else { Color::Red };
                let status_text = if u.healthy { "healthy" } else { "DOWN" };
                let latency = if u.healthy && u.latency_us > 0 {
                    fmt_us(u.latency_us)
                } else {
                    "—".to_string()
                };
                Row::new(vec![
                    ratatui::text::Text::from(Span::styled(
                        dot,
                        Style::default().fg(dot_color).add_modifier(Modifier::BOLD),
                    )),
                    ratatui::text::Text::from(u.url.clone()),
                    ratatui::text::Text::from(Span::styled(
                        status_text,
                        Style::default().fg(if u.healthy { Color::Green } else { Color::Red }),
                    )),
                    ratatui::text::Text::from(latency),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(2),
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(12),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(panel(" upstreams "));
    f.render_widget(table, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![
        Span::styled(
            "q",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "p",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            if app.paused { " resume  " } else { " pause  " },
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            "r",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" redraw  ", Style::default().fg(Color::DarkGray)),
    ];
    if app.paused {
        spans.push(Span::styled(
            "[ PAUSED ]  ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(err) = &app.last_error {
        spans.push(Span::styled(
            format!("err: {}  ", truncate(err, 60)),
            Style::default().fg(Color::Red),
        ));
    } else {
        spans.push(Span::styled(
            format!("ok ({} fetches)", app.fetch_ok),
            Style::default().fg(Color::DarkGray),
        ));
    }
    let p = Paragraph::new(Line::from(spans));
    f.render_widget(p, area);
}

// ───────────────────────────────────────────────────────────────────
// LITTLE HELPERS
// ───────────────────────────────────────────────────────────────────

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(title, Style::default().fg(Color::Cyan)))
}

fn panel_titled(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title.to_string(),
            Style::default().fg(Color::Cyan),
        ))
}

fn kv(key: &str, val: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {:<14}", key),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(val.to_string()),
    ])
}

fn kv_styled(key: &str, val: &str, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {:<14}", key),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            val.to_string(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn bar_line(label: &str, pct: u16, n: u64, color: Color) -> Line<'static> {
    let bars = (pct as usize / 5).min(20); // 0..20 chars, 5% per char
    let spark = "█".repeat(bars);
    let pad = " ".repeat(20 - bars);
    Line::from(vec![
        Span::styled(
            format!(" {:<5}", label),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(spark, Style::default().fg(color)),
        Span::raw(pad),
        Span::raw(format!(" {:>3}%  ", pct)),
        Span::styled(fmt_int(n), Style::default().fg(Color::DarkGray)),
    ])
}

fn pct(n: u64, total: u64) -> u16 {
    if total == 0 {
        0
    } else {
        ((n as f64 / total as f64) * 100.0).round() as u16
    }
}

fn fmt_int(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut digits: Vec<char> = Vec::with_capacity(20);
    while n > 0 {
        digits.push(char::from_digit((n % 10) as u32, 10).unwrap());
        n /= 10;
    }
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.iter().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(*c);
    }
    out.chars().rev().collect()
}

fn fmt_us(us: u64) -> String {
    if us == 0 {
        return "—".to_string();
    }
    if us >= 1_000_000 {
        format!("{:.1} s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.1} ms", us as f64 / 1_000.0)
    } else {
        format!("{} μs", us)
    }
}

fn fmt_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{}h {:02}m", h, m)
    } else if m > 0 {
        format!("{}m {:02}s", m, s)
    } else {
        format!("{}s", s)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

// ───────────────────────────────────────────────────────────────────
// MINIMAL HTTP CLIENT — std::net::TcpStream, no async, no extra deps
// ───────────────────────────────────────────────────────────────────

fn fetch_snapshot(url: &str) -> Result<Snapshot, String> {
    let (host, port, path) = parse_http_url(url)?;
    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    stream.set_read_timeout(Some(FETCH_TIMEOUT)).ok();
    stream.set_write_timeout(Some(FETCH_TIMEOUT)).ok();
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: zion-top/{ver}\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\
         \r\n",
        ver = env!("CARGO_PKG_VERSION"),
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read: {e}"))?;

    let header_end = find_double_crlf(&buf)
        .ok_or_else(|| "malformed response: no header terminator".to_string())?;
    let head = std::str::from_utf8(&buf[..header_end - 4])
        .map_err(|_| "non-utf8 response headers".to_string())?;
    let status_line = head.lines().next().unwrap_or("");
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    let status: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    if status != 200 {
        let body = String::from_utf8_lossy(&buf[header_end..]);
        return Err(format!("HTTP {} — {}", status, truncate(body.trim(), 80)));
    }

    let body = &buf[header_end..];
    serde_json::from_slice::<Snapshot>(body).map_err(|e| format!("decode snapshot: {e}"))
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// URLs supported".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // IPv6 in brackets: e.g. [::1]:80
    let (host, port) = if let Some(end) = authority.strip_prefix('[') {
        let close = end
            .find(']')
            .ok_or_else(|| "malformed IPv6 in URL".to_string())?;
        let host = &end[..close];
        let after = &end[close + 1..];
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(80);
        (host.to_string(), port)
    } else if let Some(idx) = authority.rfind(':') {
        let host = &authority[..idx];
        let port = authority[idx + 1..].parse::<u16>().unwrap_or(80);
        (host.to_string(), port)
    } else {
        (authority.to_string(), 80)
    };
    Ok((host, port, path.to_string()))
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_default_port() {
        let (h, p, path) = parse_http_url("http://localhost/_zion/snapshot.json").unwrap();
        assert_eq!(h, "localhost");
        assert_eq!(p, 80);
        assert_eq!(path, "/_zion/snapshot.json");
    }

    #[test]
    fn parse_url_with_port() {
        let (h, p, path) = parse_http_url("http://1.2.3.4:9000/snap").unwrap();
        assert_eq!(h, "1.2.3.4");
        assert_eq!(p, 9000);
        assert_eq!(path, "/snap");
    }

    #[test]
    fn parse_url_ipv6() {
        let (h, p, path) = parse_http_url("http://[::1]:8080/x").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 8080);
        assert_eq!(path, "/x");
    }

    #[test]
    fn parse_url_no_path() {
        let (h, p, path) = parse_http_url("http://host:1").unwrap();
        assert_eq!(h, "host");
        assert_eq!(p, 1);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_rejects_https() {
        assert!(parse_http_url("https://x").is_err());
    }

    #[test]
    fn fmt_int_formats_thousands() {
        assert_eq!(fmt_int(0), "0");
        assert_eq!(fmt_int(123), "123");
        assert_eq!(fmt_int(1_234), "1,234");
        assert_eq!(fmt_int(12_345_678), "12,345,678");
    }

    #[test]
    fn fmt_us_breakpoints() {
        assert_eq!(fmt_us(0), "—");
        assert_eq!(fmt_us(500), "500 μs");
        assert_eq!(fmt_us(1_500), "1.5 ms");
        assert_eq!(fmt_us(2_000_000), "2.0 s");
    }

    #[test]
    fn fmt_uptime_breakpoints() {
        assert_eq!(fmt_uptime(5), "5s");
        assert_eq!(fmt_uptime(125), "2m 05s");
        assert_eq!(fmt_uptime(7325), "2h 02m");
    }

    #[test]
    fn double_crlf_present() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(find_double_crlf(buf), Some(buf.len() - 2));
    }

    #[test]
    fn double_crlf_absent() {
        assert_eq!(find_double_crlf(b"no terminator"), None);
    }

    #[test]
    fn snapshot_deserializes() {
        let json = r#"{
          "version":"0.1.1","timestamp_ms":0,"uptime_secs":42,
          "platform":{"os":"linux","arch":"x86_64","cores":4,"ram_mb":8000,
            "tier":"A","tier_score":60,"projected_kreqs_cached":50,"projected_kreqs_dynamic":12,
            "has_aes_ni":true,"has_sha256":true,"has_avx2":true,"has_neon":false,
            "has_so_reuseport":true,"has_tcp_fastopen":true,"has_tcp_quickack":true,
            "worker_threads":3,"conn_limit":10000},
          "metrics":{"requests_total":10,"requests_2xx":9,"requests_4xx":1,"requests_5xx":0,
            "waf_denied":0,"rate_limited":0,"cache_hits":5,"cache_misses":5,
            "websocket_upgrades":0,"active_connections":2,"connections_total":7,"tls_handshake_errors":0,
            "request_p50_us":1000,"request_p95_us":4000,"request_p99_us":8000,
            "upstream_p50_us":900,"upstream_p95_us":3000,"upstream_p99_us":6000,
            "tls_p50_us":500,"tls_p95_us":900},
          "upstreams":[{"url":"http://1.2.3.4","healthy":true,"latency_us":1234}]
        }"#;
        let s: Snapshot = serde_json::from_str(json).unwrap();
        assert_eq!(s.platform.tier, "A");
        assert_eq!(s.metrics.requests_total, 10);
        assert_eq!(s.upstreams.len(), 1);
        assert!(s.upstreams[0].healthy);
    }
}
