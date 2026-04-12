package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Zion test backend — comprehensive response types for benchmarking.
// Covers: dynamic API, multiple static file types, SSE, large bodies,
// slow responses, error codes, binary payloads, images, WebSocket-like.

// Pre-generated payloads (avoid runtime allocation)
var (
	jsonPayload1KB   string
	jsonPayload10KB  string
	jsPayload4KB     string
	cssPayload3KB    string
	htmlPage5KB      string
	svgImage2KB      string
	pngFakeHeader    []byte
	woffFakePayload  []byte
	randomBinary100K []byte
)

func init() {
	// 1KB JSON
	items := make([]map[string]any, 10)
	for i := range items {
		items[i] = map[string]any{"id": i + 1, "name": fmt.Sprintf("item-%d", i+1), "value": float64(i) * 1.23}
	}
	b, _ := json.Marshal(map[string]any{"status": "ok", "data": items})
	jsonPayload1KB = string(b)

	// 10KB JSON
	bigItems := make([]map[string]any, 100)
	for i := range bigItems {
		bigItems[i] = map[string]any{"id": i, "name": fmt.Sprintf("item-%d", i), "desc": strings.Repeat("x", 50), "val": float64(i)}
	}
	b2, _ := json.Marshal(map[string]any{"status": "ok", "total": 100, "data": bigItems})
	jsonPayload10KB = string(b2)

	// 4KB JS
	jsPayload4KB = "/* chunk.js */\n" + strings.Repeat("var x = function() { return 'data'; };\n", 80)

	// 3KB CSS
	cssPayload3KB = "/* styles.css */\n" + strings.Repeat("body{margin:0;} .container{display:flex;} .item{padding:1rem;}\n", 40)

	// 5KB HTML
	rows := strings.Repeat("<tr><td>Name</td><td>Value</td><td>Description of item</td></tr>\n", 60)
	htmlPage5KB = fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Zion Dashboard</title><link rel="stylesheet" href="/static/style.css"></head>
<body><h1>Dashboard</h1><table>%s</table>
<script src="/static/app.js"></script></body></html>`, rows)

	// 2KB SVG
	circles := strings.Repeat(`<circle cx="50" cy="50" r="40" fill="blue"/>`, 20)
	svgImage2KB = fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">%s</svg>`, circles)

	// Fake PNG header (valid signature + minimal IHDR)
	pngFakeHeader = make([]byte, 8192)
	copy(pngFakeHeader, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	rand.Read(pngFakeHeader[8:])

	// Fake WOFF2 font
	woffFakePayload = make([]byte, 16384)
	copy(woffFakePayload, []byte("wOF2"))
	rand.Read(woffFakePayload[4:])

	// 100KB random binary
	randomBinary100K = make([]byte, 102400)
	rand.Read(randomBinary100K)
}

func main() {
	mux := http.NewServeMux()

	// ═══════════════════════════════════════════════════════════
	// DYNAMIC API
	// ═══════════════════════════════════════════════════════════

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/api/v1/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jsonPayload1KB)
	})

	mux.HandleFunc("/api/v1/data/large", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jsonPayload10KB)
	})

	mux.HandleFunc("/api/v1/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method":            r.Method,
			"path":              r.URL.Path,
			"query":             r.URL.RawQuery,
			"content_type":      r.Header.Get("Content-Type"),
			"body_len":          len(body),
			"body":              string(body),
			"remote_addr":       r.RemoteAddr,
			"x_forwarded_for":   r.Header.Get("X-Forwarded-For"),
			"x_real_ip":         r.Header.Get("X-Real-IP"),
			"x_forwarded_proto": r.Header.Get("X-Forwarded-Proto"),
		})
	})

	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"created": true, "method": r.Method, "body": string(body)})
	})

	// ═══════════════════════════════════════════════════════════
	// STATIC FILES — diverse content types
	// ═══════════════════════════════════════════════════════════

	// JavaScript
	mux.HandleFunc("/_next/static/chunk.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fmt.Fprint(w, jsPayload4KB)
	})

	// CSS
	mux.HandleFunc("/_next/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fmt.Fprint(w, cssPayload3KB)
	})

	// SVG image
	mux.HandleFunc("/_next/static/icon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fmt.Fprint(w, svgImage2KB)
	})

	// PNG image (binary)
	mux.HandleFunc("/_next/static/hero.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(pngFakeHeader)
	})

	// WOFF2 font (binary)
	mux.HandleFunc("/_next/static/font.woff2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "font/woff2")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(woffFakePayload)
	})

	// JSON manifest
	mux.HandleFunc("/_next/static/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fmt.Fprint(w, `{"name":"Zion","version":"1.0.0","icons":[{"src":"/icon.svg","sizes":"any"}]}`)
	})

	// ═══════════════════════════════════════════════════════════
	// SPECIAL ENDPOINTS
	// ═══════════════════════════════════════════════════════════

	// SSE streaming (fast — 100ms per event, 3 events)
	mux.HandleFunc("/api/v1/events/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush", 500)
			return
		}
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "event: tick\ndata: {\"seq\":%d}\n\n", i)
			flusher.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})

	// Large binary response (configurable size)
	mux.HandleFunc("/api/v1/large", func(w http.ResponseWriter, r *http.Request) {
		sizeStr := r.URL.Query().Get("size")
		size := 102400
		if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 100*1024*1024 {
			size = s
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		// Stream in 64KB chunks to avoid massive single alloc
		written := 0
		for written < size {
			chunk := size - written
			if chunk > 65536 {
				chunk = 65536
			}
			if chunk <= len(randomBinary100K) {
				w.Write(randomBinary100K[:chunk])
			} else {
				w.Write(make([]byte, chunk))
			}
			written += chunk
		}
	})

	// Large static file simulation (configurable size, with Cache-Control)
	mux.HandleFunc("/_next/static/blob", func(w http.ResponseWriter, r *http.Request) {
		sizeStr := r.URL.Query().Get("size")
		size := 102400
		if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 100*1024*1024 {
			size = s
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		written := 0
		for written < size {
			chunk := size - written
			if chunk > 65536 {
				chunk = 65536
			}
			if chunk <= len(randomBinary100K) {
				w.Write(randomBinary100K[:chunk])
			} else {
				w.Write(make([]byte, chunk))
			}
			written += chunk
		}
	})

	// Slow response (configurable delay)
	mux.HandleFunc("/api/v1/slow", func(w http.ResponseWriter, r *http.Request) {
		ms := 1000
		if d, err := strconv.Atoi(r.URL.Query().Get("ms")); err == nil && d > 0 && d <= 30000 {
			ms = d
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"delayed_ms":%d}`, ms)
	})

	// Error code mirror
	mux.HandleFunc("/api/v1/status/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		code := 200
		if len(parts) > 4 {
			if c, err := strconv.Atoi(parts[4]); err == nil && c >= 100 && c < 600 {
				code = c
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"status":%d}`, code)
	})

	// HTML (SSR simulation)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlPage5KB)
	})

	fmt.Println("test-server listening on :9090")
	http.ListenAndServe(":9090", mux)
}
