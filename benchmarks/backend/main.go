package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Minimal upstream backend for benchmarking.
// Responds with a fixed JSON payload. No framework overhead.
func main() {
	// 1KB JSON payload (realistic API response size)
	payload := `{"status":"ok","data":{"id":1,"name":"benchmark","items":[` +
		strings.Repeat(`{"k":"v"},`, 30) +
		`{"k":"v"}]}}`

	staticPayload := strings.Repeat("x", 4096) // 4KB static asset

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, payload)
	})

	mux.HandleFunc("/api/v1/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, payload)
	})

	mux.HandleFunc("/_next/static/chunk.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fmt.Fprint(w, staticPayload)
	})

	// Sized payload for the baseline payload-matrix (1K/64K/1M/...).
	// ?bytes=N returns a deterministic N-byte octet-stream body. Registered
	// under a cacheable static path and a non-cached api path so the same
	// sizing drives both the cache-hit and proxy-passthrough legs.
	sized := func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
		if err != nil || n < 0 {
			n = 1024
		}
		body := bytes.Repeat([]byte("x"), n)
		w.Header().Set("Content-Type", "application/octet-stream")
		if strings.HasPrefix(r.URL.Path, "/_next/static/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}
	mux.HandleFunc("/_next/static/blob", sized) // cacheable (static_cache route)
	mux.HandleFunc("/api/blob", sized)          // proxy passthrough (standard route)

	// Cache-correctness fixtures (validate the v0.4.2 Age/origin-TTL fix).
	// short-ttl: origin says max-age=5 → zion must honor it (emit max-age=5),
	//            not the profile's 1-year default.
	mux.HandleFunc("/_next/static/shortttl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=5")
		fmt.Fprint(w, staticPayload)
	})
	// stale-born: arrives already older (Age) than its lifetime → zion must
	// stream it through (not freeze a fresh young entry), forwarding the Age.
	mux.HandleFunc("/_next/static/staleborn", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=10")
		w.Header().Set("Age", "99999")
		fmt.Fprint(w, staticPayload)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>ok</body></html>")
	})

	fmt.Println("bench-backend listening on :9090")
	http.ListenAndServe(":9090", mux)
}
