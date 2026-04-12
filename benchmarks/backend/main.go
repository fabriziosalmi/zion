package main

import (
	"fmt"
	"net/http"
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

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>ok</body></html>")
	})

	fmt.Println("bench-backend listening on :9090")
	http.ListenAndServe(":9090", mux)
}
