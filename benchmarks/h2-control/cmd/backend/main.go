// Backend for the h2 control-frame measurements: an HTTPS (h2) site and a gRPC service.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"google.golang.org/grpc"
	"h2rig/rigpb"
)

type rig struct{ rigpb.UnimplementedRigServer }

func (rig) Download(r *rigpb.Req, s rigpb.Rig_DownloadServer) error {
	chunk := make([]byte, r.Chunk)
	for sent := int64(0); sent < r.Bytes; sent += int64(len(chunk)) {
		if err := s.Send(&rigpb.Chunk{Data: chunk}); err != nil {
			return err
		}
	}
	return nil
}
func (rig) Echo(_ context.Context, c *rigpb.Chunk) (*rigpb.Chunk, error) { return c, nil }
func (rig) Chat(s rigpb.Rig_ChatServer) error {
	for {
		c, err := s.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.Send(c); err != nil {
			return err
		}
	}
}

func main() {
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	gs := grpc.NewServer(grpc.MaxRecvMsgSize(64 << 20))
	rigpb.RegisterRigServer(gs, rig{})

	// The website, also over TLS so zion talks h2 to it.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		var b strings.Builder
		b.WriteString("<!doctype html><html><head><title>rig</title>")
		for i := 0; i < 20; i++ {
			fmt.Fprintf(&b, `<link rel=stylesheet href="/a/%d.css">`, i)
		}
		b.WriteString("</head><body><h1>rig</h1>")
		for i := 0; i < 80; i++ {
			fmt.Fprintf(&b, `<img src="/a/%d.png" width=8 height=8>`, i)
		}
		for i := 0; i < 20; i++ {
			fmt.Fprintf(&b, `<script src="/a/%d.js"></script>`, i)
		}
		b.WriteString("</body></html>")
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, b.String())
	})
	mux.HandleFunc("/a/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".css"):
			w.Header().Set("Content-Type", "text/css")
		case strings.HasSuffix(r.URL.Path, ".js"):
			w.Header().Set("Content-Type", "text/javascript")
		default:
			w.Header().Set("Content-Type", "image/png")
		}
		w.Write(make([]byte, 2048))
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		buf := make([]byte, 1<<20)
		for i := 0; i < 300; i++ { // 300 MiB
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	})
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			gs.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: "127.0.0.1:19444", Handler: root, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
