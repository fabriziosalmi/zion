// gRPC client for the measurements: what it sends depends on the mode.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"h2rig/rigpb"
)

func main() {
	target, mode := os.Args[1], os.Args[2]
	n, _ := strconv.Atoi(os.Args[3])
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64<<20)))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	c := rigpb.NewRigClient(conn)
	ctx := context.Background()
	start := time.Now()
	switch mode {
	case "download": // n MiB as 1 MiB messages in one server stream
		s, err := c.Download(ctx, &rigpb.Req{Bytes: int64(n) << 20, Chunk: 1 << 20})
		if err != nil {
			log.Fatal(err)
		}
		var got int64
		for {
			m, err := s.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
			got += int64(len(m.Data))
		}
		fmt.Printf("download: %d MiB in %v\n", got>>20, time.Since(start).Round(time.Millisecond))
	case "small": // n MiB as 16 KiB messages (many DATA frames, many window updates)
		s, err := c.Download(ctx, &rigpb.Req{Bytes: int64(n) << 20, Chunk: 16 << 10})
		if err != nil {
			log.Fatal(err)
		}
		var got int64
		for {
			m, err := s.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
			got += int64(len(m.Data))
		}
		fmt.Printf("small messages: %d MiB in %v\n", got>>20, time.Since(start).Round(time.Millisecond))
	case "unary": // n unary calls from 8 goroutines: many streams, one connection
		var wg sync.WaitGroup
		per := n / 8
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < per; i++ {
					if _, err := c.Echo(ctx, &rigpb.Chunk{Data: []byte("x")}); err != nil {
						log.Print(err)
						return
					}
				}
			}()
		}
		wg.Wait()
		fmt.Printf("unary: %d calls in %v\n", per*8, time.Since(start).Round(time.Millisecond))
	case "chat": // n small messages ping-ponged on one bidirectional stream
		s, err := c.Chat(ctx)
		if err != nil {
			log.Fatal(err)
		}
		for i := 0; i < n; i++ {
			if err := s.Send(&rigpb.Chunk{Data: []byte("x")}); err != nil {
				log.Fatal(err)
			}
			if _, err := s.Recv(); err != nil {
				log.Fatal(err)
			}
		}
		s.CloseSend()
		fmt.Printf("chat: %d round trips in %v\n", n, time.Since(start).Round(time.Millisecond))
	}
}
