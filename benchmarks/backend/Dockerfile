FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY test-server.go .
RUN go build -o bench-backend test-server.go

FROM alpine:3.19
COPY --from=builder /app/bench-backend /usr/local/bin/
EXPOSE 9090
CMD ["bench-backend"]
