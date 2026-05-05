FROM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS builder
WORKDIR /app
COPY test-server.go .
RUN go build -o bench-backend test-server.go

FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1
COPY --from=builder /app/bench-backend /usr/local/bin/
EXPOSE 9090
CMD ["bench-backend"]
