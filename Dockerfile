# Stage 1: Build the binary
FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /talosctl-oidc .

# Stage 2: Kubernetes server image — standard binary path + system CA bundle.
FROM scratch AS server

COPY --from=builder /talosctl-oidc /talosctl-oidc
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

CMD ["/talosctl-oidc", "serve"]
