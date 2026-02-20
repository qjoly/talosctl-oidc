# Stage 1: Build the binary
FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /talosctl-oidc .

# Stage 2: Talos system extension image (must be FROM scratch)
FROM scratch AS extension

# Extension metadata
COPY manifest.yaml /

# Place the binary in the extension service container rootfs
COPY --from=builder /talosctl-oidc /rootfs/usr/local/lib/containers/talosctl-oidc/talosctl-oidc

# Include the system CA bundle so the binary can verify TLS certificates
# (e.g. when fetching the OIDC discovery document from an HTTPS endpoint).
# The builder image (golang:alpine) provides this at the standard location.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Extension service configuration
COPY talosctl-oidc.yaml /rootfs/usr/local/etc/containers/talosctl-oidc.yaml

CMD ["/rootfs/usr/local/lib/containers/talosctl-oidc/talosctl-oidc", "serve"]
