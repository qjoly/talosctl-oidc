# Stage 1: Build the binary
FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /talosctl-oidc .

# Stage 2: Kubernetes server image — standard binary path + system CA bundle.
# This is what the Helm chart deploys; it is NOT a Talos extension.
FROM scratch AS server

COPY --from=builder /talosctl-oidc /talosctl-oidc
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

CMD ["/talosctl-oidc", "serve"]

# Stage 3: Talos system extension image (must be FROM scratch)
FROM scratch AS extension

# Extension metadata
COPY manifest.yaml /

# Place the binary in the extension service container rootfs
COPY --from=builder /talosctl-oidc /rootfs/usr/local/lib/containers/talosctl-oidc/talosctl-oidc

# Include the system CA bundle so the binary can verify TLS certificates
# (e.g. when fetching the OIDC discovery document from an HTTPS endpoint).
# Must live under /rootfs/ — Talos extensions may only contain files under
# allowed top-level dirs (rootfs, lib, …); a bare /etc at the image root is
# rejected by the imager with "unexpected file".
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt

# Extension service configuration
COPY talosctl-oidc.yaml /rootfs/usr/local/etc/containers/talosctl-oidc.yaml

CMD ["/rootfs/usr/local/lib/containers/talosctl-oidc/talosctl-oidc", "serve"]
