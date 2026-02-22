docker run --rm -t -v /dev:/dev --privileged -e GITHUB_TOKEN=$(gh auth token) -v "$PWD/_out:/out" \
  "ghcr.io/siderolabs/imager:v1.12.4" --arch "amd64" \
  --system-extension-image ghcr.io/qjoly/talosctl-oidc:0.0.0-dev installer
docker load -i ./_out/installer-amd64.tar
docker tag ghcr.io/siderolabs/installer:${TALOS_VERSION} ghcr.io/qjoly/talosctl-oidc-installer
