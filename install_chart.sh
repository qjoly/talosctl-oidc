helm upgrade --install talosctl-oidc -n talos-system oci://ghcr.io/qjoly/charts/talosctl-oidc:pr-71 \
  --set talos.apiAccess.enabled=true \
  --set config.issuerUrl=https://oidc.home.une-tasse-de.cafe/application/o/talos-oidc/ \
  --set config.clientId=Mh3sbRbUpgPKKH0PUJceQ3l42wmkkJjmlGfgkEDz \
  --set-json 'config.endpoints=["192.168.0.42"]'
