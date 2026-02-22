# Extract your Talos CA cert and key from your talosconfig and base64-decode them:
#
#   CONTEXT=$(talosctl config info --output json | jq -r '.context')
#   CA_CERT=$(talosctl config info --output json | jq -r '.contexts[env.CONTEXT].ca' | base64 -d)
#   CA_KEY=<the CA private key — only available from the secrets bundle used when bootstrapping the cluster>
#
# Then pass them inline below. Note: the values must be PEM-encoded.

helm upgrade --install talosctl-oidc -n talos-system oci://ghcr.io/qjoly/charts/talosctl-oidc --version 0.0.0-pr-71 \
  --set-file talos.caCertData=temp/talos-os-ca.crt \
  --set-file talos.caKeyData=temp/talos-os-ca.key \
  --set config.issuerUrl=https://oidc.home.une-tasse-de.cafe/application/o/talos-oidc/ \
  --set config.clientId=Mh3sbRbUpgPKKH0PUJceQ3l42wmkkJjmlGfgkEDz \
  --set-json 'config.endpoints=["192.168.0.42"]'
