# No CA needed: the server issues certificates via the Talos API. The chart
# (talos.apiAccess.enabled=true by default) creates a serviceaccounts.talos.dev
# resource so Talos provisions a short-lived credential into the pod.
#
# Prerequisite on the Talos nodes (machine config):
#
#   machine:
#     features:
#       kubernetesTalosAPIAccess:
#         enabled: true
#         allowedRoles: [os:admin]
#         allowedKubernetesNamespaces: [talos-system]

helm upgrade --install talosctl-oidc -n talos-system oci://ghcr.io/qjoly/charts/talosctl-oidc --version 0.0.0-pr-71 \
  --set config.issuerUrl=https://oidc.home.une-tasse-de.cafe/application/o/talos-oidc/ \
  --set config.clientId=talosctl_oidc \
  --set-json 'config.endpoints=["192.168.0.42"]'
