{{/*
Expand the name of the chart.
*/}}
{{- define "talosctl-oidc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "talosctl-oidc.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "talosctl-oidc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "talosctl-oidc.labels" -}}
helm.sh/chart: {{ include "talosctl-oidc.chart" . }}
{{ include "talosctl-oidc.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "talosctl-oidc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "talosctl-oidc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "talosctl-oidc.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "talosctl-oidc.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding the server's TLS keypair, or "" when no certificate
source is configured and the server should fall back to a self-signed one.

An explicit existingSecret wins over cert-manager, so an operator can override
a chart-managed certificate without first disabling it.
*/}}
{{- define "talosctl-oidc.tlsSecretName" -}}
{{- if .Values.tls.existingSecret -}}
{{- .Values.tls.existingSecret -}}
{{- else if .Values.tls.certManager.enabled -}}
{{- printf "%s-tls" (include "talosctl-oidc.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Value for TALOSCTL_OIDC_INSECURE.

The pod serves plain HTTP only when TLS is terminated in front of it and it has
no certificate of its own. With SSL passthrough the ingress does not terminate
anything, so the pod must keep speaking TLS.

The server rejects tls_cert together with insecure=true, so the conflicting
combination is caught here rather than as a crash loop.
*/}}
{{- define "talosctl-oidc.insecure" -}}
{{- $tlsSecret := include "talosctl-oidc.tlsSecretName" . -}}
{{- if and $tlsSecret .Values.config.insecure -}}
{{- fail "talosctl-oidc: config.insecure=true conflicts with a TLS certificate source (tls.existingSecret or tls.certManager.enabled). The server refuses to start with both. Unset one of them." -}}
{{- end -}}
{{- if $tlsSecret -}}
false
{{- else if .Values.config.insecure -}}
true
{{- else if and .Values.ingress.enabled .Values.ingress.tls (not .Values.ingress.sslPassthrough) -}}
true
{{- else -}}
false
{{- end -}}
{{- end }}

{{/*
DNS names for the cert-manager Certificate.

When the operator supplies dnsNames they are used verbatim. Otherwise they are
derived from how the server is actually reached, and deliberately not mixed:

  - with an ingress, only the ingress hosts. Adding the in-cluster names here
    would break issuance against a public ACME issuer, which cannot validate a
    .svc.cluster.local name.
  - without an ingress, only the Service names, which is how clients reach it.

Set dnsNames explicitly to cover both.
*/}}
{{- define "talosctl-oidc.certDNSNames" -}}
{{- if .Values.tls.certManager.dnsNames -}}
{{- toYaml .Values.tls.certManager.dnsNames -}}
{{- else -}}
{{- $fullName := include "talosctl-oidc.fullname" . -}}
{{- $names := list -}}
{{- if .Values.ingress.enabled -}}
{{- range .Values.ingress.hosts -}}
{{- if .host -}}
{{- $names = append $names .host -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not $names -}}
{{- $names = list $fullName (printf "%s.%s" $fullName .Release.Namespace) (printf "%s.%s.svc" $fullName .Release.Namespace) (printf "%s.%s.svc.cluster.local" $fullName .Release.Namespace) -}}
{{- end -}}
{{- toYaml (uniq $names) -}}
{{- end -}}
{{- end }}
