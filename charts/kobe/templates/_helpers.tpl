{{/*
Chart name, truncated to 63 chars.
*/}}
{{- define "kobe.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name, truncated to 63 chars.
*/}}
{{- define "kobe.fullname" -}}
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
Chart label value: name-version
*/}}
{{- define "kobe.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Standard labels applied to every resource.
*/}}
{{- define "kobe.labels" -}}
helm.sh/chart: {{ include "kobe.chart" . }}
{{ include "kobe.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (used in Deployment matchLabels and Service selector).
*/}}
{{- define "kobe.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kobe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "kobe.serviceAccountName" -}}
{{- default (include "kobe.fullname" .) .Values.serviceAccount.name }}
{{- end }}

{{/* Receipt authority identity and pod selector are deliberately distinct. */}}
{{- define "kobe.teardownAuthorityServiceAccountName" -}}
{{- printf "%s-teardown-authority" (include "kobe.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kobe.teardownAuthorityPolicyName" -}}
{{- printf "%s-teardown-authority" (include "kobe.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
The proof identity lives outside every namespace the general controller may
mutate. A release-derived hash prevents two equal release names in different
namespaces from sharing the token-mint boundary.
*/}}
{{- define "kobe.teardownAuthorityNamespace" -}}
{{- $identity := printf "%s/%s" .Release.Namespace .Release.Name -}}
{{- $prefix := printf "%s-teardown-authority" .Release.Name | trunc 46 | trimSuffix "-" -}}
{{- printf "%s-%s" $prefix ($identity | sha256sum | trunc 12) -}}
{{- end }}

{{- define "kobe.teardownAuthoritySelectorLabels" -}}
app.kubernetes.io/name: {{ printf "%s-teardown-authority" (include "kobe.name" .) | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Dedicated namespace for the Sandbox admission CAS ledger. Release namespace
and name are immutable Helm identity; the hash prevents cluster-scoped
collisions between equal release names in different namespaces. This value is
intentionally not configurable because moving the ledger would expose retained
old tokens and reset admission capacity.
*/}}
{{- define "kobe.sandboxLedgerNamespace" -}}
{{- $identity := printf "%s/%s" .Release.Namespace .Release.Name -}}
{{- $prefix := printf "%s-sandbox-ledger" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- printf "%s-%s" $prefix ($identity | sha256sum | trunc 12) -}}
{{- end }}

{{- define "kobe.sandboxLedgerPolicyName" -}}
{{- include "kobe.sandboxLedgerNamespace" . }}
{{- end }}

{{/*
Cluster-scoped admission policy that consumes namespaced, immutable teardown
fence ConfigMaps. Include the release namespace in the hash so two Helm
releases with the same name cannot collide.
*/}}
{{- define "kobe.sandboxTeardownFencePolicyName" -}}
{{- $identity := printf "%s/%s" .Release.Namespace .Release.Name -}}
{{- $prefix := printf "%s-sandbox-teardown-fence" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- printf "%s-%s" $prefix ($identity | sha256sum | trunc 12) -}}
{{- end }}

{{/*
kobe-sync sidecar image reference.
*/}}
{{- define "kobe.syncImage" -}}
{{- $repo := .Values.kobeSync.image.repository -}}
{{- $tag := .Values.kobeSync.image.tag | default (printf "v%s" .Chart.AppVersion) -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end }}
