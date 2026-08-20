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
kobe-sync sidecar image reference.
*/}}
{{- define "kobe.syncImage" -}}
{{- $repo := .Values.kobeSync.image.repository -}}
{{- $tag := .Values.kobeSync.image.tag | default (printf "v%s" .Chart.AppVersion) -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end }}
