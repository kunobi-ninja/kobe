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
Wagyu-sync sidecar image reference.
*/}}
{{- define "kobe.syncImage" -}}
{{- $repo := .Values.wagyuSync.image.repository -}}
{{- $tag := .Values.wagyuSync.image.tag | default (printf "v%s" .Chart.AppVersion) -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end }}
