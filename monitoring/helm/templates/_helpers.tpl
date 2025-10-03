{{/*
Expand the name of the chart.
*/}}
{{- define "marty-monitoring.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "marty-monitoring.fullname" -}}
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
{{- define "marty-monitoring.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "marty-monitoring.labels" -}}
helm.sh/chart: {{ include "marty-monitoring.chart" . }}
{{ include "marty-monitoring.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: marty-monitoring
{{- end }}

{{/*
Selector labels
*/}}
{{- define "marty-monitoring.selectorLabels" -}}
app.kubernetes.io/name: {{ include "marty-monitoring.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Prometheus labels
*/}}
{{- define "marty-monitoring.prometheus.labels" -}}
helm.sh/chart: {{ include "marty-monitoring.chart" . }}
{{ include "marty-monitoring.prometheus.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: marty-monitoring
app.kubernetes.io/component: prometheus
{{- end }}

{{/*
Prometheus selector labels
*/}}
{{- define "marty-monitoring.prometheus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "marty-monitoring.name" . }}-prometheus
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Grafana labels
*/}}
{{- define "marty-monitoring.grafana.labels" -}}
helm.sh/chart: {{ include "marty-monitoring.chart" . }}
{{ include "marty-monitoring.grafana.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: marty-monitoring
app.kubernetes.io/component: grafana
{{- end }}

{{/*
Grafana selector labels
*/}}
{{- define "marty-monitoring.grafana.selectorLabels" -}}
app.kubernetes.io/name: {{ include "marty-monitoring.name" . }}-grafana
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Alertmanager labels
*/}}
{{- define "marty-monitoring.alertmanager.labels" -}}
helm.sh/chart: {{ include "marty-monitoring.chart" . }}
{{ include "marty-monitoring.alertmanager.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: marty-monitoring
app.kubernetes.io/component: alertmanager
{{- end }}

{{/*
Alertmanager selector labels
*/}}
{{- define "marty-monitoring.alertmanager.selectorLabels" -}}
app.kubernetes.io/name: {{ include "marty-monitoring.name" . }}-alertmanager
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use for Prometheus
*/}}
{{- define "marty-monitoring.prometheus.serviceAccountName" -}}
{{- if .Values.prometheus.serviceAccount.create }}
{{- default (printf "%s-prometheus" (include "marty-monitoring.fullname" .)) .Values.prometheus.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.prometheus.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for Grafana
*/}}
{{- define "marty-monitoring.grafana.serviceAccountName" -}}
{{- if .Values.grafana.serviceAccount.create }}
{{- default (printf "%s-grafana" (include "marty-monitoring.fullname" .)) .Values.grafana.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.grafana.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for Alertmanager
*/}}
{{- define "marty-monitoring.alertmanager.serviceAccountName" -}}
{{- if .Values.alertmanager.serviceAccount.create }}
{{- default (printf "%s-alertmanager" (include "marty-monitoring.fullname" .)) .Values.alertmanager.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.alertmanager.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Prometheus server URL
*/}}
{{- define "marty-monitoring.prometheus.url" -}}
{{- printf "http://%s-prometheus:%d" (include "marty-monitoring.fullname" .) (.Values.prometheus.server.service.port | int) }}
{{- end }}

{{/*
Alertmanager URL
*/}}
{{- define "marty-monitoring.alertmanager.url" -}}
{{- printf "http://%s-alertmanager:%d" (include "marty-monitoring.fullname" .) (.Values.alertmanager.service.port | int) }}
{{- end }}

{{/*
Environment-specific configuration
*/}}
{{- define "marty-monitoring.environment" -}}
{{- .Values.global.environment | default "development" }}
{{- end }}

{{/*
Storage class for persistent volumes
*/}}
{{- define "marty-monitoring.storageClass" -}}
{{- if .Values.global.storageClass }}
{{- .Values.global.storageClass }}
{{- else if eq (include "marty-monitoring.environment" .) "production" }}
{{- "ssd" }}
{{- else }}
{{- "standard" }}
{{- end }}
{{- end }}

{{/*
Image pull policy based on environment
*/}}
{{- define "marty-monitoring.imagePullPolicy" -}}
{{- if eq (include "marty-monitoring.environment" .) "production" }}
{{- "Always" }}
{{- else }}
{{- "IfNotPresent" }}
{{- end }}
{{- end }}

{{/*
Resource limits based on environment
*/}}
{{- define "marty-monitoring.resources" -}}
{{- $env := include "marty-monitoring.environment" . }}
{{- $component := .component }}
{{- $resources := index .Values $component "resources" }}
{{- if hasKey .Values.environments $env }}
{{- $envResources := index .Values.environments $env $component "resources" }}
{{- if $envResources }}
{{- toYaml $envResources }}
{{- else }}
{{- toYaml $resources }}
{{- end }}
{{- else }}
{{- toYaml $resources }}
{{- end }}
{{- end }}