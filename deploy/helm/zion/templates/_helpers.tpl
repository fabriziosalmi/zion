{{/*
Expand the name of the chart.
*/}}
{{- define "zion.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "zion.fullname" -}}
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
{{- define "zion.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "zion.labels" -}}
helm.sh/chart: {{ include "zion.chart" . }}
{{ include "zion.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "zion.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zion.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name to use. Honours .Values.serviceAccount.name when
explicitly set; otherwise derives from the release name. The default
chart auto-creates the SA so you don't need a separate manifest.
*/}}
{{- define "zion.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "zion.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end }}


{{/*
"true" when a HorizontalPodAutoscaler owns the replica count: autoscaling is on and no
ReadWriteOnce volume pins the Deployment to one replica. Empty string otherwise.
*/}}
{{- define "zion.hpaEnabled" -}}
{{- $rwo := and .Values.persistence.enabled (eq .Values.persistence.accessMode "ReadWriteOnce") -}}
{{- if and .Values.autoscaling.enabled (not $rwo) -}}true{{- end -}}
{{- end }}

{{/*
The fewest replicas the Deployment can run with: the HPA minimum, or replicaCount.
*/}}
{{- define "zion.minReplicas" -}}
{{- if include "zion.hpaEnabled" . -}}{{ .Values.autoscaling.minReplicas }}{{- else -}}{{ .Values.replicaCount }}{{- end -}}
{{- end }}
