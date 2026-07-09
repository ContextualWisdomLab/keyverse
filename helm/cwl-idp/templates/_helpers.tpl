{{- define "cwl-idp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cwl-idp.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "cwl-idp.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cwl-idp.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cwl-idp.labels" -}}
app.kubernetes.io/name: {{ include "cwl-idp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
