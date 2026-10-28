{{- define "securegate.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "securegate.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "securegate.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{ include "securegate.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "securegate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "securegate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* SSH clients reach securegate only through Traefik with PROXY protocol. */}}
{{- define "securegate.proxyProtocol" -}}
{{- and .Values.traefik.enabled .Values.traefik.ssh.enabled .Values.traefik.ssh.proxyProtocol (not .Values.sshService.enabled) -}}
{{- end -}}

{{- define "securegate.tlsSecret" -}}
{{- if .Values.traefik.tls.secretName -}}
{{- .Values.traefik.tls.secretName -}}
{{- else if .Values.certManager.enabled -}}
{{- printf "%s-tls" (include "securegate.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "securegate.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else if .Values.secretEnv -}}
{{- include "securegate.fullname" . -}}
{{- end -}}
{{- end -}}
