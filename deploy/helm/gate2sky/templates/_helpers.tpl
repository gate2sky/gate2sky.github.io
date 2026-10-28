{{- define "gate2sky.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gate2sky.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "gate2sky.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{ include "gate2sky.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "gate2sky.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gate2sky.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* SSH clients reach gate2sky only through Traefik with PROXY protocol. */}}
{{- define "gate2sky.proxyProtocol" -}}
{{- and .Values.traefik.enabled .Values.traefik.ssh.enabled .Values.traefik.ssh.proxyProtocol (not .Values.sshService.enabled) -}}
{{- end -}}

{{- define "gate2sky.tlsSecret" -}}
{{- if .Values.traefik.tls.secretName -}}
{{- .Values.traefik.tls.secretName -}}
{{- else if .Values.certManager.enabled -}}
{{- printf "%s-tls" (include "gate2sky.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "gate2sky.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else if .Values.secretEnv -}}
{{- include "gate2sky.fullname" . -}}
{{- end -}}
{{- end -}}
