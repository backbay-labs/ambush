{{- define "swarm-team-six.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "swarm-team-six.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "swarm-team-six.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "swarm-team-six.selectorLabels" -}}
app.kubernetes.io/name: {{ include "swarm-team-six.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "swarm-team-six.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "swarm-team-six.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "swarm-team-six.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "swarm-team-six.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "swarm-team-six.natsServiceName" -}}
{{- printf "%s-nats" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "swarm-team-six.renderConfig" -}}
{{- $config := fromYaml (toYaml .Values.swarmConfig) -}}
{{- if and (or .Values.secrets.enabled .Values.secrets.existingSecret) (empty $config.runtime.secret_dir) -}}
{{- $_ := set $config.runtime "secret_dir" .Values.secrets.mountPath -}}
{{- end -}}
{{- if and (eq $config.pheromone.backend.kind "jet_stream") .Values.nats.enabled (empty $config.pheromone.backend.url) -}}
{{- $_ := set $config.pheromone.backend "url" (printf "nats://%s:%v" (include "swarm-team-six.natsServiceName" .) .Values.nats.service.port) -}}
{{- end -}}
{{- toYaml $config -}}
{{- end -}}
