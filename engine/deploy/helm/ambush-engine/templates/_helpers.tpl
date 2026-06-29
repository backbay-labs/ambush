{{- define "ambush-engine.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ambush-engine.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "ambush-engine.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ambush-engine.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ambush-engine.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ambush-engine.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "ambush-engine.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "ambush-engine.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "ambush-engine.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ambush-engine.natsServiceName" -}}
{{- printf "%s-nats" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ambush-engine.stateRoot" -}}
{{- $stateRoot := .Values.runtimePaths.stateRoot | default .Values.persistence.mountPath -}}
{{- if empty $stateRoot -}}
{{- fail "runtimePaths.stateRoot or persistence.mountPath must be set" -}}
{{- end -}}
{{- $stateRoot -}}
{{- end -}}

{{- define "ambush-engine.tlsSecretName" -}}
{{- if .Values.tls.existingSecret -}}
{{- .Values.tls.existingSecret -}}
{{- else -}}
{{- printf "%s-tls" (include "ambush-engine.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ambush-engine.renderConfig" -}}
{{- $config := fromYaml (toYaml .Values.swarmConfig) -}}
{{- $stateRoot := include "ambush-engine.stateRoot" . -}}
{{- $runtime := default (dict) $config.runtime -}}
{{- if and (or .Values.secrets.enabled .Values.secrets.existingSecret) (empty $runtime.secret_dir) -}}
{{- $_ := set $runtime "secret_dir" .Values.secrets.mountPath -}}
{{- end -}}
{{- $_ := set $config "runtime" $runtime -}}

{{- $pheromone := default (dict) $config.pheromone -}}
{{- $backend := default (dict) $pheromone.backend -}}
{{- $backendKind := default "" $backend.kind -}}
{{- if eq $backendKind "local_journal" -}}
{{- $backend = dict "kind" "local_journal" "path" (printf "%s/pheromones/pheromones.jsonl" $stateRoot) -}}
{{- else if eq $backendKind "jet_stream" -}}
{{- $backendUrl := $backend.url -}}
{{- if and .Values.nats.enabled (empty $backendUrl) -}}
{{- $backendUrl = (printf "nats://%s:%v" (include "ambush-engine.natsServiceName" .) .Values.nats.service.port) -}}
{{- end -}}
{{- $backend = dict "kind" "jet_stream" "url" $backendUrl "connect_timeout_ms" (default 5000 $backend.connect_timeout_ms) "gc_page_size" (default 512 $backend.gc_page_size) -}}
{{- else if eq $backendKind "in_memory" -}}
{{- $backend = dict "kind" "in_memory" -}}
{{- end -}}
{{- $_ := set $pheromone "backend" $backend -}}
{{- $_ := set $config "pheromone" $pheromone -}}

{{- $audit := default (dict) $config.audit -}}
{{- $auditBundleStore := default (dict) $audit.bundle_store -}}
{{- if eq (default "" $auditBundleStore.kind) "local_files" -}}
{{- $_ := set $auditBundleStore "directory" (printf "%s/replay" $stateRoot) -}}
{{- end -}}
{{- $_ := set $audit "bundle_store" $auditBundleStore -}}
{{- $_ := set $config "audit" $audit -}}

{{- $investigation := default (dict) $config.investigation -}}
{{- $investigationBundleStore := default (dict) $investigation.bundle_store -}}
{{- if eq (default "" $investigationBundleStore.kind) "local_files" -}}
{{- $_ := set $investigationBundleStore "directory" (printf "%s/investigations" $stateRoot) -}}
{{- end -}}
{{- $_ := set $investigation "bundle_store" $investigationBundleStore -}}
{{- $_ := set $config "investigation" $investigation -}}

{{- $correlation := default (dict) $config.correlation -}}
{{- $incidentStore := default (dict) $correlation.incident_store -}}
{{- if eq (default "" $incidentStore.kind) "local_files" -}}
{{- $_ := set $incidentStore "directory" (printf "%s/incidents" $stateRoot) -}}
{{- end -}}
{{- $_ := set $correlation "incident_store" $incidentStore -}}
{{- $_ := set $config "correlation" $correlation -}}

{{- $identity := default (dict) $config.identity -}}
{{- if empty $identity.agent_key_dir -}}
{{- $_ := set $identity "agent_key_dir" (printf "%s/agent-keys" $stateRoot) -}}
{{- end -}}
{{- if empty $identity.registry_dir -}}
{{- $_ := set $identity "registry_dir" (printf "%s/agent-identity" $stateRoot) -}}
{{- end -}}
{{- $_ := set $config "identity" $identity -}}

{{- $responseAdapter := default (dict) $config.response_adapter -}}
{{- $responseAdapterKind := default "" $responseAdapter.kind -}}
{{- if or (eq $responseAdapterKind "http_edr") (eq $responseAdapterKind "webhook") -}}
{{- if empty $responseAdapter.dead_letter_path -}}
{{- $_ := set $responseAdapter "dead_letter_path" (printf "%s/dead-letter/response-actions.jsonl" $stateRoot) -}}
{{- end -}}
{{- end -}}
{{- $_ := set $config "response_adapter" $responseAdapter -}}

{{- $siemForward := $config.siem_forward -}}
{{- if $siemForward -}}
{{- if empty $siemForward.dead_letter_path -}}
{{- $_ := set $siemForward "dead_letter_path" (printf "%s/dead-letter/siem.jsonl" $stateRoot) -}}
{{- end -}}
{{- $_ := set $config "siem_forward" $siemForward -}}
{{- end -}}

{{- $channels := default (dict) $config.notification_channels -}}
{{- range $channelName, $channel := $channels -}}
{{- if empty $channel.dead_letter_path -}}
{{- $_ := set $channel "dead_letter_path" (printf "%s/dead-letter/notification-%s.jsonl" $stateRoot $channelName) -}}
{{- end -}}
{{- $_ := set $channels $channelName $channel -}}
{{- end -}}
{{- $_ := set $config "notification_channels" $channels -}}

{{- if .Values.tls.enabled -}}
{{- if empty .Values.tls.existingSecret -}}
{{- fail "tls.existingSecret must be set when tls.enabled is true" -}}
{{- end -}}
{{- if empty $config.tls -}}
{{- $tls := dict "cert_path" (printf "%s/%s" .Values.tls.mountPath .Values.tls.certFile) "key_path" (printf "%s/%s" .Values.tls.mountPath .Values.tls.keyFile) -}}
{{- if .Values.tls.clientCaFile -}}
{{- $_ := set $tls "client_ca_cert" (printf "%s/%s" .Values.tls.mountPath .Values.tls.clientCaFile) -}}
{{- end -}}
{{- $_ := set $config "tls" $tls -}}
{{- end -}}
{{- end -}}

{{- toYaml $config -}}
{{- end -}}
