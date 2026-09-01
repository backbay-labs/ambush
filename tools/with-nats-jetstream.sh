#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BASE_COMPOSE="$ROOT_DIR/docker-compose.yml"
PINNED_IMAGE="docker.io/library/nats:2.11.17-alpine@sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00"
PINNED_REPO_DIGEST="nats@sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00"
PINNED_VERSION="2.11.17"
RUNTIME_ACCOUNT="PHASE285_RUNTIME"
WITNESS_ACCOUNT="PHASE285_WITNESS"
EXPECTED_ACCOUNT="PHASE285_WITNESS_STORE"
RUNTIME_USER="phase285_foreign"
RUNTIME_PASSWORD="phase285_foreign_fixed_password"
WITNESS_USER="phase285_witness"
WITNESS_PASSWORD="phase285_witness_fixed_password"
STORE_USER="phase285_witness_store"
STORE_PASSWORD="phase285_witness_store_fixed_password"
INIT_USER="phase285_expected"
INIT_PASSWORD="phase285_expected_fixed_password"
RELAY_USER="phase285_relay"
RELAY_PASSWORD="phase285_relay_fixed_password"
EXPECTED_USER="$INIT_USER"
EXPECTED_PASSWORD="$INIT_PASSWORD"
FOREIGN_ACCOUNT="$RUNTIME_ACCOUNT"
FOREIGN_USER="$RUNTIME_USER"
FOREIGN_PASSWORD="$RUNTIME_PASSWORD"
START_TIMEOUT_SECS="${SWARM_NATS_START_TIMEOUT_SECS:-90}"
WITNESS_FIXTURE_BUCKETS=(
  phase285_b_wrong_revision
  phase285_b_confirmed
  phase285_b_del
  phase285_b_purge
  phase285_b_unknown
  phase285_b_direct
  phase285_c_current
  phase285_c_predecessor
  phase285_c_prepared
  phase285_c_abort
  phase285_c_genesisabort
  phase285_c_anchor
  phase285_c_account
  phase285_c_global
)

paths_overlap() {
  [[ "$1" == "$2" || "$1" == "$2/"* || "$2" == "$1/"* ]]
}

canonical_directory() {
  [[ -d "$1" ]] || return 1
  (cd -- "$1" && pwd -P)
}

docker_shared_scratch_parent() {
  if [[ "$(uname -s)" == Darwin ]]; then
    canonical_directory "/Users/$(id -un)/.codex"
  else
    canonical_directory /tmp
  fi
}

repository_boundaries() {
  canonical_directory "$ROOT_DIR"
  canonical_directory "$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-dir)"
  canonical_directory "$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)"
}

create_confined_scratch() {
  local parent="${1:-${TMPDIR:-/tmp}}" boundary scratch
  parent="$(canonical_directory "$parent")" || {
    echo "PHASE285-HARNESS[scratch-parent]" >&2
    return 1
  }
  while IFS= read -r boundary; do
    if paths_overlap "$parent" "$boundary"; then
      echo "PHASE285-HARNESS[scratch-boundary-overlap]" >&2
      return 1
    fi
  done < <(repository_boundaries)
  scratch="$(mktemp -d "$parent/phase285-nats.XXXXXX")" || return 1
  scratch="$(canonical_directory "$scratch")" || return 1
  [[ -z "$(find "$scratch" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "PHASE285-HARNESS[scratch-not-empty]" >&2
    return 1
  }
  printf '%s\n' "$scratch"
}

cleanup_confined_scratch() {
  local scratch="$1" remover="${2:-/bin/rm}" boundary
  [[ -n "$scratch" && -d "$scratch" ]] || return 1
  while IFS= read -r boundary; do
    paths_overlap "$scratch" "$boundary" && return 1
  done < <(repository_boundaries)
  "$remover" -rf -- "$scratch" || return 1
  [[ ! -e "$scratch" ]]
}

write_configuration() {
  local scratch="$1" topology_mode="${2:-normal}" bucket fixture_init_permissions=""
  for bucket in "${WITNESS_FIXTURE_BUCKETS[@]}"; do
    fixture_init_permissions+=$(printf ',\n            "%s",\n            "%s",\n            "%s",\n            "%s",\n            "%s"' \
      "\$JS.API.STREAM.CREATE.KV_$bucket" \
      "\$JS.API.STREAM.INFO.KV_$bucket" \
      "\$JS.API.STREAM.MSG.GET.KV_$bucket" \
      "\$JS.API.DIRECT.GET.KV_$bucket.>" \
      "\$KV.$bucket.>")
  done
  fixture_init_permissions+=$',\n            "$JS.API.STREAM.DELETE.KV_phase285_c_anchor"'
  cat >"$scratch/nats.conf" <<EOF
server_name: phase285-nats-harness
port: 4222
http_port: 8222
jetstream {
  store_dir: "/data/jetstream"
  sync_interval: always
}
accounts {
  $RUNTIME_ACCOUNT {
    jetstream: enabled
    users: [ {
      user: "$RUNTIME_USER", password: "$RUNTIME_PASSWORD",
      permissions: {
        publish: [
          "swarm.governance.witness.v1.fence",
          "swarm.governance.witness.v1.establish",
          "swarm.governance.witness.v1.discover",
          "swarm.governance.witness.v1.prepare",
          "swarm.governance.witness.v1.commit",
          "swarm.governance.witness.v1.abort",
          "swarm.governance.witness.v1.read_prepared",
          "swarm.governance.witness.v1.read_head",
          "swarm.governance.witness.v1.fetch_payload",
          "\$JS.API.>", "\$KV.>"
        ],
        subscribe: ["_INBOX.>", "\$JS.EVENT.ADVISORY.>"]
      }
    } ]
    imports: [
      { service: { account: $WITNESS_ACCOUNT, subject: "swarm.governance.witness.v1.fence" } },
      { service: { account: $WITNESS_ACCOUNT, subject: "swarm.governance.witness.v1.establish" } },
      { service: { account: $WITNESS_ACCOUNT, subject: "swarm.governance.witness.v1.discover" } },
      { service: { account: $WITNESS_ACCOUNT, subject: "swarm.governance.witness.v1.prepare" } },
      { service: { account: $WITNESS_ACCOUNT, subject: "swarm.governance.witness.v1.commit" } },
      { service: { account: $WITNESS_ACCOUNT, subject: "swarm.governance.witness.v1.abort" } },
      { service: { account: $WITNESS_ACCOUNT, subject: "swarm.governance.witness.v1.read_prepared" } },
      { service: { account: $WITNESS_ACCOUNT, subject: "swarm.governance.witness.v1.read_head" } },
      { service: { account: $WITNESS_ACCOUNT, subject: "swarm.governance.witness.v1.fetch_payload" } }
    ]
  }
  $WITNESS_ACCOUNT {
    users: [ {
      user: "$WITNESS_USER", password: "$WITNESS_PASSWORD",
      permissions: {
        publish: [
          "swarm.governance.witness.store.v1.inspect_ready",
          "swarm.governance.witness.store.v1.read_entry",
          "swarm.governance.witness.store.v1.compare_and_swap"
        ],
        subscribe: [
          "swarm.governance.witness.v1.fence",
          "swarm.governance.witness.v1.establish",
          "swarm.governance.witness.v1.discover",
          "swarm.governance.witness.v1.prepare",
          "swarm.governance.witness.v1.commit",
          "swarm.governance.witness.v1.abort",
          "swarm.governance.witness.v1.read_prepared",
          "swarm.governance.witness.v1.read_head",
          "swarm.governance.witness.v1.fetch_payload",
          "_INBOX.>"
        ],
        allow_responses: { max: 1, expires: "12s" }
      }
    } ]
    exports: [
      { service: "swarm.governance.witness.v1.fence", accounts: [$RUNTIME_ACCOUNT] },
      { service: "swarm.governance.witness.v1.establish", accounts: [$RUNTIME_ACCOUNT] },
      { service: "swarm.governance.witness.v1.discover", accounts: [$RUNTIME_ACCOUNT] },
      { service: "swarm.governance.witness.v1.prepare", accounts: [$RUNTIME_ACCOUNT] },
      { service: "swarm.governance.witness.v1.commit", accounts: [$RUNTIME_ACCOUNT] },
      { service: "swarm.governance.witness.v1.abort", accounts: [$RUNTIME_ACCOUNT] },
      { service: "swarm.governance.witness.v1.read_prepared", accounts: [$RUNTIME_ACCOUNT] },
      { service: "swarm.governance.witness.v1.read_head", accounts: [$RUNTIME_ACCOUNT] },
      { service: "swarm.governance.witness.v1.fetch_payload", accounts: [$RUNTIME_ACCOUNT] }
    ]
    imports: [
      { service: { account: $EXPECTED_ACCOUNT, subject: "swarm.governance.witness.store.v1.inspect_ready" } },
      { service: { account: $EXPECTED_ACCOUNT, subject: "swarm.governance.witness.store.v1.read_entry" } },
      { service: { account: $EXPECTED_ACCOUNT, subject: "swarm.governance.witness.store.v1.compare_and_swap" } }
    ]
  }
  $EXPECTED_ACCOUNT {
    jetstream: enabled
    users: [
      {
        user: "$STORE_USER", password: "$STORE_PASSWORD",
        permissions: {
          publish: [
            "\$KV.phase285_service.s.0fc95119eb171c924f962c3af0a1f03c70078a8fd8a590189d7358e3c62ba1ef",
            "\$JS.API.STREAM.INFO.KV_phase285_service",
            "\$JS.API.STREAM.MSG.GET.KV_phase285_service"
          ],
          subscribe: [
            "swarm.governance.witness.store.v1.inspect_ready",
            "swarm.governance.witness.store.v1.read_entry",
            "swarm.governance.witness.store.v1.compare_and_swap",
            "_INBOX.>"
          ],
          allow_responses: { max: 1, expires: "3s" }
        }
      },
      {
        user: "$INIT_USER", password: "$INIT_PASSWORD",
        permissions: {
          publish: [
            "\$JS.API.STREAM.CREATE.KV_phase285_service",
            "\$JS.API.STREAM.INFO.KV_phase285_service",
            "\$JS.API.STREAM.MSG.GET.KV_phase285_service",
            "\$KV.phase285_service.__witness_bucket_manifest",
            "\$KV.phase285_service.s.0fc95119eb171c924f962c3af0a1f03c70078a8fd8a590189d7358e3c62ba1ef"$fixture_init_permissions
          ],
          subscribe: ["_INBOX.>"]
        }
      }
    ]
    exports: [
      { service: "swarm.governance.witness.store.v1.inspect_ready", accounts: [$WITNESS_ACCOUNT] },
      { service: "swarm.governance.witness.store.v1.read_entry", accounts: [$WITNESS_ACCOUNT] },
      { service: "swarm.governance.witness.store.v1.compare_and_swap", accounts: [$WITNESS_ACCOUNT] }
    ]
  }
}
EOF
  if [[ "$topology_mode" == relay ]]; then
    python3 -I - "$scratch/nats.conf" <<'PY'
import pathlib, sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
public = ["fence", "establish", "discover", "prepare", "commit", "abort", "read_prepared", "read_head", "fetch_payload"]
private = ["inspect_ready", "read_entry", "compare_and_swap"]
runtime_raw = ',\n          "$JS.API.>", "$KV.>"'
if text.count(runtime_raw) != 1:
    raise SystemExit("relay runtime raw-authority anchor differs")
text = text.replace(runtime_raw, "", 1)
runtime_advisory = ', "$JS.EVENT.ADVISORY.>"'
if text.count(runtime_advisory) != 1:
    raise SystemExit("relay runtime advisory anchor differs")
text = text.replace(runtime_advisory, "", 1)

for name in public:
    ordinary = f"swarm.governance.witness.v1.{name}"
    routed = f"swarm.governance.witness.relay.v1.{name}"
    imported = f'{{ service: {{ account: PHASE285_WITNESS, subject: "{ordinary}" }} }}'
    replacement = f'{{ service: {{ account: PHASE285_RELAY, subject: "{routed}" }}, to: "{ordinary}" }}'
    exported = f'{{ service: "{ordinary}", accounts: [PHASE285_RUNTIME] }}'
    if text.count(imported) != 1 or text.count(exported) != 1:
        raise SystemExit(f"relay public topology anchor differs: {name}")
    text = text.replace(imported, replacement, 1)
    text = text.replace(exported, exported.replace("PHASE285_RUNTIME", "PHASE285_RELAY"), 1)

for name in private:
    ordinary = f"swarm.governance.witness.store.v1.{name}"
    routed = f"swarm.governance.witness.relay.store.v1.{name}"
    imported = f'{{ service: {{ account: PHASE285_WITNESS_STORE, subject: "{ordinary}" }} }}'
    replacement = f'{{ service: {{ account: PHASE285_RELAY, subject: "{routed}" }}, to: "{ordinary}" }}'
    exported = f'{{ service: "{ordinary}", accounts: [PHASE285_WITNESS] }}'
    if text.count(imported) != 1 or text.count(exported) != 1:
        raise SystemExit(f"relay private topology anchor differs: {name}")
    text = text.replace(imported, replacement, 1)
    text = text.replace(exported, exported.replace("PHASE285_WITNESS", "PHASE285_RELAY"), 1)

def rows(prefix, names):
    return [f'"{prefix}{name}"' for name in names]

public_routed = rows("swarm.governance.witness.relay.v1.", public)
public_forward = rows("swarm.governance.witness.relay.forward.v1.", public)
private_routed = rows("swarm.governance.witness.relay.store.v1.", private)
private_forward = rows("swarm.governance.witness.relay.forward.store.v1.", private)
exports = [f'      {{ service: {subject}, accounts: [PHASE285_RUNTIME] }}' for subject in public_routed]
exports += [f'      {{ service: {subject}, accounts: [PHASE285_WITNESS] }}' for subject in private_routed]
imports = []
for name in public:
    imports.append(f'      {{ service: {{ account: PHASE285_WITNESS, subject: "swarm.governance.witness.v1.{name}" }}, to: "swarm.governance.witness.relay.forward.v1.{name}" }}')
for name in private:
    imports.append(f'      {{ service: {{ account: PHASE285_WITNESS_STORE, subject: "swarm.governance.witness.store.v1.{name}" }}, to: "swarm.governance.witness.relay.forward.store.v1.{name}" }}')
relay = """
  PHASE285_RELAY {
    users: [ {
      user: "phase285_relay", password: "phase285_relay_fixed_password",
      permissions: {
        publish: [\n          %s\n        ],
        subscribe: [\n          %s,\n          "_INBOX.>"\n        ],
        allow_responses: { max: 1, expires: "12s" }
      }
    } ]
    exports: [\n%s\n    ]
    imports: [\n%s\n    ]
  }
""" % (",\n          ".join(public_forward + private_forward), ",\n          ".join(public_routed + private_routed), ",\n".join(exports), ",\n".join(imports))
needle = "\n  PHASE285_WITNESS_STORE {"
if text.count(needle) != 1:
    raise SystemExit("relay account insertion anchor differs")
path.write_text(text.replace(needle, relay + needle, 1))
PY
  elif [[ "$topology_mode" != normal ]]; then
    return 64
  fi
  TLS_RUNTIME_PASSWORD="$(openssl rand -hex 32)"
  TLS_WITNESS_PASSWORD="$(openssl rand -hex 32)"
  TLS_STORE_PASSWORD="$(openssl rand -hex 32)"
  TLS_INIT_PASSWORD="$(openssl rand -hex 32)"
  TLS_RELAY_PASSWORD="$(openssl rand -hex 32)"
  TLS_CREDENTIAL_TOKEN="$(openssl rand -hex 32)"
  [[ ${#TLS_RUNTIME_PASSWORD} -eq 64 && ${#TLS_WITNESS_PASSWORD} -eq 64 &&
     ${#TLS_STORE_PASSWORD} -eq 64 && ${#TLS_INIT_PASSWORD} -eq 64 && ${#TLS_RELAY_PASSWORD} -eq 64 &&
     ${#TLS_CREDENTIAL_TOKEN} -eq 64 ]] || return 1
  [[ "$(printf '%s\n' "$TLS_RUNTIME_PASSWORD" "$TLS_WITNESS_PASSWORD" "$TLS_STORE_PASSWORD" "$TLS_INIT_PASSWORD" "$TLS_RELAY_PASSWORD" | LC_ALL=C sort -u | wc -l | tr -d ' ')" == 5 ]] || return 1
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=phase285-local-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$scratch/tls-ca-key.pem" -out "$scratch/tls-ca.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" \
    -keyout "$scratch/tls-server-key.pem" -out "$scratch/tls-server.csr" >/dev/null 2>&1
  printf '%s\n' 'subjectAltName=DNS:localhost' 'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' \
    >"$scratch/tls-server.ext"
  openssl x509 -req -days 1 -in "$scratch/tls-server.csr" \
    -CA "$scratch/tls-ca.pem" -CAkey "$scratch/tls-ca-key.pem" -CAcreateserial \
    -extfile "$scratch/tls-server.ext" -out "$scratch/tls-server.pem" >/dev/null 2>&1
  python3 -I - "$scratch/nats.conf" "$scratch/nats-tls.conf" \
    "$RUNTIME_PASSWORD" "$TLS_RUNTIME_PASSWORD" \
    "$WITNESS_PASSWORD" "$TLS_WITNESS_PASSWORD" \
    "$STORE_PASSWORD" "$TLS_STORE_PASSWORD" \
    "$INIT_PASSWORD" "$TLS_INIT_PASSWORD" <<'PY'
import pathlib, sys
source, target, *pairs = sys.argv[1:]
value = pathlib.Path(source).read_text()
for old, new in zip(pairs[::2], pairs[1::2], strict=True):
    if value.count(old) != 1:
        raise SystemExit("TLS credential replacement cardinality differs")
    value = value.replace(old, new, 1)
tls = '''tls {
  cert_file: "/etc/nats/tls/server.pem"
  key_file: "/etc/nats/tls/server-key.pem"
  timeout: 2
}
'''
pathlib.Path(target).write_text(tls + value)
PY
  if [[ "$topology_mode" == relay ]]; then
    python3 -I - "$scratch/nats-tls.conf" "$RELAY_PASSWORD" "$TLS_RELAY_PASSWORD" <<'PY'
import pathlib, sys
path, old, new = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
value = path.read_text()
if value.count(old) != 1:
    raise SystemExit("relay TLS credential replacement cardinality differs")
path.write_text(value.replace(old, new, 1))
PY
  fi
  printf '{"schema_version":1,"role":"runtime","username":"%s","password":"%s","invocation_token":"%s"}' \
    "$RUNTIME_USER" "$TLS_RUNTIME_PASSWORD" "$TLS_CREDENTIAL_TOKEN" >"$scratch/runtime.credentials.json"
  printf '{"schema_version":1,"role":"witness","username":"%s","password":"%s","invocation_token":"%s"}' \
    "$WITNESS_USER" "$TLS_WITNESS_PASSWORD" "$TLS_CREDENTIAL_TOKEN" >"$scratch/witness.credentials.json"
  printf '{"schema_version":1,"role":"witness-store","username":"%s","password":"%s","invocation_token":"%s"}' \
    "$STORE_USER" "$TLS_STORE_PASSWORD" "$TLS_CREDENTIAL_TOKEN" >"$scratch/store.credentials.json"
  printf '{"schema_version":1,"role":"init","username":"%s","password":"%s","invocation_token":"%s"}' \
    "$INIT_USER" "$TLS_INIT_PASSWORD" "$TLS_CREDENTIAL_TOKEN" >"$scratch/init.credentials.json"
  printf '{"schema_version":1,"role":"relay","username":"%s","password":"%s","invocation_token":"%s"}' \
    "$RELAY_USER" "$TLS_RELAY_PASSWORD" "$TLS_CREDENTIAL_TOKEN" >"$scratch/relay.credentials.json"
  cat >"$scratch/compose.override.yml" <<EOF
services:
  nats:
    command: ["-c", "/etc/nats/nats.conf"]
    volumes:
      - "$scratch/nats.conf:/etc/nats/nats.conf:ro"
      - nats-data:/data
  nats_tls:
    image: "$PINNED_IMAGE"
    profiles: ["nats"]
    command: ["-c", "/etc/nats/nats.conf"]
    ports:
      - "127.0.0.1::4222"
      - "127.0.0.1::8222"
    volumes:
      - "$scratch/nats-tls.conf:/etc/nats/nats.conf:ro"
      - "$scratch/tls-server.pem:/etc/nats/tls/server.pem:ro"
      - "$scratch/tls-server-key.pem:/etc/nats/tls/server-key.pem:ro"
      - nats-tls-data:/data
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:8222/healthz || exit 1"]
      interval: 1s
      timeout: 1s
      retries: 30
volumes:
  nats-tls-data:
EOF
  chmod 600 "$scratch/nats.conf" "$scratch/nats-tls.conf" "$scratch/compose.override.yml" \
    "$scratch/tls-ca-key.pem" "$scratch/tls-server-key.pem" \
    "$scratch/runtime.credentials.json" "$scratch/witness.credentials.json" \
    "$scratch/store.credentials.json" "$scratch/init.credentials.json" "$scratch/relay.credentials.json"
}

validate_authority_topology() {
  local path="$1" mode="${2:-validate}"
  python3 -I - "$path" "$mode" "$0" <<'PY'
import hashlib, pathlib, re, sys
path, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
harness_path = pathlib.Path(sys.argv[3])
source = path.read_text()
# PHASE285_TOPOLOGY_VALIDATOR_BEGIN
PUBLIC=[f"swarm.governance.witness.v1.{suffix}" for suffix in ["fence","establish","discover","prepare","commit","abort","read_prepared","read_head","fetch_payload"]]
PRIVATE=[f"swarm.governance.witness.store.v1.{suffix}" for suffix in ["inspect_ready","read_entry","compare_and_swap"]]
WITNESS_FIXTURE_BUCKETS=["phase285_b_wrong_revision","phase285_b_confirmed","phase285_b_del","phase285_b_purge","phase285_b_unknown","phase285_b_direct","phase285_c_current","phase285_c_predecessor","phase285_c_prepared","phase285_c_abort","phase285_c_genesisabort","phase285_c_anchor","phase285_c_account","phase285_c_global"]
INIT=["$JS.API.STREAM.CREATE.KV_phase285_service","$JS.API.STREAM.INFO.KV_phase285_service","$JS.API.STREAM.MSG.GET.KV_phase285_service","$KV.phase285_service.__witness_bucket_manifest","$KV.phase285_service.s.0fc95119eb171c924f962c3af0a1f03c70078a8fd8a590189d7358e3c62ba1ef"]
for bucket in WITNESS_FIXTURE_BUCKETS:
    INIT.extend([f"$JS.API.STREAM.CREATE.KV_{bucket}",f"$JS.API.STREAM.INFO.KV_{bucket}",f"$JS.API.STREAM.MSG.GET.KV_{bucket}",f"$JS.API.DIRECT.GET.KV_{bucket}.>",f"$KV.{bucket}.>"])
INIT.append("$JS.API.STREAM.DELETE.KV_phase285_c_anchor")
RELAY_PRESENT="PHASE285_RELAY {" in source
ACCOUNTS=["PHASE285_RUNTIME","PHASE285_WITNESS"] + (["PHASE285_RELAY"] if RELAY_PRESENT else []) + ["PHASE285_WITNESS_STORE"]
PRINCIPALS=[("PHASE285_RUNTIME","phase285_foreign"),("PHASE285_WITNESS","phase285_witness")] + ([('PHASE285_RELAY','phase285_relay')] if RELAY_PRESENT else []) + [("PHASE285_WITNESS_STORE","phase285_witness_store"),("PHASE285_WITNESS_STORE","phase285_expected")]
EXPECTED_PRINCIPALS={
  "PHASE285_RUNTIME":["phase285_foreign"],
  "PHASE285_WITNESS":["phase285_witness"],
  **({"PHASE285_RELAY":["phase285_relay"]} if RELAY_PRESENT else {}),
  "PHASE285_WITNESS_STORE":["phase285_witness_store","phase285_expected"],
}

def paired_end(text,start,opening="{",closing="}"):
    depth=0; quoted=False; escaped=False
    for index in range(start,len(text)):
        char=text[index]
        if quoted:
            if escaped: escaped=False
            elif char=="\\": escaped=True
            elif char=='"': quoted=False
            continue
        if char=='"': quoted=True
        elif char==opening: depth+=1
        elif char==closing:
            depth-=1
            if depth==0: return index+1
    raise ValueError("topology[unbalanced]")

def exact_block(text,pattern,reason):
    matches=list(re.finditer(pattern,text,re.M))
    if len(matches)!=1: raise ValueError(reason)
    opening=text.index("{",matches[0].start())
    return text[opening:paired_end(text,opening)]

def exact_array(text,pattern,reason):
    matches=list(re.finditer(pattern,text,re.M))
    if len(matches)!=1: raise ValueError(reason)
    opening=text.index("[",matches[0].start())
    return text[opening:paired_end(text,opening,"[","]")]

def string_array(text,name,reason):
    match=re.search(rf"\b{name}:\s*\[(.*?)\]",text,re.S)
    if not match: raise ValueError(reason)
    return re.findall(r'"([^"\n]+)"',match.group(1))

def account_blocks(text):
    accounts=exact_block(text,r"^accounts\s*\{","topology[accounts-block]")
    result={name: exact_block(accounts,rf"^  {re.escape(name)}\s*\{{",f"topology[account:{name}]") for name in ACCOUNTS}
    discovered=re.findall(r"^  ([A-Z][A-Z0-9_]*)\s*\{",accounts,re.M)
    if discovered!=ACCOUNTS: raise ValueError("topology[account-inventory]")
    return result

def user_block(account,username):
    marker=f'user: "{username}"'
    if account.count(marker)!=1: raise ValueError(f"topology[principal:{username}]")
    position=account.index(marker); opening=account.rfind("{",0,position)
    return account[opening:paired_end(account,opening)]

def user_blocks(account,owner):
    users=exact_array(account,r"^    users:\s*\[",f"topology[users:{owner}]")
    discovered=re.findall(r'\buser:\s*"([^"\n]+)"',users)
    if discovered!=EXPECTED_PRINCIPALS[owner]: raise ValueError(f"topology[principal-inventory:{owner}]")
    return {username:user_block(users,username) for username in discovered}

def optional_authority_array(account,name):
    header=rf"^    {re.escape(name)}:\s*\["
    headers=list(re.finditer(header,account,re.M))
    declarations=list(re.finditer(rf"^    {re.escape(name)}\b",account,re.M))
    if not declarations: return None
    if len(declarations)!=1 or len(headers)!=1: raise ValueError(f"topology[{name}-declaration]")
    opening=account.index("[",headers[0].start())
    return account[opening:paired_end(account,opening,"[","]")]

def imports(account):
    block=optional_authority_array(account,"imports")
    if block is None: return []
    rows=re.findall(r'\{\s*service:\s*\{\s*account:\s*([A-Z][A-Z0-9_]*),\s*subject:\s*"([^"]+)"\s*\}(?:,\s*to:\s*"([^"]+)")?\s*\}',block,re.S)
    if len(rows)!=len(re.findall(r'\{\s*service\s*:',block)): raise ValueError("topology[imports-malformed]")
    return [(subject,to or subject,owner) for owner,subject,to in rows]

def exports(account):
    block=optional_authority_array(account,"exports")
    if block is None: return []
    rows=re.findall(r'\{\s*service:\s*"([^"]+)",\s*accounts:\s*\[([A-Z][A-Z0-9_]*)\]\s*\}',block,re.S)
    if len(rows)!=len(re.findall(r'\{\s*service\s*:',block)): raise ValueError("topology[exports-malformed]")
    return [(subject,"service",allowed) for subject,allowed in rows]

def principal_row(owner,username,block):
    grants=re.findall(r'allow_responses:\s*\{\s*max:\s*(\d+),\s*expires:\s*"([^"]+)"\s*\}',block,re.S)
    return {"owner":owner,"username":username,"publish":string_array(block,"publish",f"topology[publish:{username}]"),"subscribe":string_array(block,"subscribe",f"topology[subscribe:{username}]"),"response_grant":[list(row) for row in grants]}

def parse_topology(text):
    blocks=account_blocks(text); principals=[]
    discovered={owner:user_blocks(blocks[owner],owner) for owner in ACCOUNTS}
    for owner,username in PRINCIPALS: principals.append(principal_row(owner,username,discovered[owner][username]))
    return {"accounts":ACCOUNTS,"principals":principals,"imports":{name:imports(blocks[name]) for name in ACCOUNTS},"exports":{name:exports(blocks[name]) for name in ACCOUNTS}}

def validate(value):
    graph=parse_topology(value)
    public_routed=[subject.replace("swarm.governance.witness.v1.","swarm.governance.witness.relay.v1.") for subject in PUBLIC]
    public_forward=[subject.replace("swarm.governance.witness.v1.","swarm.governance.witness.relay.forward.v1.") for subject in PUBLIC]
    private_routed=[subject.replace("swarm.governance.witness.store.v1.","swarm.governance.witness.relay.store.v1.") for subject in PRIVATE]
    private_forward=[subject.replace("swarm.governance.witness.store.v1.","swarm.governance.witness.relay.forward.store.v1.") for subject in PRIVATE]
    expected_permissions={
      "phase285_foreign":(PUBLIC+([] if RELAY_PRESENT else ["$JS.API.>","$KV.>"]),["_INBOX.>"]+([] if RELAY_PRESENT else ["$JS.EVENT.ADVISORY.>"]),[]),
      "phase285_witness":(PRIVATE,PUBLIC+["_INBOX.>"],[["1","12s"]]),
      **({"phase285_relay":(public_forward+private_forward,public_routed+private_routed+["_INBOX.>"],[["1","12s"]])} if RELAY_PRESENT else {}),
      "phase285_witness_store":(["$KV.phase285_service.s.0fc95119eb171c924f962c3af0a1f03c70078a8fd8a590189d7358e3c62ba1ef","$JS.API.STREAM.INFO.KV_phase285_service","$JS.API.STREAM.MSG.GET.KV_phase285_service"],PRIVATE+["_INBOX.>"],[["1","3s"]]),
      "phase285_expected":(INIT,["_INBOX.>"],[]),
    }
    for row in graph["principals"]:
        publish,subscribe,grant=expected_permissions[row["username"]]
        if row["publish"]!=publish: raise ValueError(f'topology[publish:{row["username"]}]')
        if row["subscribe"]!=subscribe: raise ValueError(f'topology[subscribe:{row["username"]}]')
        if row["response_grant"]!=grant: raise ValueError(f'topology[response-grant:{row["username"]}]')
    if RELAY_PRESENT:
        expected_imports={
          "PHASE285_RUNTIME":[(routed,ordinary,"PHASE285_RELAY") for routed,ordinary in zip(public_routed,PUBLIC,strict=True)],
          "PHASE285_WITNESS":[(routed,ordinary,"PHASE285_RELAY") for routed,ordinary in zip(private_routed,PRIVATE,strict=True)],
          "PHASE285_RELAY":[(ordinary,forward,"PHASE285_WITNESS") for ordinary,forward in zip(PUBLIC,public_forward,strict=True)]+[(ordinary,forward,"PHASE285_WITNESS_STORE") for ordinary,forward in zip(PRIVATE,private_forward,strict=True)],
          "PHASE285_WITNESS_STORE":[],
        }
        expected_exports={
          "PHASE285_RUNTIME":[],
          "PHASE285_WITNESS":[(subject,"service","PHASE285_RELAY") for subject in PUBLIC],
          "PHASE285_RELAY":[(subject,"service","PHASE285_RUNTIME") for subject in public_routed]+[(subject,"service","PHASE285_WITNESS") for subject in private_routed],
          "PHASE285_WITNESS_STORE":[(subject,"service","PHASE285_RELAY") for subject in PRIVATE],
        }
    else:
        expected_imports={"PHASE285_RUNTIME":[(subject,subject,"PHASE285_WITNESS") for subject in PUBLIC],"PHASE285_WITNESS":[(subject,subject,"PHASE285_WITNESS_STORE") for subject in PRIVATE],"PHASE285_WITNESS_STORE":[]}
        expected_exports={"PHASE285_RUNTIME":[],"PHASE285_WITNESS":[(subject,"service","PHASE285_RUNTIME") for subject in PUBLIC],"PHASE285_WITNESS_STORE":[(subject,"service","PHASE285_WITNESS") for subject in PRIVATE]}
    for owner in ACCOUNTS:
        if graph["imports"][owner]!=expected_imports[owner]: raise ValueError(f"topology[imports:{owner}]")
        if graph["exports"][owner]!=expected_exports[owner]: raise ValueError(f"topology[exports:{owner}]")
    return graph
# PHASE285_TOPOLOGY_VALIDATOR_END

validate(source)
if mode == "validate": print(f"phase285_authority_topology accounts={len(ACCOUNTS)} principals={len(PRINCIPALS)} public=9 private=3 init={len(INIT)} relay={int(RELAY_PRESENT)} passed=1"); raise SystemExit(0)
if mode != "self-test": raise SystemExit("unknown topology validator mode")

def once(text,old,new,label):
    if text.count(old)!=1: raise SystemExit(f"topology mutation anchor differs: {label}:{text.count(old)}")
    return text.replace(old,new,1)
def swap(text,left,right,label):
    marker=f"__PHASE285_{label}__"
    return once(once(once(text,left,marker,label),right,left,label),marker,right,label)
def mutate_init(text,transform):
    start=text.index('user: "phase285_expected"'); end=text.index("    exports:",start)
    return text[:start]+transform(text[start:end])+text[end:]
def mutate_store_users(text,transform):
    start=text.index('user: "phase285_witness_store"'); end=text.index("    exports:",start)
    return text[:start]+transform(text[start:end])+text[end:]
def once_after(text,anchor,old,new,label):
    start=text.index(anchor); position=text.find(old,start)
    if position<0: raise SystemExit(f"topology mutation anchor differs: {label}:0")
    return text[:position]+new+text[position+len(old):]
if RELAY_PRESENT:
    runtime_fence='service: { account: PHASE285_RELAY, subject: "swarm.governance.witness.relay.v1.fence" }, to: "swarm.governance.witness.v1.fence"'
    witness_inspect='service: { account: PHASE285_RELAY, subject: "swarm.governance.witness.relay.store.v1.inspect_ready" }, to: "swarm.governance.witness.store.v1.inspect_ready"'
    runtime_fence_wrong_to=runtime_fence.replace('to: "swarm.governance.witness.v1.fence"','to: "swarm.governance.witness.v1.wrong"')
    runtime_fence_wrong_account=runtime_fence.replace("account: PHASE285_RELAY","account: PHASE285_WITNESS_STORE")
    export_fence='{ service: "swarm.governance.witness.v1.fence", accounts: [PHASE285_RELAY] }'
else:
    runtime_fence='service: { account: PHASE285_WITNESS, subject: "swarm.governance.witness.v1.fence" }'
    witness_inspect='service: { account: PHASE285_WITNESS_STORE, subject: "swarm.governance.witness.store.v1.inspect_ready" }'
    runtime_fence_wrong_to=runtime_fence[:-2]+', to: "swarm.governance.witness.v1.wrong" }'
    runtime_fence_wrong_account=runtime_fence.replace("PHASE285_WITNESS","PHASE285_WITNESS_STORE")
    export_fence='{ service: "swarm.governance.witness.v1.fence", accounts: [PHASE285_RUNTIME] }'
mutations=[]
mutations.append(("runtime_witness_import_block_move",swap(source,runtime_fence,witness_inspect,"BLOCK_MOVE")))
mutations.extend([
 ("missing_runtime_account",once(source,'  PHASE285_RUNTIME {','  PHASE285_RUNTIME_MISSING {',"missing_runtime_account")),
 ("missing_init_principal",once(source,'user: "phase285_expected"','user: "phase285_expected_missing"',"missing_init_principal")),
 ("store_init_credential_swap",swap(source,'user: "phase285_witness_store"','user: "phase285_expected"',"CREDENTIAL_SWAP")),
 ("public_subject_omission",once(source,runtime_fence,runtime_fence.replace("fence","fence_missing"),"public_subject_omission")),
 ("private_subject_omission",once(source,witness_inspect,witness_inspect.replace("inspect_ready","inspect_ready_missing"),"private_subject_omission")),
 ("public_wildcard_import",once(source,runtime_fence,runtime_fence.replace("fence","*"),"public_wildcard_import")),
 ("runtime_private_import",once(source,runtime_fence,witness_inspect,"runtime_private_import")),
 ("witness_raw_js",once(source,'"swarm.governance.witness.store.v1.compare_and_swap"\n        ],','"swarm.governance.witness.store.v1.compare_and_swap", "$JS.API.>"\n        ],',"witness_raw_js")),
 ("store_public_service",once(source,'"swarm.governance.witness.store.v1.compare_and_swap",\n            "_INBOX.>"','"swarm.governance.witness.v1.prepare",\n            "_INBOX.>"',"store_public_service")),
 ("init_serving",mutate_init(source,lambda block: once(block,'subscribe: ["_INBOX.>"]','subscribe: ["_INBOX.>", "swarm.governance.witness.store.v1.inspect_ready"]',"init_serving"))),
 ("init_raw_authority_widening",once(once(source,'"$JS.API.STREAM.CREATE.KV_phase285_service"','"$JS.API.>"',"init_raw_authority_widening"),'"$KV.phase285_service.__witness_bucket_manifest"','"$KV.>"',"init_raw_authority_widening")),
 ("init_manifest_admitted_subject_swap",mutate_init(source,lambda block: swap(block,'"$KV.phase285_service.__witness_bucket_manifest"','"$KV.phase285_service.s.0fc95119eb171c924f962c3af0a1f03c70078a8fd8a590189d7358e3c62ba1ef"',"INIT_SUBJECT_SWAP"))),
 ("import_to_substitution",once(source,runtime_fence,runtime_fence_wrong_to,"import_to_substitution")),
 ("import_source_account_substitution",once(source,runtime_fence,runtime_fence_wrong_account,"import_source_account_substitution")),
 ("export_allowed_account_substitution",once(source,export_fence,'{ service: "swarm.governance.witness.v1.fence", accounts: [PHASE285_WITNESS_STORE] }',"export_allowed_account_substitution")),
 ("response_grant_move",once_after(source,'user: "phase285_witness"','allow_responses: { max: 1, expires: "12s" }','allow_responses: { max: 2, expires: "12s" }',"response_grant_move")),
 ("cross_principal_permission_swap",swap(source,'"swarm.governance.witness.store.v1.inspect_ready",\n          "swarm.governance.witness.store.v1.read_entry",\n          "swarm.governance.witness.store.v1.compare_and_swap"','"$KV.phase285_service.s.0fc95119eb171c924f962c3af0a1f03c70078a8fd8a590189d7358e3c62ba1ef",\n            "$JS.API.STREAM.INFO.KV_phase285_service",\n            "$JS.API.STREAM.MSG.GET.KV_phase285_service"',"PERMISSION_SWAP")),
])
mutations.extend([
 ("extra_store_principal_raw_authority",mutate_store_users(source,lambda block: once(block,'      }\n    ]\n','      },\n      {\n        user: "phase285_extra", password: "phase285-extra-password",\n        permissions: { publish: ["$JS.API.>"], subscribe: ["_INBOX.>"] }\n      }\n    ]\n',"extra_store_principal_raw_authority"))),
 ("duplicate_store_imports_declaration",once(source,'    exports: [\n      { service: "swarm.governance.witness.store.v1.inspect_ready"','    imports: []\n    imports: []\n    exports: [\n      { service: "swarm.governance.witness.store.v1.inspect_ready"',"duplicate_store_imports_declaration")),
 ("duplicate_runtime_exports_declaration",once(source,'    imports: [\n      { '+runtime_fence,'    exports: []\n    exports: []\n    imports: [\n      { '+runtime_fence,"duplicate_runtime_exports_declaration")),
])
mutations.extend([
 ("malformed_store_import_row",once(source,'    exports: [\n      { service: "swarm.governance.witness.store.v1.inspect_ready"','    imports: [\n      { service: { account: PHASE285_WITNESS, subject: "swarm.governance.witness.store.v1.inspect_ready", phase285_unexpected: "present" } }\n    ]\n    exports: [\n      { service: "swarm.governance.witness.store.v1.inspect_ready"',"malformed_store_import_row")),
 ("malformed_runtime_export_row",once(source,'    imports: [\n      { '+runtime_fence,'    exports: [\n      { service: "swarm.governance.witness.v1.fence", accounts: [PHASE285_WITNESS], phase285_unexpected: "present" }\n    ]\n    imports: [\n      { '+runtime_fence,"malformed_runtime_export_row")),
])
intended_reasons={
 "extra_store_principal_raw_authority":"topology[principal-inventory:PHASE285_WITNESS_STORE]",
 "duplicate_store_imports_declaration":"topology[imports-declaration]",
 "duplicate_runtime_exports_declaration":"topology[exports-declaration]",
 "malformed_store_import_row":"topology[imports-malformed]",
 "malformed_runtime_export_row":"topology[exports-malformed]",
}
shape_predicates={
 "malformed_store_import_row":"topology[imports-malformed]",
 "malformed_runtime_export_row":"topology[exports-malformed]",
}
digests=[]
for label,candidate in mutations:
    digest=hashlib.sha256(candidate.encode()).hexdigest(); digests.append(digest)
    try: validate(candidate)
    except ValueError as error:
        if label in intended_reasons and str(error)!=intended_reasons[label]: raise SystemExit(f"authority topology mutant wrong reason: {label}:{error}")
        if label in shape_predicates:
            harness=harness_path.read_text(); start=harness.index("# PHASE285_TOPOLOGY_VALIDATOR_BEGIN"); end=harness.index("# PHASE285_TOPOLOGY_VALIDATOR_END",start)
            validator_source=harness[start:end]; reason=shape_predicates[label]
            matches=[line for line in validator_source.splitlines(keepends=True) if f'raise ValueError("{reason}")' in line]
            if len(matches)!=1: raise SystemExit(f"authority topology row-shape anchor differs: {label}")
            predicate=matches[0]
            namespace={"re":re,"source":candidate}; exec(validator_source.replace(predicate,"",1),namespace); namespace["validate"](candidate)
        print(f"phase285_authority_topology_self_test_red mutation={label} reason={error} digest={digest}")
    else: raise SystemExit(f"authority topology mutant survived: {label}")
if len(mutations)!=23 or len(set(digests))!=23: raise SystemExit("authority topology mutant inventory/digests differ")
print("phase285_authority_topology_self_test mutations=23 unique=23 vacuous=0 passed=1")
PY
}

validate_observation() {
  local path="$1" expected_nonce="$2"
  [[ "$(sed -n 's/^image=//p' "$path")" == "$PINNED_IMAGE" ]] || return 1
  [[ "$(sed -n 's/^repo_digest=//p' "$path")" == "$PINNED_REPO_DIGEST" ]] || return 1
  [[ "$(sed -n 's/^version=//p' "$path")" == "$PINNED_VERSION" ]] || return 1
  [[ "$(sed -n 's/^health=//p' "$path")" == ok ]] || return 1
  [[ "$(sed -n 's/^service=//p' "$path")" == nats ]] || return 1
  [[ "$(sed -n 's/^expected_account=//p' "$path")" == "$EXPECTED_ACCOUNT" ]] || return 1
  [[ "$(sed -n 's/^foreign_account=//p' "$path")" == "$FOREIGN_ACCOUNT" ]] || return 1
  [[ "$(sed -n 's/^foreign_resource_isolation=//p' "$path")" == ok ]] || return 1
  [[ "$(sed -n 's/^config_mount=//p' "$path")" == ro ]] || return 1
  [[ "$(sed -n 's/^volume_restart=//p' "$path")" == stable ]] || return 1
  [[ "$(sed -n 's/^sync_interval=//p' "$path")" == always ]] || return 1
  [[ "$(sed -n 's/^nonce=//p' "$path")" == "$expected_nonce" ]] || return 1
  [[ "$(wc -l <"$path" | tr -d ' ')" == 12 ]] || return 1
}

validate_test_transcript() {
  local path="$1" test_name="$2" nonce="$3" filtered="$4"
  [[ "$(grep -Fxc "phase285_harness_nonce=$nonce" "$path")" -eq 1 ]] || return 1
  [[ "$(grep -Ec '^phase285_harness_nonce=' "$path")" -eq 1 ]] || return 1
  [[ "$(grep -Fxc 'running 1 test' "$path")" -eq 1 ]] || return 1
  [[ "$(grep -Ec '^running [0-9]+ tests?$' "$path")" -eq 1 ]] || return 1
  [[ "$(grep -Fxc "test ${test_name} ... ok" "$path")" -eq 1 ]] || return 1
  [[ "$(grep -Ec '^test result:' "$path")" -eq 1 ]] || return 1
  [[ "$(grep -Ec "^test result: ok\\. 1 passed; 0 failed; 0 ignored; 0 measured; ${filtered} filtered out; finished in [0-9]+\\.[0-9]+s$" "$path")" -eq 1 ]] || return 1
  ! grep -Eq 'running 0 tests|\.\.\. ignored|test result: FAILED|test result: ok\. 0 passed' "$path"
}

parse_exact_test_prefix() {
  EXPECTED_EXACT_TEST=""
  EXPECTED_EXACT_FILTERED=""
  HARNESS_COMMAND=("$@")
  [[ "${1:-}" == --expect-exact-test ]] || return 0
  [[ $# -ge 5 ]] || return 1
  [[ "$2" =~ ^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)+$ ]] || return 1
  [[ "$3" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  [[ "$4" == -- ]] || return 1
  EXPECTED_EXACT_TEST="$2"
  EXPECTED_EXACT_FILTERED="$3"
  shift 4
  HARNESS_COMMAND=("$@")
  [[ ${#HARNESS_COMMAND[@]} -gt 0 ]] || return 1

  local index previous exact_markers=0
  for ((index = 0; index < ${#HARNESS_COMMAND[@]}; index++)); do
    [[ "${HARNESS_COMMAND[index]}" != --expect-exact-test ]] || return 1
    if [[ "${HARNESS_COMMAND[index]}" == --exact ]]; then
      (( exact_markers += 1 ))
      (( index > 0 )) || return 1
      previous=$((index - 1))
      [[ "${HARNESS_COMMAND[previous]}" == "$EXPECTED_EXACT_TEST" ]] || return 1
    fi
  done
  [[ "$exact_markers" -eq 1 ]]
}

validate_checkpoint_test_environment() {
  [[ $# -eq 5 ]] || return 64
  local token="$1" tree="$2" threads="$3" expected_token="$4" expected_tree="$5"
  [[ -n "$token" && "$token" == "$expected_token" && ${#token} -le 512 ]] || return 1
  [[ "$token" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  [[ "$tree" == "$expected_tree" && "$tree" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ "$threads" == 1 ]]
}

bind_checkpoint_test_environment() {
  [[ $# -eq 1 ]] || return 64
  local nonce="$1" expected_token expected_tree token tree threads
  expected_token="phase285-package-$nonce"
  expected_tree="$(git -C "$ROOT_DIR" write-tree)"
  token="${PHASE285_CHECKPOINT_INVOCATION_TOKEN:-$expected_token}"
  tree="${PHASE285_CHECKPOINT_TREE:-$expected_tree}"
  threads="${RUST_TEST_THREADS:-1}"
  validate_checkpoint_test_environment \
    "$token" "$tree" "$threads" "$expected_token" "$expected_tree" || {
    echo "PHASE285-HARNESS[checkpoint-test-environment]" >&2
    return 1
  }
  export PHASE285_CHECKPOINT_INVOCATION_TOKEN="$token"
  export PHASE285_CHECKPOINT_TREE="$tree"
  export RUST_TEST_THREADS="$threads"
}

is_exact_witness_package_test_command() {
  [[ $# -eq 6 && "$1" == cargo && "$2" == test && "$3" == -p \
    && "$4" == swarm-governance-witness && "$5" == --locked && "$6" == --offline ]]
}

checkpoint_test_environment_source_guard() {
  local source_path="$1" mode="${2:-validate}"
  python3 -I - "$source_path" "$mode" <<'PY'
import hashlib, pathlib, sys

source_path, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
source = source_path.read_text()

def production_source(value):
    guard_start = value.index("checkpoint_test_environment_source_guard() {")
    guard_end = value.index("\nmutate_line() {", guard_start)
    return value[:guard_start] + value[guard_end:]

def replace_once(value, old, new):
    guard_start = value.index("checkpoint_test_environment_source_guard() {")
    guard_end = value.index("\nmutate_line() {", guard_start)
    positions = []
    cursor = 0
    while True:
        found = value.find(old, cursor)
        if found < 0: break
        if found < guard_start or found >= guard_end: positions.append(found)
        cursor = found + 1
    if len(positions) != 1: raise ValueError(f"checkpoint environment mutation anchor differs: {old}")
    found = positions[0]
    return value[:found] + new + value[found + len(old):]

def validate(value):
    production = production_source(value)
    matcher_body = '''is_exact_witness_package_test_command() {
  [[ $# -eq 6 && "$1" == cargo && "$2" == test && "$3" == -p \\
    && "$4" == swarm-governance-witness && "$5" == --locked && "$6" == --offline ]]
}'''
    fragments = [
        'expected_token="phase285-package-$nonce"',
        'expected_tree="$(git -C "$ROOT_DIR" write-tree)"',
        'token="${PHASE285_CHECKPOINT_INVOCATION_TOKEN:-$expected_token}"',
        'tree="${PHASE285_CHECKPOINT_TREE:-$expected_tree}"',
        'threads="${RUST_TEST_THREADS:-1}"',
        'export PHASE285_CHECKPOINT_INVOCATION_TOKEN="$token"',
        'export PHASE285_CHECKPOINT_TREE="$tree"',
        'export RUST_TEST_THREADS="$threads"',
        'bind_checkpoint_test_environment "$HARNESS_NONCE"',
        'if ! is_exact_witness_package_test_command "$@"; then',
        'unset RUST_TEST_THREADS',
    ]
    if any(production.count(fragment) != 1 for fragment in fragments):
        raise ValueError("checkpoint package environment wiring differs")
    if production.count(matcher_body) != 1:
        raise ValueError("checkpoint package serialization matcher differs")
    run_start = production.index("run_harness()")
    nonce = production.index('HARNESS_NONCE="phase285-$PPID-$$-$(date +%s)"',run_start)
    binding = production.index('bind_checkpoint_test_environment "$HARNESS_NONCE"',nonce)
    serial_scope = production.index('if ! is_exact_witness_package_test_command "$@"; then',binding)
    execution = production.index('  "$@" 2>&1 | tee -a "$transcript"',binding)
    if not nonce < binding < serial_scope < execution: raise ValueError("checkpoint package environment order differs")

validate(source)
if mode == "validate":
    print("phase285_checkpoint_environment_source_guard passed=1")
    raise SystemExit(0)
if mode != "self-test": raise SystemExit("unknown checkpoint environment source-guard mode")
transformations = [
    ("omit_binding_call", 'bind_checkpoint_test_environment "$HARNESS_NONCE"', ':'),
    ("stale_default_token", 'expected_token="phase285-package-$nonce"', 'expected_token="phase285-package-stale"'),
    ("wrong_binding_token", 'bind_checkpoint_test_environment "$HARNESS_NONCE"', 'bind_checkpoint_test_environment "wrong-token"'),
    ("wrong_tree", 'expected_tree="$(git -C "$ROOT_DIR" write-tree)"', 'expected_tree="0000000000000000000000000000000000000000"'),
    ("non_serial", 'threads="${RUST_TEST_THREADS:-1}"', 'threads="${RUST_TEST_THREADS:-2}"'),
    ("omit_token_export", 'export PHASE285_CHECKPOINT_INVOCATION_TOKEN="$token"', ':'),
    ("selector_serial_leak", 'unset RUST_TEST_THREADS', ':'),
    ("matcher_wrong_package", '"$4" == swarm-governance-witness', '"$4" == swarm-governance'),
    ("matcher_locked_substitution", '"$5" == --locked', '"$5" == --frozen'),
    ("matcher_offline_substitution", '"$6" == --offline', '"$6" == --online'),
    ("matcher_tail_reordered", '"$5" == --locked && "$6" == --offline', '"$5" == --offline && "$6" == --locked'),
]
mutants = [(name,replace_once(source,old,new)) for name,old,new in transformations]
labels = [name for name,_candidate in mutants]
expected = ["omit_binding_call","stale_default_token","wrong_binding_token","wrong_tree","non_serial","omit_token_export","selector_serial_leak","matcher_wrong_package","matcher_locked_substitution","matcher_offline_substitution","matcher_tail_reordered"]
digests = [hashlib.sha256(candidate.encode()).hexdigest() for _name,candidate in mutants]
if labels != expected or len(set(digests)) != len(expected):
    raise SystemExit("checkpoint environment mutation inventory/digests differ")
for name,candidate in mutants:
    try: validate(candidate)
    except ValueError: print(f"phase285_harness_environment_source_self_test_red mutation={name}")
    else: raise SystemExit(f"checkpoint environment source mutant survived: {name}")
print(f"phase285_harness_environment_source_self_test mutations={len(mutants)} unique_digests={len(set(digests))} passed=1")
PY
}

mutate_line() {
  local source="$1" target="$2" key="$3" value="$4"
  awk -F= -v key="$key" -v value="$value" '$1 == key {$0 = key "=" value} {print}' "$source" >"$target"
}

self_test() (
  local scratch hostile scratch_link output status mutation key nonce test_name prefix_test_name last_index targeted=0
  local checkpoint_tree checkpoint_token environment_killed=0 binding_killed=0 matcher_killed=0
  local transcript_killed=0 exact_prefix_killed=0 pre_nats_prefix_refusals=0
  local -a transcript_survivors=()
  scratch="$(create_confined_scratch)"
  trap 'cleanup_confined_scratch "$scratch"' EXIT
  write_configuration "$scratch"
  validate_authority_topology "$scratch/nats.conf" self-test
  validate_authority_topology "$scratch/nats-tls.conf"
  [[ -s "$scratch/tls-ca.pem" && -s "$scratch/tls-server.pem" && -s "$scratch/tls-server-key.pem" ]] || return 1
  [[ "$TLS_RUNTIME_PASSWORD" != "$RUNTIME_PASSWORD" && "$TLS_WITNESS_PASSWORD" != "$WITNESS_PASSWORD" &&
     "$TLS_STORE_PASSWORD" != "$STORE_PASSWORD" && "$TLS_INIT_PASSWORD" != "$INIT_PASSWORD" ]] || return 1

  nonce="phase285-self-test-nonce"
  cat >"$scratch/observation" <<EOF
image=$PINNED_IMAGE
repo_digest=$PINNED_REPO_DIGEST
version=$PINNED_VERSION
health=ok
service=nats
expected_account=$EXPECTED_ACCOUNT
foreign_account=$FOREIGN_ACCOUNT
foreign_resource_isolation=ok
config_mount=ro
volume_restart=stable
sync_interval=always
nonce=$nonce
EOF
  validate_observation "$scratch/observation" "$nonce"
  for key in image repo_digest version health service expected_account foreign_account foreign_resource_isolation config_mount volume_restart sync_interval nonce; do
    mutate_line "$scratch/observation" "$scratch/mutant" "$key" broken
    if validate_observation "$scratch/mutant" "$nonce"; then
      echo "PHASE285-HARNESS[observation-mutant-survived:$key]" >&2
      return 1
    fi
  done
  while IFS='|' read -r key value; do
    mutate_line "$scratch/observation" "$scratch/mutant" "$key" "$value"
    if validate_observation "$scratch/mutant" "$nonce"; then
      echo "PHASE285-HARNESS[targeted-mutant-survived:$key:$value]" >&2
      return 1
    fi
    targeted=$((targeted + 1))
  done <<EOF
image|docker.io/library/nats:2.11.17-alpine
image|docker.io/library/nats:2.11.17-alpine@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
version|2.11.18
health|unhealthy
expected_account|$FOREIGN_ACCOUNT
foreign_account|$EXPECTED_ACCOUNT
foreign_resource_isolation|visible
EOF
  grep -v '^service=' "$scratch/observation" >"$scratch/mutant"
  if validate_observation "$scratch/mutant" "$nonce"; then
    echo "PHASE285-HARNESS[absent-service-survived]" >&2
    return 1
  fi
  targeted=$((targeted + 1))

  test_name="jetstream_cas_rejects_each_raw_config_mutation"
  cat >"$scratch/transcript" <<EOF
phase285_harness_nonce=$nonce
running 1 test
test $test_name ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.01s
EOF
  validate_test_transcript "$scratch/transcript" "$test_name" "$nonce" 4
  for mutation in zero skipped ignored partial stale missing-running running-2 wrong-filtered extra-result suffix; do
    case "$mutation" in
      zero) sed 's/running 1 test/running 0 tests/; s/1 passed/0 passed/; /test jetstream/d' "$scratch/transcript" >"$scratch/mutant" ;;
      skipped) sed "/^test $test_name/d" "$scratch/transcript" >"$scratch/mutant" ;;
      ignored) sed 's/\.\.\. ok/... ignored/; s/1 passed; 0 failed; 0 ignored/0 passed; 0 failed; 1 ignored/' "$scratch/transcript" >"$scratch/mutant" ;;
      partial) sed '/^test result:/d' "$scratch/transcript" >"$scratch/mutant" ;;
      stale) sed 's/phase285-self-test-nonce/stale-nonce/' "$scratch/transcript" >"$scratch/mutant" ;;
      missing-running) sed '/^running 1 test$/d' "$scratch/transcript" >"$scratch/mutant" ;;
      running-2) sed 's/^running 1 test$/running 2 tests/' "$scratch/transcript" >"$scratch/mutant" ;;
      wrong-filtered) sed 's/4 filtered out/3 filtered out/' "$scratch/transcript" >"$scratch/mutant" ;;
      extra-result) sed -n '1,5p' "$scratch/transcript" >"$scratch/mutant"; printf '\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.02s\n' >>"$scratch/mutant" ;;
      suffix) sed 's/finished in 0.01s$/finished in 0.01s trailing-garbage/' "$scratch/transcript" >"$scratch/mutant" ;;
    esac
    if validate_test_transcript "$scratch/mutant" "$test_name" "$nonce" 4; then
      transcript_survivors+=("$mutation")
    else
      transcript_killed=$((transcript_killed + 1))
    fi
  done
  if [[ "${#transcript_survivors[@]}" -ne 0 ]]; then
    printf 'PHASE285-HARNESS[transcript-mutant-survived:%s]\n' "${transcript_survivors[@]}" >&2
    return 1
  fi
  [[ "$transcript_killed" -eq 10 ]] || return 1

  prefix_test_name="phase285_tests::$test_name"
  sed "s/test $test_name/test $prefix_test_name/" "$scratch/transcript" >"$scratch/exact-transcript"
  validate_test_transcript "$scratch/exact-transcript" "$prefix_test_name" "$nonce" 4
  parse_exact_test_prefix --expect-exact-test "$prefix_test_name" 4 -- \
    cargo test -p swarm-governance-witness --lib --locked --offline -- \
    --test-threads=1 "$prefix_test_name" --exact
  [[ "$EXPECTED_EXACT_TEST" == "$prefix_test_name" && "$EXPECTED_EXACT_FILTERED" == 4 ]] || return 1
  last_index=$((${#HARNESS_COMMAND[@]} - 1))
  [[ "${HARNESS_COMMAND[0]}" == cargo && "${HARNESS_COMMAND[last_index]}" == --exact ]] || return 1
  [[ " ${HARNESS_COMMAND[*]} " != *" --expect-exact-test "* ]] || return 1
  for mutation in missing-fqn empty-fqn malformed-fqn missing-count nondecimal-count \
    noncanonical-count wrong-delimiter missing-command missing-exact duplicate-exact \
    wrong-exact-fqn duplicate-prefix; do
    if case "$mutation" in
      missing-fqn) parse_exact_test_prefix --expect-exact-test ;;
      empty-fqn) parse_exact_test_prefix --expect-exact-test "" 4 -- cargo test "$prefix_test_name" --exact ;;
      malformed-fqn) parse_exact_test_prefix --expect-exact-test invalid-fqn 4 -- cargo test invalid-fqn --exact ;;
      missing-count) parse_exact_test_prefix --expect-exact-test "$prefix_test_name" ;;
      nondecimal-count) parse_exact_test_prefix --expect-exact-test "$prefix_test_name" four -- cargo test "$prefix_test_name" --exact ;;
      noncanonical-count) parse_exact_test_prefix --expect-exact-test "$prefix_test_name" 04 -- cargo test "$prefix_test_name" --exact ;;
      wrong-delimiter) parse_exact_test_prefix --expect-exact-test "$prefix_test_name" 4 --- cargo test "$prefix_test_name" --exact ;;
      missing-command) parse_exact_test_prefix --expect-exact-test "$prefix_test_name" 4 -- ;;
      missing-exact) parse_exact_test_prefix --expect-exact-test "$prefix_test_name" 4 -- cargo test "$prefix_test_name" ;;
      duplicate-exact) parse_exact_test_prefix --expect-exact-test "$prefix_test_name" 4 -- cargo test "$prefix_test_name" --exact "$prefix_test_name" --exact ;;
      wrong-exact-fqn) parse_exact_test_prefix --expect-exact-test "$prefix_test_name" 4 -- cargo test wrong::test --exact ;;
      duplicate-prefix) parse_exact_test_prefix --expect-exact-test "$prefix_test_name" 4 -- cargo test --expect-exact-test "$prefix_test_name" --exact ;;
    esac; then
      echo "PHASE285-HARNESS[exact-prefix-mutant-survived:$mutation]" >&2
      return 1
    fi
    echo "phase285_harness_exact_prefix_self_test_red mutation=$mutation"
    exact_prefix_killed=$((exact_prefix_killed + 1))
  done
  [[ "$exact_prefix_killed" -eq 12 ]] || return 1
  parse_exact_test_prefix --expect-exact-test "$prefix_test_name" 3 -- cargo test "$prefix_test_name" --exact
  if validate_test_transcript "$scratch/exact-transcript" "$EXPECTED_EXACT_TEST" "$nonce" "$EXPECTED_EXACT_FILTERED"; then
    echo "PHASE285-HARNESS[exact-prefix-count-mutant-survived]" >&2
    return 1
  fi
  echo "phase285_harness_exact_prefix_self_test_red mutation=wrong-filtered-count"
  exact_prefix_killed=$((exact_prefix_killed + 1))
  [[ "$exact_prefix_killed" -eq 13 ]] || return 1
  status=0
  output="$(DOCKER_HOST="tcp://127.0.0.1:1" \
    PHASE285_EXPECT_EXACT_TEST="ambient::wrong" \
    PHASE285_EXPECTED_FILTERED_OUT=0 \
    "$ROOT_DIR/tools/with-nats-jetstream.sh" \
      --expect-exact-test malformed-fqn 4 -- cargo test malformed-fqn --exact 2>&1)" || status=$?
  [[ "$status" -eq 64 && "$output" == "PHASE285-HARNESS[exact-test-prefix]" ]] || return 1
  pre_nats_prefix_refusals=$((pre_nats_prefix_refusals + 1))

  checkpoint_tree="$(git -C "$ROOT_DIR" write-tree)"
  checkpoint_token="phase285-package-$nonce"
  validate_checkpoint_test_environment \
    "$checkpoint_token" "$checkpoint_tree" 1 "$checkpoint_token" "$checkpoint_tree"
  while IFS='|' read -r mutation token tree threads; do
    if validate_checkpoint_test_environment \
      "$token" "$tree" "$threads" "$checkpoint_token" "$checkpoint_tree"; then
      echo "PHASE285-HARNESS[checkpoint-environment-mutant-survived:$mutation]" >&2
      return 1
    fi
    echo "phase285_harness_environment_self_test_red mutation=$mutation"
    environment_killed=$((environment_killed + 1))
  done <<EOF
missing_token||$checkpoint_tree|1
stale_token|phase285-package-stale|$checkpoint_tree|1
wrong_token|phase285-package-wrong|$checkpoint_tree|1
missing_tree|$checkpoint_token||1
wrong_tree|$checkpoint_token|0000000000000000000000000000000000000000|1
missing_serial|$checkpoint_token|$checkpoint_tree|
non_serial|$checkpoint_token|$checkpoint_tree|2
EOF
  [[ "$environment_killed" -eq 7 ]] || return 1

  (
    unset PHASE285_CHECKPOINT_INVOCATION_TOKEN PHASE285_CHECKPOINT_TREE RUST_TEST_THREADS
    bind_checkpoint_test_environment "$nonce"
    [[ "$PHASE285_CHECKPOINT_INVOCATION_TOKEN" == "$checkpoint_token" ]]
    [[ "$PHASE285_CHECKPOINT_TREE" == "$checkpoint_tree" ]]
    [[ "$RUST_TEST_THREADS" == 1 ]]
  )
  while IFS='|' read -r mutation token tree threads; do
    status=0
    output="$(PHASE285_CHECKPOINT_INVOCATION_TOKEN="$token" \
      PHASE285_CHECKPOINT_TREE="$tree" \
      RUST_TEST_THREADS="$threads" \
      bind_checkpoint_test_environment "$nonce" 2>&1)" || status=$?
    [[ "$status" -ne 0 && "$output" == "PHASE285-HARNESS[checkpoint-test-environment]" ]] || return 1
    echo "phase285_harness_environment_binding_self_test_red mutation=$mutation"
    binding_killed=$((binding_killed + 1))
  done <<EOF
stale_token|phase285-package-stale|$checkpoint_tree|1
wrong_tree|$checkpoint_token|0000000000000000000000000000000000000000|1
non_serial|$checkpoint_token|$checkpoint_tree|2
EOF
  [[ "$binding_killed" -eq 3 ]] || return 1
  is_exact_witness_package_test_command \
    cargo test -p swarm-governance-witness --locked --offline || return 1
  for mutation in wrong_package missing_locked missing_offline reordered_flags substituted_locked substituted_offline extra_arg selector_command filtered_cargo_selector; do
    if case "$mutation" in
      wrong_package) is_exact_witness_package_test_command cargo test -p swarm-governance --locked --offline ;;
      missing_locked) is_exact_witness_package_test_command cargo test -p swarm-governance-witness --offline ;;
      missing_offline) is_exact_witness_package_test_command cargo test -p swarm-governance-witness --locked ;;
      reordered_flags) is_exact_witness_package_test_command cargo test -p swarm-governance-witness --offline --locked ;;
      substituted_locked) is_exact_witness_package_test_command cargo test -p swarm-governance-witness --frozen --offline ;;
      substituted_offline) is_exact_witness_package_test_command cargo test -p swarm-governance-witness --locked --online ;;
      extra_arg) is_exact_witness_package_test_command cargo test -p swarm-governance-witness --locked --offline extra ;;
      selector_command) is_exact_witness_package_test_command bash tools/check-phase285-witness-conformance.sh jetstream-checkpoint ;;
      filtered_cargo_selector) is_exact_witness_package_test_command cargo test -p swarm-governance-witness --locked --offline -- jetstream_checkpoint --exact ;;
    esac; then
      echo "PHASE285-HARNESS[checkpoint-package-matcher-mutant-survived:$mutation]" >&2
      return 1
    fi
    echo "phase285_harness_package_matcher_self_test_red mutation=$mutation"
    matcher_killed=$((matcher_killed + 1))
  done
  [[ "$matcher_killed" -eq 9 ]] || return 1
  checkpoint_test_environment_source_guard "$ROOT_DIR/tools/with-nats-jetstream.sh" self-test

  for hostile in "$ROOT_DIR" "$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-dir)" "$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)"; do
    status=0
    output="$(TMPDIR="$hostile" create_confined_scratch 2>&1)" || status=$?
    [[ "$status" -ne 0 && "$output" == "PHASE285-HARNESS[scratch-boundary-overlap]" ]] || return 1
  done
  scratch_link="$scratch/root-link"
  ln -s "$ROOT_DIR" "$scratch_link"
  status=0
  output="$(TMPDIR="$scratch_link" create_confined_scratch 2>&1)" || status=$?
  [[ "$status" -ne 0 && "$output" == "PHASE285-HARNESS[scratch-boundary-overlap]" ]] || return 1
  rm -- "$scratch_link"

  mkdir "$scratch/cleanup-control"
  if cleanup_confined_scratch "$scratch/cleanup-control" /usr/bin/false; then
    echo "PHASE285-HARNESS[cleanup-failure-accepted]" >&2
    return 1
  fi
  cleanup_confined_scratch "$scratch/cleanup-control"
  echo "phase285_nats_harness_self_test observation_mutants=12 targeted_mutants=$targeted transcript_mutants=$transcript_killed exact_prefix_mutants=$exact_prefix_killed pre_nats_prefix_refusals=$pre_nats_prefix_refusals environment_mutants=$environment_killed binding_mutants=$binding_killed matcher_mutants=$matcher_killed wiring_mutants=11 hostile_boundaries=4 cleanup_failure=1 passed=1"
)

compose_for() {
  docker compose -p "$PROJECT_NAME" -f "$BASE_COMPOSE" -f "$SCRATCH/compose.override.yml" --profile nats "$@"
}

wait_for_health() {
  local deadline=$((SECONDS + START_TIMEOUT_SECS))
  until curl -fsS "$NATS_HTTP_URL/healthz" >/dev/null; do
    (( SECONDS < deadline )) || return 1
    sleep 1
  done
}

validate_nats_login() {
  local port="$1" user="$2" password="$3" expect_success="$4"
  python3 -I - "$port" "$user" "$password" "$expect_success" <<'PY'
import json, socket, sys
port, user, password, expectation = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
    connection.settimeout(5)
    if not connection.recv(65536).startswith(b"INFO "):
        raise SystemExit("missing NATS INFO")
    connect = json.dumps({"user": user, "pass": password, "verbose": True})
    connection.sendall(f"CONNECT {connect}\r\nPING\r\n".encode())
    response = connection.recv(65536)
    success = b"PONG" in response and b"-ERR" not in response
    if success != (expectation == "success"):
        raise SystemExit(f"unexpected authentication response: {response!r}")
PY
}

validate_account_isolation() {
  local port="$1" mode="$2" stream="${3:-KV_phase285_service}"
  python3 -I - "$port" "$mode" "$stream" "$EXPECTED_USER" "$EXPECTED_PASSWORD" "$FOREIGN_USER" "$FOREIGN_PASSWORD" <<'PY'
import json, socket, sys, time

port, mode = int(sys.argv[1]), sys.argv[2]
stream = sys.argv[3]
expected = (sys.argv[4], sys.argv[5])
foreign = (sys.argv[6], sys.argv[7])

def request(credentials, subject, payload):
    inbox = "_INBOX.phase285.authority"
    body = json.dumps(payload, separators=(",", ":")).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.settimeout(5)
        if not connection.recv(65536).startswith(b"INFO "):
            raise SystemExit("missing NATS INFO")
        connect = json.dumps({"user": credentials[0], "pass": credentials[1], "verbose": True})
        commands = (
            f"CONNECT {connect}\r\nSUB {inbox} 1\r\n"
            f"PUB {subject} {inbox} {len(body)}\r\n"
        ).encode() + body + b"\r\nPING\r\n"
        connection.sendall(commands)
        received = b""
        response_deadline = time.monotonic() + 2
        while b"MSG " not in received and b"-ERR " not in received:
            remaining = response_deadline - time.monotonic()
            if remaining <= 0:
                break
            connection.settimeout(remaining)
            try:
                received += connection.recv(65536)
            except TimeoutError:
                break
        if b"MSG " not in received:
            if b"-ERR " in received:
                return {"transport_permission_error": True}
            if b"PONG\r\n" in received:
                return {"transport_no_response": True}
            raise SystemExit(f"NATS request did not flush: {received!r}")
        marker = received.index(b"MSG ")
        header_end = received.index(b"\r\n", marker)
        header = received[marker:header_end].split()
        size = int(header[-1])
        start = header_end + 2
        while len(received) < start + size:
            received += connection.recv(65536)
        return json.loads(received[start:start + size])

if mode == "create":
    created = request(expected, f"$JS.API.STREAM.CREATE.{stream}", {
        "name": stream,
        "subjects": ["$KV.phase285_service.>"],
        "storage": "file",
        "num_replicas": 1,
        "max_msgs_per_subject": 1,
    })
    if "error" in created or created.get("config", {}).get("name") != stream:
        raise SystemExit(f"expected account failed to create authority fixture: {created!r}")
elif mode != "inspect":
    raise SystemExit("unknown isolation mode")

visible = request(expected, f"$JS.API.STREAM.INFO.{stream}", {})
if "error" in visible or visible.get("config", {}).get("name") != stream:
    raise SystemExit(f"expected account cannot inspect its authority fixture: {visible!r}")
foreign_view = request(foreign, f"$JS.API.STREAM.INFO.{stream}", {})
if (
    "error" not in foreign_view
    and foreign_view.get("transport_permission_error") is not True
    and foreign_view.get("transport_no_response") is not True
):
    raise SystemExit(f"foreign account observed expected authority fixture: {foreign_view!r}")
PY
}

checkpoint_control() (
  [[ $# -eq 6 ]] || {
    echo "usage: $0 --checkpoint-control <token> <ack> <release> <done> <observation>" >&2
    return 64
  }
  local token="$2" acknowledgement="$3" release="$4" done="$5" observation="$6"
  local event_trace="${observation}.events"
  local expected_token="${SWARM_NATS_CHECKPOINT_TOKEN:-}"
  local deadline mount_before mount_after image_before image_after container_before container_after live_leader
  local checkpoint_client_port checkpoint_http_port checkpoint_http_url checkpoint_stream
  [[ -n "$expected_token" && "$token" == "$expected_token" ]] || {
    echo "PHASE285-HARNESS[checkpoint-token]" >&2
    return 1
  }
  PROJECT_NAME="${SWARM_NATS_COMPOSE_PROJECT:-}"
  SCRATCH="${SWARM_NATS_HARNESS_SCRATCH:-}"
  [[ -n "$PROJECT_NAME" && -d "$SCRATCH" ]] || return 1
  for path in "$acknowledgement" "$release" "$done" "$observation" "$event_trace"; do
    [[ "$path" == /* && "$(dirname -- "$path")" == "$(dirname -- "$acknowledgement")" ]] || return 1
  done
  [[ ! -e "$release" && ! -e "$done" && ! -e "$observation" && ! -e "$event_trace" ]] || return 1
  deadline=$((SECONDS + START_TIMEOUT_SECS))
  until [[ -f "$acknowledgement" ]]; do
    (( SECONDS < deadline )) || {
      echo "PHASE285-HARNESS[checkpoint-ack-timeout]" >&2
      return 1
    }
    sleep 1
  done
  checkpoint_stream="$(python3 -I - "$acknowledgement" "$token" <<'PY'
import json, pathlib, re, sys
path, token = pathlib.Path(sys.argv[1]), sys.argv[2]
raw = path.read_bytes()
if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
    raise SystemExit("ack event is not one canonical line")
event = json.loads(raw)
if set(event) != {"stream", "sequence", "duplicate", "proposed_digest", "token"}:
    raise SystemExit("ack event field set differs")
if event["token"] != token or event["duplicate"] is not False or event["sequence"] <= 0:
    raise SystemExit("ack event identity differs")
if not isinstance(event["stream"], str) or re.fullmatch(r"KV_phase285_[A-Za-z0-9_-]{1,128}", event["stream"]) is None:
    raise SystemExit("ack stream malformed")
if not isinstance(event["proposed_digest"], str) or len(event["proposed_digest"]) != 64:
    raise SystemExit("ack proposed digest malformed")
print(event["stream"])
PY
  )" || return 1
  (set -o noclobber; printf '1\tack_observed\t%s\n' "$token" >"$event_trace") 2>/dev/null || return 1
  container_before="$(compose_for ps -q nats)"
  [[ -n "$container_before" ]] || return 1
  image_before="$(docker inspect "$container_before" --format '{{.Config.Image}}')"
  mount_before="$(docker inspect "$container_before" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}:{{.RW}}{{end}}{{end}}')"
  [[ "$image_before" == "$PINNED_IMAGE" && -n "$mount_before" ]] || return 1
  compose_for kill -s KILL nats >/dev/null
  (set -o noclobber; printf '%s\n' "$token" >"$release") 2>/dev/null || return 1
  printf '2\trelease_written\t%s\n' "$token" >>"$event_trace" || return 1
  deadline=$((SECONDS + START_TIMEOUT_SECS))
  until [[ -f "$done" && "$(cat -- "$done")" == "$token" ]]; do
    (( SECONDS < deadline )) || {
      echo "PHASE285-HARNESS[checkpoint-cas-timeout]" >&2
      return 1
    }
    sleep 1
  done
  printf '3\tdone_observed\t%s\n' "$token" >>"$event_trace" || return 1
  compose_for start nats >/dev/null
  checkpoint_client_port="$(compose_for port nats 4222 | awk -F: 'NF {print $NF}')"
  checkpoint_http_port="$(compose_for port nats 8222 | awk -F: 'NF {print $NF}')"
  [[ "$checkpoint_client_port" =~ ^[0-9]+$ && "$checkpoint_http_port" =~ ^[0-9]+$ ]] || return 1
  checkpoint_http_url="http://127.0.0.1:$checkpoint_http_port"
  deadline=$((SECONDS + START_TIMEOUT_SECS))
  until curl -fsS "$checkpoint_http_url/healthz" >/dev/null; do
    (( SECONDS < deadline )) || return 1
    sleep 1
  done
  live_leader="$(curl -fsS "$checkpoint_http_url/varz" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["server_name"])')"
  [[ -n "$live_leader" ]] || return 1
  [[ "$(curl -fsS "$checkpoint_http_url/jsz?config=true" | python3 -I -c 'import json,sys; print(str(json.load(sys.stdin).get("config", {}).get("sync_always", False)).lower())')" == true ]] || return 1
  validate_nats_login "$checkpoint_client_port" "$EXPECTED_USER" "$EXPECTED_PASSWORD" success
  validate_account_isolation "$checkpoint_client_port" inspect "$checkpoint_stream"
  printf '%s\n' "$checkpoint_client_port" >"$SCRATCH/current-client-port.next"
  mv -- "$SCRATCH/current-client-port.next" "$SCRATCH/current-client-port"
  printf '%s\n' "$checkpoint_http_port" >"$SCRATCH/current-http-port.next"
  mv -- "$SCRATCH/current-http-port.next" "$SCRATCH/current-http-port"
  container_after="$(compose_for ps -q nats)"
  image_after="$(docker inspect "$container_after" --format '{{.Config.Image}}')"
  mount_after="$(docker inspect "$container_after" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}:{{.RW}}{{end}}{{end}}')"
  [[ "$container_after" == "$container_before" && "$image_after" == "$image_before" && "$mount_after" == "$mount_before" ]] || return 1
  printf '4\trestart_observed\t%s\n' "$token" >>"$event_trace" || return 1
  (set -o noclobber; cat >"$observation" <<EOF
token=$token
project=$PROJECT_NAME
service=nats
image_before=$image_before
image_after=$image_after
volume_before=$mount_before
volume_after=$mount_after
container_before=$container_before
container_after=$container_after
leader=$live_leader
client_port=$checkpoint_client_port
status=restarted
EOF
  ) 2>/dev/null || return 1
)

checkpoint_unavailable_control() (
  [[ $# -eq 3 ]] || {
    echo "usage: $0 --checkpoint-unavailable <stop|start> <token>" >&2
    return 64
  }
  local mode="$2" token="$3"
  local unavailable_client_port unavailable_http_port unavailable_http_url deadline
  [[ -n "${SWARM_NATS_CHECKPOINT_TOKEN:-}" && "$token" == "$SWARM_NATS_CHECKPOINT_TOKEN" ]] || return 1
  PROJECT_NAME="${SWARM_NATS_COMPOSE_PROJECT:-}"
  SCRATCH="${SWARM_NATS_HARNESS_SCRATCH:-}"
  [[ -n "$PROJECT_NAME" && -d "$SCRATCH" ]] || return 1
  if [[ "$mode" == stop ]]; then
    compose_for stop nats >/dev/null
    if curl -fsS --max-time 1 "${NATS_HTTP_URL:-http://127.0.0.1:1}/healthz" >/dev/null 2>&1; then
      return 1
    fi
  elif [[ "$mode" == start ]]; then
    compose_for start nats >/dev/null
    unavailable_client_port="$(compose_for port nats 4222 | awk -F: 'NF {print $NF}')"
    unavailable_http_port="$(compose_for port nats 8222 | awk -F: 'NF {print $NF}')"
    [[ "$unavailable_client_port" =~ ^[0-9]+$ && "$unavailable_http_port" =~ ^[0-9]+$ ]] || return 1
    unavailable_http_url="http://127.0.0.1:$unavailable_http_port"
    deadline=$((SECONDS + START_TIMEOUT_SECS))
    until curl -fsS "$unavailable_http_url/healthz" >/dev/null; do
      (( SECONDS < deadline )) || return 1
      sleep 1
    done
    printf '%s\n' "$unavailable_client_port" >"$SCRATCH/current-client-port.next"
    mv -- "$SCRATCH/current-client-port.next" "$SCRATCH/current-client-port"
    printf '%s\n' "$unavailable_http_port" >"$SCRATCH/current-http-port.next"
    mv -- "$SCRATCH/current-http-port.next" "$SCRATCH/current-http-port"
  else
    return 64
  fi
)

run_harness() (
  [[ $# -gt 0 ]] || { echo "usage: $0 <command> [args...]" >&2; return 64; }
  local scratch_cleanup=0 stack_started=0 child_status=0 mount_before mount_after
  local actual_image tls_actual_image repo_digest reported_version reported_sync_always expected_test="" expected_filtered=4 transcript index previous
  local tls_nats_port tls_nats_http_port tls_nats_http_url tls_deadline topology_mode="${PHASE285_NATS_TOPOLOGY_MODE:-normal}"
  parse_exact_test_prefix "$@" || {
    echo "PHASE285-HARNESS[exact-test-prefix]" >&2
    return 64
  }
  set -- "${HARNESS_COMMAND[@]}"
  [[ $# -gt 0 ]] || { echo "PHASE285-HARNESS[exact-test-command]" >&2; return 64; }
  if [[ -n "$EXPECTED_EXACT_TEST" ]]; then
    expected_test="$EXPECTED_EXACT_TEST"
    expected_filtered="$EXPECTED_EXACT_FILTERED"
  fi
  SCRATCH="$(create_confined_scratch "$(docker_shared_scratch_parent)")"
  PROJECT_NAME="phase285-nats-$PPID-$$"
  NATS_PORT=""
  NATS_HTTP_PORT=""
  # Invoked by the EXIT trap below.
  # shellcheck disable=SC2329
  cleanup() {
    local status=$?
    if (( stack_started == 1 )); then
      if (( status != 0 )); then
        if ! compose_for ps >&2; then
          echo "PHASE285-HARNESS[diagnostic-ps-failed]" >&2
        fi
        if ! compose_for logs nats nats_tls >&2; then
          echo "PHASE285-HARNESS[diagnostic-logs-failed]" >&2
        fi
      fi
      if ! compose_for down -v --remove-orphans >/dev/null; then
        echo "PHASE285-HARNESS[compose-cleanup-failed]" >&2
        status=1
      fi
    fi
    if ! cleanup_confined_scratch "$SCRATCH"; then
      echo "PHASE285-HARNESS[scratch-cleanup-failed]" >&2
      status=1
    else
      scratch_cleanup=1
    fi
    (( scratch_cleanup == 1 )) || status=1
    exit "$status"
  }
  trap cleanup EXIT
  trap 'exit 130' INT TERM
  write_configuration "$SCRATCH" "$topology_mode"
  validate_authority_topology "$SCRATCH/nats.conf"
  validate_authority_topology "$SCRATCH/nats-tls.conf"

  actual_image="$(compose_for config --format json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["services"]["nats"]["image"])')"
  tls_actual_image="$(compose_for config --format json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["services"]["nats_tls"]["image"])')"
  [[ "$actual_image" == "$PINNED_IMAGE" ]] || { echo "PHASE285-HARNESS[wrong-image:$actual_image]" >&2; return 1; }
  [[ "$tls_actual_image" == "$PINNED_IMAGE" ]] || { echo "PHASE285-HARNESS[wrong-tls-image:$tls_actual_image]" >&2; return 1; }
  if ! docker image inspect "$PINNED_IMAGE" >/dev/null 2>&1; then
    docker pull "$PINNED_IMAGE" >/dev/null
  fi
  repo_digest="$(docker image inspect "$PINNED_IMAGE" --format '{{join .RepoDigests "\n"}}' | grep -Fx "$PINNED_REPO_DIGEST")"
  [[ "$repo_digest" == "$PINNED_REPO_DIGEST" ]] || return 1
  compose_for up -d nats nats_tls >/dev/null
  stack_started=1
  NATS_PORT="$(compose_for port nats 4222 | awk -F: 'NF {print $NF}')"
  NATS_HTTP_PORT="$(compose_for port nats 8222 | awk -F: 'NF {print $NF}')"
  [[ "$NATS_PORT" =~ ^[0-9]+$ && "$NATS_HTTP_PORT" =~ ^[0-9]+$ ]] || return 1
  NATS_HTTP_URL="http://127.0.0.1:$NATS_HTTP_PORT"
  wait_for_health
  tls_nats_port="$(compose_for port nats_tls 4222 | awk -F: 'NF {print $NF}')"
  tls_nats_http_port="$(compose_for port nats_tls 8222 | awk -F: 'NF {print $NF}')"
  [[ "$tls_nats_port" =~ ^[0-9]+$ && "$tls_nats_http_port" =~ ^[0-9]+$ ]] || return 1
  tls_nats_http_url="http://127.0.0.1:$tls_nats_http_port"
  tls_deadline=$((SECONDS + START_TIMEOUT_SECS))
  until curl -fsS "$tls_nats_http_url/healthz" >/dev/null; do
    (( SECONDS < tls_deadline )) || return 1
    sleep 1
  done
  reported_version="$(curl -fsS "$NATS_HTTP_URL/varz" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
  [[ "$reported_version" == "$PINNED_VERSION" ]] || return 1
  reported_sync_always="$(curl -fsS "$NATS_HTTP_URL/jsz?config=true" | python3 -I -c 'import json,sys; print(str(json.load(sys.stdin).get("config", {}).get("sync_always", False)).lower())')"
  [[ "$reported_sync_always" == true ]] || return 1
  validate_nats_login "$NATS_PORT" "$EXPECTED_USER" "$EXPECTED_PASSWORD" success
  validate_nats_login "$NATS_PORT" "$FOREIGN_USER" "$FOREIGN_PASSWORD" success
  validate_nats_login "$NATS_PORT" "$EXPECTED_USER" "$FOREIGN_PASSWORD" refusal
  if [[ "$topology_mode" == normal ]]; then
    validate_account_isolation "$NATS_PORT" create
  fi
  mount_before="$(compose_for ps -q nats | xargs docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}:{{.RW}}{{end}}{{end}}')"
  [[ -n "$mount_before" ]] || return 1
  compose_for stop nats >/dev/null
  compose_for start nats >/dev/null
  NATS_PORT="$(compose_for port nats 4222 | awk -F: 'NF {print $NF}')"
  NATS_HTTP_PORT="$(compose_for port nats 8222 | awk -F: 'NF {print $NF}')"
  [[ "$NATS_PORT" =~ ^[0-9]+$ && "$NATS_HTTP_PORT" =~ ^[0-9]+$ ]] || return 1
  NATS_HTTP_URL="http://127.0.0.1:$NATS_HTTP_PORT"
  wait_for_health
  if [[ "$topology_mode" == normal ]]; then
    validate_account_isolation "$NATS_PORT" inspect
  fi
  mount_after="$(compose_for ps -q nats | xargs docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}:{{.RW}}{{end}}{{end}}')"
  [[ "$mount_after" == "$mount_before" ]] || return 1
  [[ "$(compose_for ps -q nats | xargs docker inspect --format '{{range .Mounts}}{{if eq .Destination "/etc/nats/nats.conf"}}{{.RW}}{{end}}{{end}}')" == false ]] || return 1

  HARNESS_NONCE="phase285-$PPID-$$-$(date +%s)"
  cat >"$SCRATCH/observation" <<EOF
image=$actual_image
repo_digest=$repo_digest
version=$reported_version
health=ok
service=nats
expected_account=$EXPECTED_ACCOUNT
foreign_account=$FOREIGN_ACCOUNT
foreign_resource_isolation=ok
config_mount=ro
volume_restart=stable
sync_interval=always
nonce=$HARNESS_NONCE
EOF
  validate_observation "$SCRATCH/observation" "$HARNESS_NONCE"
  bind_checkpoint_test_environment "$HARNESS_NONCE"
  if ! is_exact_witness_package_test_command "$@"; then
    unset RUST_TEST_THREADS
  fi

  for ((index = 1; index <= $#; index++)); do
    if [[ -z "$EXPECTED_EXACT_TEST" && "${!index}" == --exact && $index -gt 1 ]]; then
      previous=$((index - 1))
      expected_test="${!previous}"
    fi
    if [[ "${!index}" == jetstream_checkpoint ]]; then
      expected_filtered=3
    elif [[ "${!index}" == full_service_path ]]; then
      expected_filtered=9
    fi
  done
  transcript="$SCRATCH/command.transcript"
  printf 'phase285_harness_nonce=%s\n' "$HARNESS_NONCE" >"$transcript"
  export NATS_URL="nats://$EXPECTED_USER:$EXPECTED_PASSWORD@127.0.0.1:$NATS_PORT"
  export SWARM_NATS_RUNTIME_URL="nats://$RUNTIME_USER:$RUNTIME_PASSWORD@127.0.0.1:$NATS_PORT"
  export SWARM_NATS_WITNESS_URL="nats://$WITNESS_USER:$WITNESS_PASSWORD@127.0.0.1:$NATS_PORT"
  export SWARM_NATS_STORE_URL="nats://$STORE_USER:$STORE_PASSWORD@127.0.0.1:$NATS_PORT"
  export SWARM_NATS_INIT_URL="nats://$INIT_USER:$INIT_PASSWORD@127.0.0.1:$NATS_PORT"
  export SWARM_NATS_ROLE_ENDPOINT="nats://127.0.0.1:$NATS_PORT"
  export SWARM_NATS_WITNESS_USER="$WITNESS_USER"
  export SWARM_NATS_WITNESS_PASSWORD="$WITNESS_PASSWORD"
  export SWARM_NATS_STORE_USER="$STORE_USER"
  export SWARM_NATS_STORE_PASSWORD="$STORE_PASSWORD"
  export SWARM_NATS_STORE_TLS_URL="tls://localhost:$tls_nats_port"
  export SWARM_NATS_TLS_HTTP_URL="$tls_nats_http_url"
  export SWARM_NATS_TLS_CA_PATH="$SCRATCH/tls-ca.pem"
  export SWARM_NATS_TLS_SERVER_NAME="localhost"
  export SWARM_NATS_TLS_CREDENTIAL_TOKEN="$TLS_CREDENTIAL_TOKEN"
  export SWARM_NATS_RUNTIME_CREDENTIAL_PATH="$SCRATCH/runtime.credentials.json"
  export SWARM_NATS_WITNESS_CREDENTIAL_PATH="$SCRATCH/witness.credentials.json"
  export SWARM_NATS_STORE_CREDENTIAL_PATH="$SCRATCH/store.credentials.json"
  export SWARM_NATS_INIT_CREDENTIAL_PATH="$SCRATCH/init.credentials.json"
  if [[ "$topology_mode" == relay ]]; then
    export SWARM_NATS_RELAY_CREDENTIAL_PATH="$SCRATCH/relay.credentials.json"
    export PHASE285_RELAY_TOPOLOGY_TOKEN="relay-phase285-$HARNESS_NONCE"
  else
    unset SWARM_NATS_RELAY_CREDENTIAL_PATH PHASE285_RELAY_TOPOLOGY_TOKEN
  fi
  export PHASE285_TOPOLOGY_CONFIG_PATH="$SCRATCH/nats-tls.conf"
  export PHASE285_TOPOLOGY_RUNTIME_CREDENTIAL_PATH="$SCRATCH/runtime.credentials.json"
  export PHASE285_TOPOLOGY_WITNESS_CREDENTIAL_PATH="$SCRATCH/witness.credentials.json"
  export PHASE285_TOPOLOGY_STORE_CREDENTIAL_PATH="$SCRATCH/store.credentials.json"
  export PHASE285_TOPOLOGY_INIT_CREDENTIAL_PATH="$SCRATCH/init.credentials.json"
  export SWARM_NATS_CAPABILITY_INVOCATION_TOKEN="$HARNESS_NONCE"
  export NATS_HTTP_URL
  export SWARM_NATS_COMPOSE_PROJECT="$PROJECT_NAME"
  export SWARM_NATS_HARNESS_SCRATCH="$SCRATCH"
  export SWARM_NATS_CHECKPOINT_TOKEN="$HARNESS_NONCE"
  printf '%s\n' "$NATS_PORT" >"$SCRATCH/current-client-port"
  export SWARM_NATS_CURRENT_PORT_FILE="$SCRATCH/current-client-port"
  printf '%s\n' "$NATS_HTTP_PORT" >"$SCRATCH/current-http-port"
  export SWARM_NATS_CURRENT_HTTP_PORT_FILE="$SCRATCH/current-http-port"
  set +e
  "$@" 2>&1 | tee -a "$transcript"
  child_status=${PIPESTATUS[0]}
  set -e
  (( child_status == 0 )) || return "$child_status"
  if [[ -n "$expected_test" ]]; then
    validate_test_transcript "$transcript" "$expected_test" "$HARNESS_NONCE" "$expected_filtered" || {
      echo "PHASE285-HARNESS[non-materialized-test:$expected_test]" >&2
      return 1
    }
  fi
)

if [[ "${1:-}" == --checkpoint-control ]]; then
  checkpoint_control "$@"
elif [[ "${1:-}" == --checkpoint-unavailable ]]; then
  checkpoint_unavailable_control "$@"
elif [[ "${1:-}" == --self-test ]]; then
  if [[ $# -eq 1 ]]; then
    self_test
  elif [[ $# -eq 2 && "$2" == topology-owner-blocks ]]; then
    self_test
  else
    echo "usage: $0 --self-test [topology-owner-blocks]" >&2
    exit 64
  fi
elif [[ "${1:-}" == --topology-validator ]]; then
  [[ $# -eq 3 && "$3" =~ ^(validate|self-test)$ ]] || { echo "usage: $0 --topology-validator <config> <validate|self-test>" >&2; exit 64; }
  validate_authority_topology "$2" "$3"
elif [[ "${1:-}" == --relay-service-checkpoint ]]; then
  shift
  [[ $# -gt 0 ]] || { echo "usage: $0 --relay-service-checkpoint <command> [args...]" >&2; exit 64; }
  PHASE285_NATS_TOPOLOGY_MODE=relay run_harness "$@"
else
  run_harness "$@"
fi
