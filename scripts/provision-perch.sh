#!/usr/bin/env bash
#
# Provision the local Ambush relay for the operator-console dev loop
# (docs/plans/ambush-ui/integration/11-PLAN-GROUND.md Task 10, P0-21).
#
# What it does, in order:
#   1. Resolves the dev operator identity and prints its Nostr public key. That
#      key is the value rulesets-dev/perch-dev.yaml carries as
#      operator_surface.auth.principals[].nostr_pubkey (Task 9); the script
#      checks the two agree and says so loudly when they do not.
#   2. Mints the twelve lane channels named by standard_threat_classes()
#      (crates/swarm-runtime/src/escalation.rs): open visibility, stream type,
#      one per threat class, named `lane-<slug-with-dashes>`. The taxonomy
#      check is fatal -- a missing or moved standard_threat_classes() aborts
#      rather than provisioning a possibly stale hard-coded list. Idempotent:
#      a channel that already carries the name is reused, never duplicated,
#      including an archived one, which is unarchived and reused.
#   3. Writes .perch-dev/lane-channels.json (threat-class slug -> channel UUID)
#      and .perch-dev/operator.env (AMBUSH_* variables for the ambush CLI).
#      .perch-dev/ is git-ignored.
#
# Membership for the bridge identities is First card's job (it derives them).
#
# The dev operator identity
#   By default the secret is sha256("ambush-perch-dev-operator-v1"): a
#   WELL-KNOWN development identity for a LOCAL relay, deterministic so the
#   committed, debug-signed rulesets-dev/perch-dev.yaml can name its public key
#   without a per-machine re-sign. It authenticates nothing outside this dev
#   stack; a release daemon refuses the ruleset that trusts it (Task 9).
#   Export AMBUSH_PRIVATE_KEY (64 hex) to use your own key instead; the script
#   then tells you to update the ruleset and re-sign it with
#   `cargo run -p swarm-runtime-http --bin sign_dev_ruleset -- rulesets-dev/perch-dev.yaml`.
#
# Requirements: the ambush CLI (`cd workspace && cargo build --release -p ambush-cli`),
# a reachable relay (`docker compose up -d postgres redis relay`), node (the
# Hermit one under workspace/bin is preferred), python3, curl, and a full
# checkout (crates/swarm-runtime/src/escalation.rs must be present).
#
# Tests: `bash scripts/provision-perch.test.sh` -- hermetic, no relay needed.
#
# Environment:
#   AMBUSH_RELAY_URL    relay base URL                  [default: http://localhost:3000]
#   AMBUSH_PRIVATE_KEY  operator secret, 64 hex         [default: the dev identity above]
#   AMBUSH_CLI          path to the ambush binary       [default: workspace/target/release/ambush]
#   PERCH_DEV_DIR       output directory                [default: .perch-dev]
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RELAY_URL="${AMBUSH_RELAY_URL:-http://localhost:3000}"
CLI="${AMBUSH_CLI:-$ROOT_DIR/workspace/target/release/ambush}"
OUT_DIR="${PERCH_DEV_DIR:-$ROOT_DIR/.perch-dev}"
RULESET="$ROOT_DIR/rulesets-dev/perch-dev.yaml"
ESCALATION_RS="$ROOT_DIR/crates/swarm-runtime/src/escalation.rs"
DEV_OPERATOR_SEED="ambush-perch-dev-operator-v1"

# The twelve lanes, in standard_threat_classes() order. Checked against the
# source below so the list cannot drift silently.
THREAT_CLASSES=(
  lateral_movement
  data_exfiltration
  privilege_escalation
  command_and_control
  initial_access
  persistence
  supply_chain
  defense_evasion
  credential_access
  discovery
  execution
  impact
)

die() {
  echo "provision-perch: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH"
}

need curl
need python3

if [ -x "$ROOT_DIR/workspace/bin/node" ]; then
  NODE="$ROOT_DIR/workspace/bin/node"
else
  need node
  NODE="$(command -v node)"
fi

[ -x "$CLI" ] || die "ambush CLI not found at $CLI; build it with:
  cd workspace && . ./bin/activate-hermit && cargo build --release -p ambush-cli
or point AMBUSH_CLI at an existing binary"

# --- 0. The lane list matches the engine's taxonomy ---------------------------
# Hard requirement, never advisory. Provisioning lanes that no longer match the
# engine's taxonomy is worse than not provisioning at all: frames the engine
# routes to a class with no lane land nowhere, while the console shows a full
# set of lanes that look right. A missing file or a moved function means the
# list is unverifiable -- exactly when the hard-coded copy above is most likely
# to be the stale one.
[ -f "$ESCALATION_RS" ] \
  || die "$ESCALATION_RS not found; the lane list cannot be checked against standard_threat_classes(). Run this from a full checkout."

expected="$(python3 - "$ESCALATION_RS" <<'PYEOF'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
body = re.search(r"pub fn standard_threat_classes\(\) -> Vec<ThreatClass> \{\s*vec!\[(.*?)\]", src, re.S)
if not body:
    sys.exit("standard_threat_classes() not found")
names = re.findall(r"ThreatClass::([A-Za-z]+)", body.group(1))
print(" ".join(re.sub(r"(?<!^)(?=[A-Z])", "_", n).lower() for n in names))
PYEOF
)" || die "could not read standard_threat_classes() from $ESCALATION_RS; the lane list is unverifiable"

[ "$expected" = "${THREAT_CLASSES[*]}" ] \
  || die "lane list drifted from standard_threat_classes(): expected [$expected], script has [${THREAT_CLASSES[*]}]"

# --- 1. The dev operator identity ---------------------------------------------
if [ -n "${AMBUSH_PRIVATE_KEY:-}" ]; then
  KEY_SOURCE="AMBUSH_PRIVATE_KEY from the environment"
  OPERATOR_SECRET="$AMBUSH_PRIVATE_KEY"
else
  KEY_SOURCE="the well-known dev identity sha256(\"$DEV_OPERATOR_SEED\")"
  OPERATOR_SECRET="$(printf '%s' "$DEV_OPERATOR_SEED" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
fi

case "$OPERATOR_SECRET" in
  *[!0-9a-f]*|"") die "AMBUSH_PRIVATE_KEY must be 64 lowercase hex characters (nsec is not accepted here)" ;;
esac
[ "${#OPERATOR_SECRET}" -eq 64 ] || die "AMBUSH_PRIVATE_KEY must be exactly 64 hex characters"

# x-only secp256k1 public key (NIP-01), via OpenSSL through node: a SEC1
# ECPrivateKey DER wrapper around the 32-byte scalar, then the JWK `x`.
#
# The secret goes in on **stdin**, never in argv: an argv element is readable
# by every local process for the life of the call (`ps -ef`,
# /proc/<pid>/cmdline), so passing a 64-hex private key that way publishes it
# to every user on the box.
OPERATOR_PUBKEY="$(printf '%s' "$OPERATOR_SECRET" | "$NODE" -e '
const crypto = require("node:crypto");
const fs = require("node:fs");
const d = Buffer.from(fs.readFileSync(0, "utf8").trim(), "hex");
const order = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const s = BigInt("0x" + d.toString("hex"));
if (s === 0n || s >= order) { console.error("secret is not a valid secp256k1 scalar"); process.exit(1); }
const der = Buffer.concat([Buffer.from("302e0201010420", "hex"), d, Buffer.from("a00706052b8104000a", "hex")]);
const priv = crypto.createPrivateKey({ key: der, format: "der", type: "sec1" });
const jwk = crypto.createPublicKey(priv).export({ format: "jwk" });
process.stdout.write(Buffer.from(jwk.x, "base64url").toString("hex"));
')"

echo "operator identity: $KEY_SOURCE"
echo "operator pubkey:   $OPERATOR_PUBKEY"

if [ -f "$RULESET" ]; then
  ruleset_pubkey="$(sed -n 's/^[[:space:]]*nostr_pubkey:[[:space:]]*"\{0,1\}\([0-9a-f]\{64\}\)"\{0,1\}[[:space:]]*$/\1/p' "$RULESET" | head -n 1)"
  if [ -z "$ruleset_pubkey" ]; then
    echo "warning: $RULESET carries no nostr_pubkey; holds cannot be addressed to this operator" >&2
  elif [ "$ruleset_pubkey" != "$OPERATOR_PUBKEY" ]; then
    echo "warning: $RULESET names operator pubkey $ruleset_pubkey," >&2
    echo "         but this identity is $OPERATOR_PUBKEY." >&2
    echo "         Update operator_surface.auth.principals[].nostr_pubkey and re-sign:" >&2
    echo "         cargo run -p swarm-runtime-http --bin sign_dev_ruleset -- rulesets-dev/perch-dev.yaml" >&2
  else
    echo "ruleset:           $RULESET names this pubkey"
  fi
fi

# --- 2. The relay -------------------------------------------------------------
curl -fsS --max-time 5 "$RELAY_URL/health" >/dev/null 2>&1 \
  || die "relay at $RELAY_URL is not healthy; start it with:
  docker compose up -d postgres redis relay
(the relay needs workspace/.env with AMBUSH_RELAY_PRIVATE_KEY; \`cd workspace && just bootstrap\` writes one)"

export AMBUSH_RELAY_URL="$RELAY_URL"
export AMBUSH_PRIVATE_KEY="$OPERATOR_SECRET"

# --- 3. The twelve lanes ------------------------------------------------------
mkdir -p "$OUT_DIR"

# Print "<channel_id> <archived|active>" for the first exact-name match, or
# nothing. `--include-archived` is load-bearing: the CLI hides archived channels
# by default, so without it an archived lane is invisible here and the run below
# creates a second channel with the same name -- the exact duplication this
# function exists to prevent.
existing_channel() {
  "$CLI" --format json channels search --query "$1" --exact --include-archived \
    | python3 -c '
import json, sys
rows = json.load(sys.stdin)
if rows:
    print(rows[0]["channel_id"], "archived" if rows[0]["archived"] else "active")
'
}

# Create the channel; print its channel_id or fail with the relay's message.
create_channel() {
  "$CLI" --format json channels create \
    --name "$1" --type stream --visibility open \
    --description "$2" \
    | python3 -c '
import json, sys
resp = json.load(sys.stdin)
if not resp.get("accepted") or not resp.get("channel_id"):
    sys.exit("relay refused the channel: " + json.dumps(resp))
print(resp["channel_id"])
'
}

# Bring an archived lane back into service. Reusing it archived would hand the
# console a lane that accepts nothing.
unarchive_channel() {
  "$CLI" --format json channels unarchive --channel "$1" \
    | python3 -c '
import json, sys
resp = json.load(sys.stdin)
if not resp.get("accepted"):
    sys.exit("relay refused the unarchive: " + json.dumps(resp))
'
}

declare -a LANE_IDS=()
for slug in "${THREAT_CLASSES[@]}"; do
  name="lane-${slug//_/-}"
  read -r channel_id channel_state <<<"$(existing_channel "$name")"
  if [ -z "$channel_id" ]; then
    channel_id="$(create_channel "$name" "Lane for the ${slug//_/ } threat class (swarm engine)")"
    echo "lane $name: created $channel_id"
  elif [ "$channel_state" = "archived" ]; then
    unarchive_channel "$channel_id" \
      || die "lane $name exists as archived channel $channel_id and could not be unarchived"
    echo "lane $name: reused $channel_id (unarchived)"
  else
    echo "lane $name: exists $channel_id"
  fi
  LANE_IDS+=("$slug=$channel_id")
done

# --- 4. Outputs ---------------------------------------------------------------
python3 - "$OUT_DIR/lane-channels.json" "${LANE_IDS[@]}" <<'PY'
import json, sys
path, pairs = sys.argv[1], sys.argv[2:]
lanes = dict(pair.split("=", 1) for pair in pairs)
with open(path, "w", encoding="utf-8") as handle:
    json.dump(lanes, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

umask 077
cat > "$OUT_DIR/operator.env" <<ENV
# Written by scripts/provision-perch.sh. Source it (set -a; . .perch-dev/operator.env)
# to drive the ambush CLI as the dev operator. $KEY_SOURCE.
AMBUSH_RELAY_URL=$RELAY_URL
AMBUSH_PRIVATE_KEY=$OPERATOR_SECRET
AMBUSH_OPERATOR_PUBKEY=$OPERATOR_PUBKEY
ENV

echo
echo "wrote $OUT_DIR/lane-channels.json (${#LANE_IDS[@]} lanes) and $OUT_DIR/operator.env"
echo "operator pubkey for rulesets-dev/perch-dev.yaml: $OPERATOR_PUBKEY"
