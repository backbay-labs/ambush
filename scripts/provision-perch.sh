#!/usr/bin/env bash
#
# Provision the local Ambush relay for the operator-console dev loop
# (docs/plans/ambush-ui/integration/11-PLAN-GROUND.md Task 10, P0-21, amended by
# 12-PLAN-FIRST-CARD.md Task 14 / decision D-FC-5).
#
# What it does, in order:
#   1. Resolves the dev operator identity and prints its Nostr public key. That
#      key is the value rulesets-dev/perch-dev.yaml carries as
#      operator_surface.auth.principals[].nostr_pubkey (Task 9); the script
#      checks the two agree and says so loudly when they do not.
#   2. Writes .perch-dev/operator.nsec (mode 600) so the desktop can restore the
#      identity, and .perch-dev/operator.env (AMBUSH_* variables for the ambush
#      CLI). .perch-dev/ is git-ignored.
#   3. Reads the bridge's public identities back from a RUNNING daemon into
#      .perch-dev/identities.json. Skipped, with a printed re-run line, when the
#      daemon is not up yet -- provisioning the operator does not depend on it.
#   4. When workspace/.env sets AMBUSH_REQUIRE_RELAY_MEMBERSHIP=true, adds the
#      operator and every bridge identity to the relay's member list. The dev
#      default leaves that variable unset (an open relay,
#      workspace/crates/ambush-relay/src/config.rs:670) and the loop is skipped.
#
# WHAT IT NO LONGER DOES: mint the twelve lane channels. Decision D-FC-5 moved
# that to the bridge, which creates them idempotently at every daemon start from
# the UUIDs committed in `perch.lane_channels`, and adds each operator principal
# to each lane. A duplicate kind:9007 is answered "duplicate: channel already
# exists" and the bridge's OK classifier treats that as success, so a fresh relay
# database (`docker compose down -v`) recovers every lane on the next daemon
# start with no operator action. That also removed this script's dependency on
# the ambush CLI.
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
# Requirements: a reachable relay (`docker compose up -d postgres redis relay`),
# node (the Hermit one under workspace/bin is preferred), python3 and curl.
# docs/PERCH-DEV.md runs the whole loop around this script.
#
# Environment:
#   AMBUSH_RELAY_URL    relay base URL                  [default: http://localhost:3000]
#   AMBUSH_PRIVATE_KEY  operator secret, 64 hex         [default: the dev identity above]
#   PERCH_DAEMON_URL    swarm_detect --bind base URL    [default: http://127.0.0.1:9090]
#   PERCH_DEV_DIR       output directory                [default: .perch-dev]
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RELAY_URL="${AMBUSH_RELAY_URL:-http://localhost:3000}"
DAEMON_URL="${PERCH_DAEMON_URL:-http://127.0.0.1:9090}"
OUT_DIR="${PERCH_DEV_DIR:-$ROOT_DIR/.perch-dev}"
RULESET="$ROOT_DIR/rulesets-dev/perch-dev.yaml"
DEV_OPERATOR_SEED="ambush-perch-dev-operator-v1"

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
# The secret arrives on stdin, never as an argv element: argv is world-readable
# through `ps -ef` and /proc/<pid>/cmdline for the life of the process.
OPERATOR_PUBKEY="$(printf '%s' "$OPERATOR_SECRET" | "$NODE" -e '
const crypto = require("node:crypto");
const d = Buffer.from(require("node:fs").readFileSync(0, "utf8").trim(), "hex");
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

# --- 3. Operator outputs ------------------------------------------------------
mkdir -p "$OUT_DIR"
umask 077

# bech32 nsec (NIP-19). The desktop's Keys::parse accepts hex too, but the
# onboarding field, the backup step and every doc speak nsec, so write the form
# an operator can paste without thinking about it.
printf '%s' "$OPERATOR_SECRET" | python3 - > "$OUT_DIR/operator.nsec" <<'PY'
import sys

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

hrp = "nsec"
data = convertbits(bytes.fromhex(sys.stdin.read().strip()), 8, 5)
checksum_input = hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
polymod_value = polymod(checksum_input) ^ 1
checksum = [(polymod_value >> 5 * (5 - i)) & 31 for i in range(6)]
sys.stdout.write(hrp + "1" + "".join(CHARSET[d] for d in data + checksum) + "\n")
PY
chmod 600 "$OUT_DIR/operator.nsec"

cat > "$OUT_DIR/operator.env" <<ENV
# Written by scripts/provision-perch.sh. Source it (set -a; . .perch-dev/operator.env)
# to drive the ambush CLI as the dev operator. $KEY_SOURCE.
AMBUSH_RELAY_URL=$RELAY_URL
AMBUSH_PRIVATE_KEY=$OPERATOR_SECRET
AMBUSH_OPERATOR_PUBKEY=$OPERATOR_PUBKEY
ENV
chmod 600 "$OUT_DIR/operator.env"

echo "wrote $OUT_DIR/operator.nsec (mode 600) and $OUT_DIR/operator.env"
echo "import $OUT_DIR/operator.nsec into the desktop (onboarding → restore an existing identity)"

# --- 4. The bridge identities, read back from a running daemon -----------------
# The bridge derives its own keys from PERCH_BRIDGE_NOSTR_SEED at startup
# (D-FC-1), so this list only exists once the daemon has run. It is the
# admitted-issuer set the console reads (D-FC-2), and the input to the
# membership loop below.
IDENTITIES_JSON="$OUT_DIR/identities.json"
if curl -fsS --max-time 5 "$DAEMON_URL/metrics/perch/identities" > "$IDENTITIES_JSON" 2>/dev/null; then
  identity_count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["identities"]))' "$IDENTITIES_JSON")"
  echo "wrote $IDENTITIES_JSON ($identity_count bridge identities from $DAEMON_URL)"
else
  rm -f "$IDENTITIES_JSON"
  echo "note: no daemon answering at $DAEMON_URL/metrics/perch/identities."
  echo "      Start it, then re-run this script (or just this line) to capture the"
  echo "      admitted-issuer set:"
  echo "      curl -sf $DAEMON_URL/metrics/perch/identities > $OUT_DIR/identities.json"
fi

# --- 5. Relay membership, only on a closed relay -------------------------------
WORKSPACE_ENV="$ROOT_DIR/workspace/.env"
require_membership=""
if [ -f "$WORKSPACE_ENV" ]; then
  require_membership="$(sed -n 's/^[[:space:]]*AMBUSH_REQUIRE_RELAY_MEMBERSHIP[[:space:]]*=[[:space:]]*//p' "$WORKSPACE_ENV" | tail -n 1 | tr -d '"'"'"' \r')"
fi

if [ "$require_membership" != "true" ]; then
  echo "note: AMBUSH_REQUIRE_RELAY_MEMBERSHIP is not \`true\` in workspace/.env, so this"
  echo "      relay admits any authenticated key and no memberships are needed."
  echo "      Set it to true and re-run to add the operator and the bridge identities."
  exit 0
fi

command -v cargo >/dev/null 2>&1 || die "AMBUSH_REQUIRE_RELAY_MEMBERSHIP=true needs cargo to run ambush-admin"

members="$OPERATOR_PUBKEY"
if [ -f "$IDENTITIES_JSON" ]; then
  members="$members $(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
print(" ".join(i["pubkey"] for i in doc["identities"]))
' "$IDENTITIES_JSON")"
else
  echo "warning: $IDENTITIES_JSON is missing, so only the operator is added." >&2
  echo "         Start the daemon and re-run to admit the bridge identities." >&2
fi

# ambush-admin writes the member row directly and signs the kind:13534 list, so
# it needs the relay's own DATABASE_URL/REDIS_URL/AMBUSH_RELAY_PRIVATE_KEY --
# exactly what workspace/.env holds.
for pubkey in $members; do
  echo "add-member $pubkey"
  # shellcheck source=/dev/null
  ( set -a; . "$WORKSPACE_ENV"; set +a
    cd "$ROOT_DIR/workspace" && cargo run --quiet -p ambush-admin -- add-member --pubkey "$pubkey" --role member )
done
