#!/usr/bin/env bash
# docker-entrypoint.sh — bootstrap the workshop minter against a live Tower 1,
# then exec it. This is the containerized form of what examples/tower-provision/
# up.sh does inline: the minter is a DELEGATE of Tower 1 (sumo-ca), so it can't
# self-start — it must first ask sumo-ca to sign it a short leaf cert carrying the
# delegated-rights extension, and sign its JWTs with that leaf's key.
#
# Sequence (mirrors up.sh):
#   1. wait for Tower 1 /healthz
#   2. POST $CA_URL/admin/workshop/delegate-cert  -> { key_pem, cert_pem, ca_root_pem }
#   3. write key + build the x5c chain (leaf-first: minter leaf, then sumo-ca root)
#   4. exec sovd-token-helper with that key/chain
#
# Env (with the compose defaults):
#   CA_URL                          Tower 1 base URL (e.g. http://sumo-ca:8080)
#   SOVD_MINTER_PORT                listen port (default 9200)
#   SOVD_MINTER_OPERATOR_TOKEN      operator bearer required on POST /mint
#   SOVD_MINTER_KID / _ISSUER       JWT kid / iss (default workshop-minter-1 / workshop-ca)
#   MINTER_STATE_DIR                where the minted key/chain are written (a volume)
#   DELEGATE_SCOPES                 scopes requested in the delegate cert
set -euo pipefail

CA_URL="${CA_URL:?CA_URL (Tower 1 base URL) is required}"
PORT="${SOVD_MINTER_PORT:-9200}"
OPERATOR_TOKEN="${SOVD_MINTER_OPERATOR_TOKEN:?SOVD_MINTER_OPERATOR_TOKEN is required}"
KID="${SOVD_MINTER_KID:-workshop-minter-1}"
ISSUER="${SOVD_MINTER_ISSUER:-workshop-ca}"
STATE="${MINTER_STATE_DIR:-/state}"
SCOPES="${DELEGATE_SCOPES:-reset:execute update:transfer update:execute update:verdict}"

mkdir -p "$STATE"

# --- 1. wait for Tower 1 -----------------------------------------------------
echo "[minter] waiting for Tower 1 at $CA_URL ..."
for _ in $(seq 1 120); do
    if curl -sf -o /dev/null "$CA_URL/healthz" 2>/dev/null; then break; fi
    sleep 1
done
curl -sf -o /dev/null "$CA_URL/healthz" 2>/dev/null || {
    echo "[minter] ERROR: Tower 1 ($CA_URL) never came healthy." >&2
    exit 1
}

# --- 2. mint the delegate cert from sumo-ca ----------------------------------
echo "[minter] requesting a delegate cert from sumo-ca (scopes: $SCOPES) ..."
resp="$(curl -sf -X POST "$CA_URL/admin/workshop/delegate-cert" \
    -H 'content-type: application/json' \
    -d "{\"scopes\":\"$SCOPES\",\"cn\":\"workshop-minter\"}")" || {
    echo "[minter] ERROR: sumo-ca delegate-cert endpoint failed — is Tower 1 healthy?" >&2
    exit 1
}

# --- 3. write key + build the leaf-first x5c chain ---------------------------
# `jq -j` (not -r): -r appends its own newline atop the PEM's trailing one,
# leaving a blank line the strict PKCS#8 parser rejects. -j writes verbatim.
printf '%s' "$resp" | jq -je '.key_pem'     > "$STATE/minter.key"
printf '%s' "$resp" | jq -je '.cert_pem'    > "$STATE/minter-leaf.pem"
printf '%s' "$resp" | jq -je '.ca_root_pem' > "$STATE/sumo-ca-root.pem"
cat "$STATE/minter-leaf.pem" "$STATE/sumo-ca-root.pem" > "$STATE/minter-chain.pem"
echo "[minter] delegate cert minted; key + x5c chain written to $STATE"

# --- 4. exec the minter ------------------------------------------------------
echo "[minter] starting sovd-token-helper on :$PORT (issuer=$ISSUER kid=$KID) ..."
exec sovd-token-helper \
    --port "$PORT" --bind-all \
    --signing-key "$STATE/minter.key" \
    --cert-chain "$STATE/minter-chain.pem" \
    --operator-token "$OPERATOR_TOKEN" \
    --kid "$KID" --issuer "$ISSUER" \
    --ca-url "$CA_URL"
