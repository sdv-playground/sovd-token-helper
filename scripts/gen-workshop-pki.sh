#!/usr/bin/env bash
# gen-workshop-pki.sh — generate a THROWAWAY dev/test workshop PKI for SOVD.
#
# Produces a 3-level ECDSA P-256 chain mirroring the real delegation model:
#
#   OEM Workshop CA (root)            ← the device's pinned trust anchor
#     └─ Regional Sub-CA (intermediate)
#          └─ Workshop leaf           ← the minter signs JWTs with this
#
# plus a self-signed "rogue" key/cert that does NOT chain to the CA (for the
# negative test — SOVDd must reject tokens it signs).
#
# Usage:
#   scripts/gen-workshop-pki.sh [OUTPUT_DIR]      # default ./workshop-pki
#
# Then:
#   sovd-token-helper --signing-key <OUT>/leaf.key --cert-chain <OUT>/chain.pem ...
#   # and SOVDd pins <OUT>/ca.crt as the trusted workshop-CA anchor.
#
# NOT FOR PRODUCTION — throwaway keys, generated locally.
set -euo pipefail

OUT="${1:-./workshop-pki}"
CURVE="P-256"
DAYS_CA=3650
DAYS_INT=1825
DAYS_LEAF=365

command -v openssl >/dev/null 2>&1 || { echo "error: openssl not found on PATH" >&2; exit 1; }
mkdir -p "$OUT"

gen_key() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$CURVE" -out "$1"; }

echo "Generating throwaway workshop PKI in: $OUT"

# --- Root: OEM Workshop CA (the device's pinned anchor) ---------------------
gen_key "$OUT/ca.key"
openssl req -x509 -new -key "$OUT/ca.key" -subj "/CN=OEM-Workshop-CA" -days "$DAYS_CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT/ca.crt"

# --- Intermediate: regional sub-CA ------------------------------------------
gen_key "$OUT/int.key"
openssl req -new -key "$OUT/int.key" -subj "/CN=Region-EU-SubCA" -out "$OUT/int.csr"
openssl x509 -req -in "$OUT/int.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days "$DAYS_INT" \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n") \
  -out "$OUT/int.crt"

# --- Leaf: workshop bay (the minter's signing cert) -------------------------
gen_key "$OUT/leaf.key"
openssl req -new -key "$OUT/leaf.key" -subj "/CN=Workshop-Bay-7" -out "$OUT/leaf.csr"
openssl x509 -req -in "$OUT/leaf.csr" -CA "$OUT/int.crt" -CAkey "$OUT/int.key" -CAcreateserial \
  -days "$DAYS_LEAF" \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n") \
  -out "$OUT/leaf.crt"

# x5c chain the minter embeds in the JWT header: leaf first, then intermediate.
cat "$OUT/leaf.crt" "$OUT/int.crt" > "$OUT/chain.pem"

# --- Rogue: self-signed, does NOT chain to the CA (negative test) -----------
gen_key "$OUT/rogue.key"
openssl req -x509 -new -key "$OUT/rogue.key" -subj "/CN=Rogue-Minter" -days "$DAYS_LEAF" \
  -addext "basicConstraints=critical,CA:FALSE" -out "$OUT/rogue.crt"

rm -f "$OUT"/*.csr "$OUT"/*.srl

# --- Verify the recipe (fail loudly if wrong) -------------------------------
openssl verify -CAfile "$OUT/ca.crt" -untrusted "$OUT/int.crt" "$OUT/leaf.crt" >/dev/null
if openssl verify -CAfile "$OUT/ca.crt" "$OUT/rogue.crt" >/dev/null 2>&1; then
  echo "error: rogue cert unexpectedly verified against the CA" >&2
  exit 1
fi

cat <<EOF

OK — workshop PKI ready (P-256, 3-level chain verified):
  CA anchor (pin in SOVDd) : $OUT/ca.crt
  minter --signing-key     : $OUT/leaf.key
  minter --cert-chain      : $OUT/chain.pem   (leaf + intermediate → x5c)
  rogue (negative test)    : $OUT/rogue.key + $OUT/rogue.crt
EOF
