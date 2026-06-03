# sovd-token-helper

Offboard **workshop JWT minter** for SOVD. Issues short-lived bearer tokens that a
SOVD server (SOVDd) validates to authorize client access — the JWT analog of
`SOVD-security-helper`, but a *distinct authority* (client→SOVD access tokens, not
UDS unlock). The device never mints tokens: this service holds the signing key and
publishes its public key as a JWKS that SOVDd trusts (pinned for the offline /
workshop case, fetched when connected).

See `tasks/sovdd-token-minter.md` (design) and `tasks/sovdd-auth-slice.md` (the
SOVDd validator side) in the sumo-workspace.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/mint` | Operator-authenticated. Body `{ device_id, components[], ttl_secs?, subject? }` → `{ token, expires_at }`. |
| `GET`  | `/jwks` | Public verification key(s) (JWKS). |
| `GET`  | `/info` | Issuer, kid, algorithm, TTL policy. |
| `GET`  | `/health` | Liveness. |

The minted JWT is **ES256**, `aud = device_id` (the replay guard — a token for one
vehicle is rejected by another), with `scope = "component:<id> …"` matching SOVDd's
per-component grammar (`component:*` for all).

## Run

```bash
# Generate a throwaway workshop PKI (CA → regional intermediate → workshop leaf):
scripts/gen-workshop-pki.sh ./workshop-pki

sovd-token-helper \
  --signing-key ./workshop-pki/leaf.key \
  --cert-chain  ./workshop-pki/chain.pem \
  --issuer https://workshop.example/minter \
  --operator-token "$SOVD_MINTER_OPERATOR_TOKEN"

# Mint a token (presented to SOVDd as the bearer):
curl -s -X POST http://127.0.0.1:9200/mint \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SOVD_MINTER_OPERATOR_TOKEN" \
  -d '{"device_id":"vin:1HGBH41JXMN109186","components":["engine_ecu"],"ttl_secs":600}'
```

## Trusting it from SOVDd

The vehicle pins the **OEM Workshop CA** (`workshop-pki/ca.crt`) — *not* this
minter's key. The minter signs with a leaf cert that chains to that CA and ships
the chain in the JWT `x5c` header, so SOVDd validates entirely offline (no contact
with the minter or CA):

```toml
[server.auth]
mode = "workshop-ca"
ca_cert = "/path/to/ca.crt"          # the pinned OEM Workshop CA (via SUIT keystore)
device_id = "vin:1HGBH41JXMN109186"  # the expected token aud (this device)
```

(`/jwks` is retained for the connected path, but offline validation uses `x5c`.)

## Trust model & limitations (slice 1)

A token is accepted by the vehicle iff its `x5c` chain validates to the pinned
OEM Workshop CA, the leaf cert is in-validity, the JWS is signed by the leaf key,
and `aud` == the vehicle's device id. So, **today**:

- **A CA-signed workshop leaf can mint a token for *any* vehicle and *any*
  component scope.** The CA signature is an *unconstrained* delegation — it
  attests "trusted workshop," not "may only touch X." (`aud` binds a token to
  one device — it prevents replay of *that* token onto another vehicle, but does
  **not** limit which vehicles a workshop may target, since the minter sets `aud`.)
- **No revocation / OCSP.** The vehicle validates fully offline, so a compromised
  leaf key is usable until the leaf cert **expires**.

Mitigations: keep **leaf cert TTLs short** (bounds the compromise window), rotate
by re-issuing from the CA, and (future) push a CRL/blocklist over OTA.

**Slice 2 — fleet-constrained delegation** is the real blast-radius control: a
`fleet_id` provisioned in the device HSM + an `authorized_fleets` extension in the
workshop's cert, so e.g. a military workshop's cert only validates on military
vehicles.

> Reference implementation. Operator authentication is a static bearer token here;
> a real deployment plugs in badge / smartcard / SSO. Bind is loopback by default
> (`--bind-all` for a dealer-LAN bay service, behind TLS).
