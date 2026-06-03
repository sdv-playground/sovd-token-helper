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
# Generate a signing key (PKCS#8 P-256):
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out workshop.pem

sovd-token-helper \
  --signing-key workshop.pem \
  --issuer https://workshop.example/minter \
  --operator-token "$SOVD_MINTER_OPERATOR_TOKEN"

# Mint a token:
curl -s -X POST http://127.0.0.1:9200/mint \
  -H "Authorization: Bearer $SOVD_MINTER_OPERATOR_TOKEN" \
  -d '{"device_id":"vin:1HGBH41JXMN109186","components":["engine_ecu"],"ttl_secs":600}'
```

## Trusting it from SOVDd

Point SOVDd's trusted-issuer set at this minter — `iss` = `--issuer`, `aud` = the
device id. Offline, install this minter's `/jwks` output on the device (via the
SUIT keystore channel) and configure SOVDd's static-JWKS issuer source. Connected,
SOVDd can fetch the JWKS directly.

> Reference implementation. Operator authentication is a static bearer token here;
> a real deployment plugs in badge / smartcard / SSO. Bind is loopback by default
> (`--bind-all` for a dealer-LAN bay service, behind TLS).
