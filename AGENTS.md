# sovd-token-helper Index

Rust workshop JWT minter for SOVD authorization tokens, distinct from UDS seed/key security helpers.

## Where to look

- `README.md` — endpoints, trust model, run example, limitations.
- `Cargo.toml` — package and dependency set.
- `src/main.rs` — CLI flags, HTTP handlers, token minting and JWKS logic.
- `scripts/gen-workshop-pki.sh` — throwaway workshop CA/leaf generation.
- `rust-toolchain.toml` — pinned Rust toolchain.

## Essential commands

No component-local `mise` file is present; use Cargo and scripts from this submodule root.

```bash
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
scripts/gen-workshop-pki.sh ./workshop-pki
cargo run -- --help
```

Finding commands:

```bash
rg --files -g 'Cargo.toml' -g 'README*' -g 'scripts/**' -g 'rust-toolchain.toml'
rg -n "mint|jwks|x5c|operator-token|workshop|aud|scope|revocation|fleet" README.md src scripts
```

## Stack

- Rust binary using JWT/JWKS, ES256 keys, axum/tokio style service code.
- Shell helper for local workshop PKI generation.

## Guardrails

- This mints client-to-SOVD bearer tokens; it does not derive UDS unlock keys.
- Keep `aud = device_id` and component scope semantics aligned with SOVDd auth validation.
- Treat generated workshop PKI as disposable local test material; do not commit generated keys/certs.

## Gotchas

- Slice 1 has unconstrained workshop delegation and no revocation/OCSP; README calls this out intentionally.
- Offline validation uses JWT `x5c`, while `/jwks` is retained for connected paths.

## Missing docs/specs to watch

- Design references live in workspace task docs, not inside this submodule.
- Fleet-constrained delegation is future work, not implemented behavior.
