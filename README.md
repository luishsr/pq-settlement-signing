# pq-settlement-signing

Hybrid **Ed25519 + ML-DSA-65** signatures for settlement instructions, with a verifier policy for migrating a ledger from classical to post-quantum signatures. It accompanies the article in [`article.md`](article.md).

> **Educational code. Not audited.** Private keys are written to disk as unencrypted PKCS#8, so use it for demos only; real keys belong in an HSM or KMS. The signed-message construction is inspired by RFC 10073 (composite ML-DSA) but is **not** an implementation of it.

## Run

```bash
cargo test                              # 32 tests: unit, CLI exit codes, cross-implementation (aws-lc-rs <-> RustCrypto), signature properties
./demo.sh                               # two banks: sign in each mode, verify under each phase, five attacks (needs jq)
cargo run --release -- bench            # latency (p50/mean/p99), sizes and multi-core throughput: Ed25519, ML-DSA-44/65/87, hybrid
cargo run --release --example compare   # ML-DSA-65 speed: aws-lc-rs vs RustCrypto (cached and per-call keys)
```

On CPUs with mixed core types, pin the latency runs to one fast core (Linux: `taskset -c 2 ...`); an efficient core can be twice as slow. `demo.sh` fails if any verdict or exit code differs from the policy table.

## CLI

```text
pq-settle keygen --id <party> --out-dir <dir>
pq-settle sign   --key <party.key.json> --in <instruction.json> --out <signed.json>
                 (--mode classical|hybrid|post-quantum | --phase <phase>)
pq-settle verify --pub <party.pub.json> --in <signed.json> --phase <phase>
pq-settle bench  [--iterations <n>]
```

`verify` exits with 0 if the signature is accepted, 1 if it is rejected, and 2 on a usage or I/O error. An example instruction is in `examples/instruction.json`.

## Layout

| File | What it does |
|---|---|
| `src/instruction.rs` | The settlement instruction, its validation, and the canonical length-prefixed encoding that gets signed |
| `src/hybrid.rs` | Modes, the signed message `M'`, signing, verification (AND, never OR), and key files |
| `src/policy.rs` | Migration phases and `verify_in_phase` |
| `src/main.rs` | The CLI and the benchmark |
| `tests/interop.rs` | ML-DSA-65 signatures cross-checked in both directions between aws-lc-rs and RustCrypto |
| `tests/signature_properties.rs` | Ed25519 malleation (S + L) is rejected; re-signing changes only the ML-DSA half |
| `tests/cli.rs` | Exit codes: 0 accepted, 1 rejected, 2 our own usage or I/O error |
| `examples/compare.rs` | ML-DSA-65 timings, aws-lc-rs vs RustCrypto (uses the dev-dependency, so it stays out of the binary) |

## Migration phases

| Phase | Classical | Hybrid | Post-quantum | Signers produce |
|---|:-:|:-:|:-:|---|
| `accept-classical` | ✓ | | | classical |
| `prefer-hybrid` | ✓ | ✓ | | hybrid |
| `hybrid-required` | | ✓ | | hybrid |
| `post-quantum-ready` | | ✓ | ✓ | post-quantum |
