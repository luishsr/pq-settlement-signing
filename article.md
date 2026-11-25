# Quantum-Safe Settlement Signatures in Rust: Hybrid Ed25519 + ML-DSA for Tokenised Finance

*How ML-DSA works, what a hybrid signature does and doesn't guarantee, what it costs on real hardware, and how to migrate a settlement network to it, with a working Rust implementation.*

---

In October 2026, NIST published the final version of IR 8547, its plan for leaving quantum-vulnerable cryptography behind. Table 2 is blunt: ECDSA, EdDSA and RSA signatures are **deprecated after 2030 and disallowed after 2035**, at every approved strength. The EU's coordinated roadmap points the same way: Member States start in 2025 and complete the "First Steps" by the end of 2026; high-risk use cases are done by the end of 2030, and as many systems as practically feasible by 2035. In November 2026 the IETF published RFC 10073, which standardises composite ML-DSA signatures for X.509. And the Ledger API of Canton 3.7, a ledger built for regulated finance, already defines `SIGNING_ALGORITHM_SPEC_ML_DSA_65` next to Ed25519 and ECDSA.

Tokenised finance runs on signatures. A delivery-versus-payment instruction, a custody transfer and a settlement confirmation are each a signed statement that one institution agreed to move value to another. So I built a small, complete example of what migrating those signatures looks like:

- a Rust library and CLI that signs settlement instructions with **Ed25519 and ML-DSA-65 together**;
- a **verifier policy** that moves a network from classical to post-quantum in deliberate phases;
- **benchmarks** of latency, tail latency, throughput and sizes on a laptop.

The code is about 2,000 lines of Rust, including the tests, the CLI and the benchmarks. This article goes further than the code:
- how ML-DSA works, and why that explains its numbers;
- what the hybrid construction provably guarantees, and where it falls short;
- a trap specific to ledgers;
- how long-lived records should be protected;
- what a migration looks like in operations.

## What a quantum computer actually breaks

Ed25519's security rests on the elliptic-curve discrete-logarithm problem. Shor's algorithm solves that problem efficiently on a large, fault-tolerant quantum computer, which means **the private key can be computed from the public key**. On a permissioned settlement network, every party's public key is known to every counterparty by design, because that is how they verify each other.

Nobody knows when such a machine will exist. Published resource estimates give a sense of scale:
- Roetteler, Naehrig, Svore and Lauter (2017) showed that discrete logarithms on a curve over an *n*-bit prime field need at most 9*n* + 2⌈log₂ *n*⌉ + 10 logical qubits. That is about 2,330 for a 256-bit field (2,321 for Curve25519's 255 bits), and they concluded that elliptic curves are "an easier target than RSA".
- In 2025, Gidney estimated that RSA-2048 could be factored with fewer than a million noisy qubits, down from 20 million in his 2019 estimate with Ekerå, at the cost of a longer run: under a week rather than eight hours. That estimate is for RSA; the elliptic-curve figure above is older.

The policy dates above were set without anyone needing to know the year.

The usual argument for urgency is "harvest now, decrypt later": record encrypted traffic today, decrypt it once the machine exists. That argument is about *confidentiality*. Signatures are different: a quantum computer that arrives in 2035 can't retroactively forge a signature you verified in 2027.

Signatures have two problems of their own.

**Lead time.** A settlement network isn't one system. It's dozens of institutions, each with its own HSMs, key ceremonies, message formats, size limits and change windows. Among the EU roadmap's rough examples of a high-risk use case is one whose transition would take more than eight years, with a high-impact attack. I'd argue that describes most interbank settlement infrastructure, and by that arithmetic, anyone starting in 2026 is already late for 2030. The roadmap is explicit about that date: for high-risk use cases, quantum-vulnerable public-key mechanisms "shall not be used stand-alone after the end of 2030".

**Evidence that has to last.** A signed instruction is evidence in reconciliation, in disputes and in audits, sometimes a decade later. Once Ed25519 can be forged, an Ed25519 signature on its own no longer proves who agreed to what. Records that must stay verifiable need protecting before that day, a problem with its own section below.

## Inside ML-DSA

ML-DSA, standardised as FIPS 204 in August 2024, is the lattice-based scheme formerly called CRYSTALS-Dilithium. You don't need its internals to use it. You do need them to understand its sizes, its timings and its failure modes.

**The hard problems.** Work with polynomials of 256 coefficients modulo the prime *q* = 8,380,417. A public matrix **A** of such polynomials (6 × 5 for ML-DSA-65) is expanded from a 32-byte seed. The private key is a pair of vectors **s₁**, **s₂** with tiny coefficients. The public key is **t** = **A·s₁** + **s₂**.

Recovering **s₁** from **A** and **t** is the Module Learning With Errors problem. Without the small "error" **s₂** it would be ordinary linear algebra; with it, no efficient algorithm is known, classical or quantum. That protects the key. Forging a signature without the key is a different problem: FIPS 204 bases ML-DSA's security on MLWE *and* a variant of the Module Short Integer Solution problem (SelfTargetMSIS), which roughly asks for short vectors that satisfy the verification equation.

**Signing is a proof of knowledge, made non-interactive.** The structure is the same as a Schnorr signature:

1. **Commit.** Pick a random vector **y** with medium-sized coefficients (up to 2¹⁹ in ML-DSA-65) and compute **w** = **A·y**. Keep only its high-order bits, **w₁**.
2. **Challenge.** Hash the message representative with **w₁** to get a sparse polynomial *c*: exactly 49 coefficients are ±1, and the rest are zero.
3. **Respond.** Send **z** = **y** + *c*·**s₁**. The verifier checks two things: that every coefficient of **z** is small (below γ₁ − β), and that the high bits of **A·z** − *c*·**t**, which equal **w₁** if the signer knew **s₁**, hash back to the challenge. The size check is essential. Without it, anyone could solve for a suitable **z** with ordinary linear algebra.

There's a catch. **z** is **y** shifted by a multiple of the secret, so its distribution leans towards **s₁**. Publish enough of them and you leak the key.

ML-DSA's answer is **rejection sampling**, the "with aborts" in *Fiat–Shamir with Aborts*: if **z**, or a second check on the low-order bits, falls outside a safe range, the signer throws the attempt away and starts again with a fresh **y**. The signatures that survive are distributed independently of the secret. FIPS 204 lists the expected number of attempts:

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---:|---:|---:|
| Matrix **A** (*k* × *ℓ*) | 4 × 4 | 6 × 5 | 8 × 7 |
| Expected signing attempts | 4.25 | 5.1 | 3.85 |
| NIST security category | 2 | 3 | 5 |
| Public key / signature (bytes) | 1,312 / 2,420 | 1,952 / 3,309 | 2,592 / 4,627 |
| Private key, expanded / seed (bytes) | 2,560 / 32 | 4,032 / 32 | 4,896 / 32 |

That loop is why ML-DSA signing time varies from one signature to the next, which shows up in the measurements below.

**Why the signature is 3,309 bytes.** It holds three things:
- a 48-byte hash that fixes the challenge;
- the response **z**: five polynomials of 256 coefficients, each coefficient encoded in 20 bits, for 3,200 bytes;
- 61 bytes of "hints" that let the verifier rebuild **w₁** from a compressed public key.

So 97% of the signature is **z**. A lattice signature is big because it has to carry a vector of a thousand-odd medium-sized numbers. An elliptic-curve signature carries two.

**The key is bound in.** ML-DSA doesn't sign your message directly. It signs μ = H(H(public key) ‖ message). FIPS 204 does this to get what the literature calls "beyond unforgeability" properties: each signature is tied to one public key, so an attacker can't construct a second key under which your existing signature also verifies.

**Hedged, not deterministic.** By default, FIPS 204 mixes fresh randomness into each signature as well as a secret derived from the key. The standard is explicit about why: the fresh randomness exists "to facilitate countermeasures to side-channel attacks and fault attacks on deterministic signatures." A deterministic variant is allowed, but it "should not be used on platforms where side-channel attacks are a concern and where they cannot be otherwise mitigated". One consequence matters for ledgers: signing the same message twice gives two different, equally valid signatures.

**Pure, pre-hash and application-level hashing.** FIPS 204 offers "pure" ML-DSA, which it calls preferred, and a pre-hash variant, HashML-DSA. It also allows what this crate does: hash at the application level, then sign the digest with pure ML-DSA. The condition is that the digest's hash provides at least λ bits of collision resistance, which means a digest at least 2λ bits long. For ML-DSA-65, λ is 192, so the digest needs at least 384 bits. SHA-256 is still permitted, but its 256-bit digest caps collision resistance at 128 bits: **a SHA-256 digest quietly lowers ML-DSA-65 below its 192-bit target.** This crate uses SHA-512. It's an easy mistake to make when bolting ML-DSA onto a SHA-256-everywhere stack.

## Why hybrid, not just ML-DSA

ML-DSA is young as a standard, and its implementations are younger still. The post-quantum competition has already produced two well-known surprises:
- In 2022, Ward Beullens recovered private keys for Rainbow's lowest security level in about 53 hours on a laptop. Rainbow was a signature finalist.
- That same year, Castryck and Decru broke SIDH, the basis of the fourth-round candidate SIKE, with an efficient classical key-recovery attack.

Neither attack touches lattices. But both are good reasons not to bet a settlement network on one young assumption.

A hybrid signature carries both: Ed25519, an elliptic-curve scheme with decades of cryptanalysis and hardened implementations behind it, and ML-DSA-65 for quantum resistance. The hedge runs in both directions:
- if ML-DSA suffers a cryptanalytic surprise or an implementation bug, Ed25519 still holds;
- once quantum computers arrive, ML-DSA still holds.

The EU roadmap recommends "standardised and tested hybrid solutions, whenever feasible and suitable". NIST is more reserved: it accepts hybrids but notes that they "add complexity" and are "typically expected to be temporary measures that lead to a second transition" to post-quantum-only signatures. Both views are reflected in the migration phases below.

## The design: four rules

The library rests on four rules. Each one exists because of a specific attack.

```text
SettlementInstruction ──canonical_bytes()──▶ "SI/1" ‖ (tag ‖ len ‖ value)×9        135 bytes
                                                   │ SHA-512
                                                   ▼
M' = "PQSETTLE/v1/" ‖ "ed25519+ml-dsa-65" ‖ 0x00 ‖ hash                         94 bytes
           │                                   │
     Ed25519.Sign(M')                   ML-DSA-65.Sign(M')
           ▼                                   ▼
     64-byte signature                 3,309-byte signature
                         ╲               ╱
              envelope { mode, signer, ed25519, ml_dsa_65 }
```

### 1. Sign bytes, never JSON

JSON is fine for files and transport. It's a poor thing to sign, because whitespace, key order and number formatting all change the bytes without changing the meaning. The instruction is therefore encoded canonically: a version tag, then every field in a fixed order as `tag ‖ u32 length ‖ value`.

The length prefix matters more than it looks, and a test I thought was sufficient taught me that (see *Testing the tests* below). The parser also refuses unknown fields. Otherwise an attacker could add `"memo": "pay to another account"`: the signature still verifies, and a downstream system that reads the memo acts on unsigned data.

### 2. Bind the mode into what's signed

Every component signs the same message representative:

```rust
pub fn message_to_sign(mode: Mode, instruction: &SettlementInstruction) -> Vec<u8> {
    let hash = digest(&SHA512, &instruction.canonical_bytes());
    let mut m = Vec::with_capacity(DOMAIN.len() + mode.label().len() + 1 + hash.as_ref().len());
    m.extend_from_slice(DOMAIN.as_bytes());       // "PQSETTLE/v1/"
    m.extend_from_slice(mode.label().as_bytes()); // "ed25519" | "ed25519+ml-dsa-65" | "ml-dsa-65"
    m.push(0x00);
    m.extend_from_slice(hash.as_ref());
    m
}
```

Without the label, a hybrid signature contains a perfectly good Ed25519 signature. An attacker could strip off the ML-DSA half and present what's left as a classical signature to any verifier that still accepts classical, which during a migration is most of them. With the label inside `M'`, the Ed25519 half was made over `"ed25519+ml-dsa-65"`, so it can't pass as a signature over `"ed25519"`.

### 3. AND, never OR

```rust
let m = message_to_sign(mode, &signed.instruction);
if let Some(s) = &sig.ed25519 {
    UnparsedPublicKey::new(&ED25519, &signer.ed25519)
        .verify(&m, s)
        .map_err(|_| Error::BadSignature("Ed25519"))?;
}
if let Some(s) = &sig.ml_dsa_65 {
    UnparsedPublicKey::new(&ML_DSA_65, &signer.ml_dsa_65)
        .verify(&m, s)
        .map_err(|_| Error::BadSignature("ML-DSA-65"))?;
}
Ok(mode)
```

Each `?` returns on failure. The `if let` lines skip a component that isn't there, so the AND rule also depends on the shape check that runs before them, which refuses a hybrid envelope with either half missing. Together, they leave no path where one valid half is enough. (That shape check is one line, and for a while it was the least-tested line in the crate; see *Testing the tests*.) NIST IR 8547 describes hybrid signatures the same way: "verification of the dual signature requires all of the component signatures to be successfully verified."

Before this code runs, `verify` checks three things:
- the signer's id matches the keys;
- the instruction passes validation;
- the components present match the mode *exactly*.

A "classical" envelope that also carries an ML-DSA signature is malformed, not "classical plus a bonus".

### 4. The verifier's phase decides, before any cryptography

```rust
pub fn accepts(self, mode: Mode) -> bool {
    match self {
        Phase::AcceptClassical  => mode == Mode::Classical,
        Phase::PreferHybrid     => matches!(mode, Mode::Classical | Mode::Hybrid),
        Phase::HybridRequired   => mode == Mode::Hybrid,
        Phase::PostQuantumReady => matches!(mode, Mode::Hybrid | Mode::PostQuantum),
    }
}
```

A migration is a sequence of configuration changes, never an automatic fallback. "Try hybrid, and accept classical if that fails" is a downgrade attack written as a feature. The phase is checked first, so a cryptographically perfect classical signature is still refused once the network requires hybrid.

### How this compares with RFC 10073

RFC 10073 solves the same problem for X.509, and this construction is *inspired by* it, not an implementation of it:

| | RFC 10073 (`id-MLDSA65-Ed25519-SHA512`) | This crate |
|---|---|---|
| Message representative | `Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M)` | `"PQSETTLE/v1/" ‖ label ‖ 0x00 ‖ SHA-512(canonical M)` |
| ML-DSA context string | the label | empty |
| Keys | fresh composite keys, reuse forbidden | each component key reused across modes |
| Encoding | X.509 / ASN.1 | JSON envelope with hex |
| Public key / signature | 1,984 / 3,373 bytes | 1,984 / 3,373 bytes |

The sizes match exactly because both just place the two components side by side. If you need interoperability, use the RFC. The key-reuse row is a real difference, and I come back to it in the next section.

## What the hybrid guarantees, and what it doesn't

"Secure if either algorithm is secure" is the slogan. RFC 10073's security considerations are more careful. Most of them carry over to this construction; the exception is their assumption that keys are never reused, which I deal with below.

**Unforgeability holds if either component holds.** A forger who produces a valid hybrid signature on a new instruction has produced a valid Ed25519 signature *and* a valid ML-DSA signature on a new `M'`, unless they found a SHA-512 collision. Breaking one algorithm isn't enough. That is the EUF-CMA guarantee, and it is what the AND rule buys.

**Strong unforgeability doesn't survive a quantum attacker.** SUF-CMA means an attacker can't produce even a *second* valid signature on an instruction that was already signed. ML-DSA is designed to have it, and aws-lc-rs refuses the classic Ed25519 malleation that would break it classically: a test in the crate adds the group order L to S and checks that the result is rejected. But a quantum attacker who can forge Ed25519 can replace the Ed25519 half of an existing hybrid signature, producing a new valid signature on the same instruction. RFC 10073 is blunt about it: none of its composites "are SUF-CMA secure against a quantum adversary", so "replacing an ML-DSA signature with a Composite ML-DSA signature is a reduction in security", and applications that depend on SUF-CMA "SHOULD NOT" use them.

**Signatures aren't unique anyway.** This is a separate point, about honest signers rather than attackers. Hedged ML-DSA means that each time Bank A signs the same instruction, the result is a different valid signature. A test in the crate shows it: the Ed25519 halves are identical (Ed25519 is deterministic), the ML-DSA halves differ, and both envelopes verify.

Both points lead to the same rule for a ledger: **never use signature bytes as an identifier**, whether as a de-duplication key, a transaction id or an idempotency key. Identify an instruction by its canonical hash.

**Stripping is stopped inside the protocol.** RFC 10073 calls the property "non-separability". In this crate, every signature these keys produce is over an `M'` that starts with the domain and names the mode, so no component of a hybrid signature can verify in any other mode. The demo below shows the attack failing.

What stripping would gain is worth spelling out, because no content is forged: the instruction is one Bank A really signed. The gain is a *downgrade of the evidence*. A stripped copy carries only the Ed25519 half, which Bank A could disown once Ed25519 is breakable, and it slips past any monitoring of how much traffic is hybrid. (RFC 10073 also passes its label to ML-DSA as the context string, which gives its ML-DSA half a limited form of protection even outside the protocol. This crate leaves the context empty, so it relies on `M'` alone.)

**Where I depart from the RFC: key reuse.** RFC 10073 §9.3 says that key reuse between composite and single-algorithm use "MUST be avoided", because a component key that also signs on its own opens stripping and cross-protocol attacks. This crate deliberately reuses each party's Ed25519 key for classical and hybrid signatures, and its ML-DSA key for hybrid and post-quantum ones. It's a demo convenience: one key pair per party, and a stripping demo that shows the label doing its job.

The condition that makes reuse safe is precise: **every message the key ever signs, in any system, must be distinguishable from `M'` by its first bytes.** Every signature this code makes starts with `PQSETTLE/v1/` and a label, so within the protocol the condition holds. It fails the moment the same key signs anything else, and the obvious ways that happens are exactly the tempting ones:
- reusing the Ed25519 key a bank *already* has, which has been signing legacy formats for years (the RFC's own example of what not to do);
- using the same keys for other duties, such as the key-registration statement recommended below, unless that statement carries its own distinct prefix.

Code can't enforce that condition; only key policy can, typically in the HSM. The RFC adds that context-style mitigations mean the risk "can be somewhat mitigated, but not eliminated", and need per-application analysis. So in production I would follow the RFC. You are distributing new key material in the migration anyway, so make it a fresh Ed25519 + ML-DSA pair used only for hybrid settlement signatures, and leave the old classical key to the classical phase.

## Every node must agree on what "valid" means

There's a property signature standards rarely state, and ledgers depend on: **every verifier must reach the same verdict on every signature**, including malformed and adversarial ones. If some nodes accept a signature that others reject, you have a fork, or a settlement one party considers final and the other considers void.

Ed25519 is the cautionary tale. Henry de Valence's 2020 survey found that validation results were "generally inconsistent not just between implementations, but also between different versions and different modes". He spelled out the consequence: a malicious participant can submit signatures that some implementations accept and others reject, splitting the network or forking consensus. The edge cases are about:
- cofactors;
- non-canonical point encodings;
- small-order keys.

The same year, Chalkias, Garillot and Nikolaenko published edge-case test vectors and found that most libraries did not follow the latest recommendations. The crate tests one of those edge cases, S ≥ L, which aws-lc-rs rejects. The adversarial review behind this article found another that it accepts: a *small-order* Ed25519 public key, such as the identity point, under which a trivial signature verifies for every message. Public keys come from registration, not from attackers, but a party that registers such a key could later disown its classical signatures. Validate every public key when it is registered: the right length and, for Ed25519, not of small order. The crate now does this before every verification, against the standard list of small-order encodings.

ML-DSA starts from a better place, but not a perfect one. FIPS 204 specifies verification precisely, down to saying that an implementation which can accept a signature or public key of any other length "shall return false" for it. Its own history shows why that precision matters: the *draft* standard's pseudocode "unintentionally omitted a check for malformed input while unpacking the hint", which left the scheme "not strongly existentially unforgeable". The final standard restored the check.

The hybrid, however, inherits both algorithms' edge cases. The interop test proves two implementations accept each other's *valid* signatures. It says nothing about whether they reject the same *invalid* ones.

For a settlement network, that means:
- pin one verification library and version across all nodes, or adopt precisely specified rules (Zcash's ZIP 215 did this for Ed25519);
- run negative test vectors, not just positive ones, in every implementation you deploy, including NIST's ACVP vectors for ML-DSA.

## Watching it work

`demo.sh` runs two banks through the whole flow. Bank A signs one instruction in each mode, and Bank B verifies each under each phase. This is real output:

```text
               accept-classical    prefer-hybrid       hybrid-required     post-quantum-ready
classical      ACCEPTED            ACCEPTED            REJECTED            REJECTED
hybrid         REJECTED            ACCEPTED            ACCEPTED            ACCEPTED
post-quantum   REJECTED            REJECTED            REJECTED            ACCEPTED
```

Then the demo attacks Bank A's hybrid-signed instruction:

```text
-- Tamper: raise the nominal from 1,000,000 to 9,000,000
REJECTED  Ed25519 signature does not verify
-- Strip: drop the ML-DSA half and present the Ed25519 half as classical,
   to a verifier still in prefer-hybrid (classical accepted)
REJECTED  Ed25519 signature does not verify
-- Downgrade: relabel the envelope as classical, keeping both signatures
REJECTED  malformed signature: the components present don't match mode ed25519
-- Smuggle: add a field the signature doesn't cover
REJECTED  malformed signed instruction: unknown field `memo`, expected one of ...
-- Impersonate: Bank B signs a changed instruction with its own keys and claims to be Bank A
REJECTED  Ed25519 signature does not verify
```

The strip attack is the subtle one. It targets a verifier in `prefer-hybrid`, where classical signatures are legitimately accepted, so the policy can't help; the label inside `M'` is what stops it. With fresh keys per mode, as recommended above, key separation would stop it too.

## Two implementations must agree

If a signature only verifies with the library that made it, that proves little about conformance to FIPS 204. Cross-checking two libraries is evidence, not proof; proof of conformance is what NIST's ACVP known-answer tests are for. The crate signs with **aws-lc-rs**, the Rust bindings to AWS-LC, and its integration tests cross-check against RustCrypto's pure-Rust **`ml-dsa`** in both directions:
- an aws-lc-rs hybrid signature's ML-DSA half verifies under RustCrypto, and RustCrypto rejects it over a changed instruction;
- a RustCrypto signature, made deterministically from a fixed seed, verifies under aws-lc-rs and passes through the crate's own envelope verifier.

RustCrypto's crate is a dev-dependency only. Its README says plainly that it has never been independently audited, which is fine for a cross-check and not fine for production signing.

Implementations also differ a lot in speed. On the same machine, pinned to one performance core, signing distinct messages with ML-DSA-65:

| Implementation | Keygen from seed µs | Sign p50 µs | Sign p99 µs | Verify p50 µs |
|---|---:|---:|---:|---:|
| aws-lc-rs 1.19 (C, hedged) | 31.7 | 77.6 | 293.8 | 31.4 |
| RustCrypto `ml-dsa` 0.1, cached keys | 169.7 | 459.0 | 2,401.5 | 58.5 |
| RustCrypto `ml-dsa` 0.1, keys decoded per call | 169.7 | 558.1 | 2,466.4 | 134.1 |

The two libraries don't do the same work per call by default. RustCrypto's key objects cache the expanded matrix **A** and transformed key material, while aws-lc re-derives them on every sign and verify. The third row makes RustCrypto do the same work, and the gap widens: about seven times slower to sign and four times slower to verify. RustCrypto also signs deterministically here, while aws-lc-rs signs hedged. The lesson isn't that one is bad. It's that the cost of ML-DSA depends on the implementation, and on what it caches, as much as on the algorithm, so benchmark the one you will actually run, HSM included.

## Testing the tests

The suite has 32 tests: 25 unit tests, 2 interop tests, 2 signature-property tests and 3 CLI tests. They cover:
- round trips in every mode;
- every field tampered in every mode;
- stripping, relabelling, a hybrid with either half missing, and splicing two genuine signatures from different modes into one fake hybrid;
- wrong and impostor keys, and public keys of the wrong length or of small order;
- the full phase-by-mode matrix, and that the phase is checked before any cryptography;
- Ed25519 malleation and re-signing behaviour;
- the CLI's exit codes, which scripts branch on, and that hostile input is printed safely;
- every byte of the encoding and of `M'`, pinned against values computed independently in Python, so a refactor can't silently invalidate stored signatures.

Passing tests prove little if the tests are weak, so I mutation-tested the rules by hand. I broke each one in turn and checked that something failed:
- dropped the mode label, and separately its `0x00` terminator;
- hashed only half the instruction;
- turned AND into OR, in two places;
- removed the shape check, the signer check, validation on either side, the policy check, the length prefix, the control-character check and the unknown-field check.

All 13 mutants were caught, but not on the first try.

My first field-boundary test passed with the length prefixes removed. I had assumed per-field tags were enough to keep boundaries unambiguous. They aren't: a value can contain the next field's tag byte, so without lengths, `("A\x02B", "C")` and `("A", "B\x02C")` encode identically. The test now checks exactly that pair, and validation also refuses control characters as a second line of defence. A code review can easily miss that kind of bug; a deliberately broken build won't.

Then I had the code and this article reviewed adversarially, and the review found two tests weaker than I had claimed:
- My "pinned" encoding test checked only the first two fields, the last one and the total length. The deliverer, receiver and ISIN are all 12 bytes, so swapping deliverer and receiver in the encoder passed every test, and a signature on "A delivers to B" verified as "B delivers to A".
- No test sent a hybrid envelope with one half missing. Weakening the shape check to refuse only *extra* halves passed every test, and that mutant accepted an Ed25519-only "hybrid" in `hybrid-required`, the exact signature a quantum attacker could forge.

Both gaps are closed. The review also found smaller problems in the CLI, now fixed: an attacker-chosen JSON field name could carry a terminal escape sequence into the rejection message, some failures had the wrong exit code, and `sign` would overwrite any file, including a key file. The suite now catches 32 mutants, all of these among them.

## The numbers

The machine is an Intel Core Ultra 9 185H laptop on a balanced power profile, with 16 cores (6 performance, 8 efficient, 2 low-power) and 22 threads. It runs aws-lc-rs 1.19.0 and Rust 1.100. Each latency figure comes from 2,000 runs on one thread, pinned with `taskset` to one performance core. Pinning matters on this CPU: on an efficient core, ML-DSA-65 signing takes twice as long (a 160 µs median against 80 µs). The message is the 86-byte `M'` used in post-quantum mode. The hybrid row is the whole envelope: validation, canonical encoding, SHA-512 and both signatures.

Across three pinned runs, the ML-DSA medians moved by up to about 4%. Ed25519's few-microsecond figures and all the 99th percentiles are noisier. The tables show the third run.

**Latency, µs**

| Algorithm | Keygen p50 | Sign p50 | Sign mean | Sign p99 | Verify p50 | Verify p99 |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 | 6.7 | 5.9 | 6.2 | 9.2 | 24.3 | 26.4 |
| ML-DSA-44 | 20.6 | 52.4 | 65.9 | 210.7 | 18.8 | 25.9 |
| ML-DSA-65 | 34.7 | 80.0 | 96.0 | 315.6 | 31.8 | 38.7 |
| ML-DSA-87 | 53.5 | 105.1 | 123.3 | 371.2 | 50.0 | 54.6 |
| **Hybrid envelope** | 41.9 | 87.4 | 105.0 | 332.4 | 57.3 | 66.6 |

**Verification is not the problem.** ML-DSA-65 verifies about as fast as Ed25519, ML-DSA-44 is faster, and verification time varies far less than signing time, because there's no loop in it.

**Signing has a tail, with the shape the theory expects.** Ed25519 signing is deterministic and nearly flat: 9.2 µs at the 99th percentile against a 5.9 µs median, a spread that is ordinary system noise. ML-DSA-65's 99th percentile is four times its median, and its mean (96.0 µs) sits well above its median (80.0 µs).

That is the rejection loop. FIPS 204's own analysis treats each signing attempt as independent, which makes the number of attempts geometric with a mean of 5.1. On that model, the median signature needs 4 attempts and the 99th-percentile one needs 22. If each attempt costs the same, the two measured percentiles imply about 28 µs of fixed work plus 13 µs per attempt, and so a mean of about 94 µs. The measured mean is 96.0 µs. Two parameters can always be fitted to two points, so the fit itself proves nothing; what supports the model is that its prediction for a third quantity, the mean, lands within 2%.

The practical lesson: **plan signing capacity from the mean or from throughput, not from the median**, and set your signing service's timeouts with the tail in mind. The single-thread throughput below, 9,530 hybrid signatures a second, is what 1 ÷ the hybrid mean (105.0 µs) predicts.

**Throughput, hybrid envelope**

| Threads | Signatures/s | Verifications/s |
|---:|---:|---:|
| 1 | 9,530 | 17,292 |
| 4 | 34,985 | 63,289 |
| 8 | 53,259 | 100,959 |
| 16 | 82,488 | 147,972 |
| 22 | 81,482 | 151,723 |

Every thread runs for the same one-second window. An earlier version of the benchmark gave each thread a fixed number of operations instead, which left the fast cores idle while the slow ones finished, and understated throughput by roughly a fifth. Scaling is still sub-linear: 16 threads give about 8.7 times one thread, and the last six threads add almost nothing. Only 6 of the 16 cores are performance cores, and 12 of the 22 threads are those cores' hyperthread pairs. Even so, a single laptop verifies about 150,000 hybrid signatures a second. CPU is not what limits a settlement network.

**Sizes, bytes**

| Algorithm | Public key | Signature | Private key seed | Private key, expanded | Key file (PKCS#8) |
|---|---:|---:|---:|---:|---:|
| Ed25519 | 32 | 64 | 32 | 64 | 83 |
| ML-DSA-44 | 1,312 | 2,420 | 32 | 2,560 | 54 |
| ML-DSA-65 | 1,952 | 3,309 | 32 | 4,032 | 54 |
| ML-DSA-87 | 2,592 | 4,627 | 32 | 4,896 | 54 |
| **Hybrid envelope** | 1,984 | 3,373 | 64 | 4,096 | 137 |

**Bytes are the problem.** A hybrid signature is 53 times larger than an Ed25519 signature, and a public key 62 times larger. At one million instructions a day, signatures alone grow from 64 MB to 3.4 GB a day, or about 1.2 TB a year before replication.

Three things make it worse or better:
- **Encoding.** The demo's hex-in-JSON files are 523 bytes for a classical instruction and 7,159 bytes for a hybrid one. Store signatures as binary.
- **Certificates in every message.** A composite ML-DSA-65 certificate carries a 1,984-byte key and a 3,373-byte signature from its issuer, so it's over 5 KB before any other field, and a chain doubles that. Register keys once and reference them by id. Canton's Ledger API does exactly that: its `Signature` message carries a `signed_by` key fingerprint, not a key.
- **Size limits you forgot you had**, such as message-queue limits, database columns and ledger transaction limits. Find them in the inventory phase, not in production.

The private-key columns have a pleasant surprise. An ML-DSA private key expands to 4,032 bytes, but FIPS 204 lets you store just the 32-byte seed it was generated from. RFC 9881 recommends exactly that for key files, and it's what aws-lc-rs writes: 54 bytes of DER holding only the seed. (Its 83-byte Ed25519 file also embeds the public key.)

## Records that must outlive the algorithm

Hybrid signatures protect instructions while they are verified. Archives raise a different question: in 2040, how do you show that an instruction from 2027 is genuine, if Ed25519 is broken by then and ML-DSA has had thirteen more years of cryptanalysis?

The conservative tool is a **hash-based signature**, whose security rests only on the hash function. FIPS 205 standardises the stateless SLH-DSA, with small keys and large signatures:

| SLH-DSA (FIPS 205) | Category | Public key | Signature |
|---|---:|---:|---:|
| SHA2-128s | 1 | 32 B | 7,856 B |
| SHA2-128f | 1 | 32 B | 17,088 B |
| SHA2-192s | 3 | 48 B | 16,224 B |
| SHA2-256s | 5 | 64 B | 29,792 B |

The "s" sets are smaller and slower to sign; the "f" sets are faster and larger. Each key pair may sign up to 2⁶⁴ messages.

NIST SP 800-208 standardises the stateful alternatives, LMS and XMSS, with smaller signatures. But it comes with a stark warning: if two messages are ever signed with the same one-time key, an attacker can "forge signatures on arbitrary messages". NIST itself calls them "not suitable for general use", and requires their keys to live in hardware modules that don't let the private key be exported, "even in encrypted form". Ordinary key backup is therefore off the table. For an archive, SLH-DSA is usually the simpler choice.

Those sizes rule SLH-DSA out per instruction, but they don't matter once a day. A pattern that fits settlement well is to **seal the day**:
1. Build a Merkle tree or hash chain over every signed instruction of the day.
2. Sign its root once with SLH-DSA-SHA2-192s.
3. Store the seal next to the ledger, and keep the inclusion proofs.

The seal signatures cost about 6 MB a year. The inclusion proofs cost far more if you store them: at a million instructions a day, each proof is about 20 hashes, which comes to 230 GB a year with 32-byte hashes, or 350 GB with 48-byte ones. A proof can be recomputed from the day's instructions, so most systems should store the instructions and the roots and derive proofs on demand. Hash the tree with SHA-384 or SHA-512, to match a category-3 seal.

Each instruction then has two independent lines of evidence: its own hybrid signature, and its inclusion under a hash-based seal. Three caveats keep the pattern honest:
- **A seal you sign yourself isn't trusted time.** It becomes evidence of *when* only if someone else witnesses it: a timestamp authority, or counterparties countersigning or storing each day's root.
- **Seals only cover history from the day they start**, so start them early (step 2 of the playbook below).
- **There may be better-fitting parameters.** FIPS 205 points to SP 800-230 for additional parameter sets that support fewer signatures per key, and a once-a-day seal is the kind of use they are meant for.

## Running it in production: keys, HSMs and governance

**HSMs.** Most of the operational work lands here. Questions to put to your vendor early:
- Is ML-DSA in the *validated* firmware, not just a beta?
- Can keys be generated and backed up as seeds?
- Can the module sign an externally computed message representative? FIPS 204 explicitly allows μ to be "computed in a different cryptographic module", so the HSM receives 64 bytes instead of the message.
- What is the signing throughput, including the tail?

FIPS 204 also requires the hedged signing randomness to be generated inside the module that signs, which is one more reason not to roll your own around a raw key.

**Key registration.** Register new public keys with proof of possession: each party signs a registration statement with each new key, which stops it from registering someone else's key as its own. Give that statement its own domain prefix, distinct from `PQSETTLE/v1/`, so it can never be mistaken for a settlement signature. Check each key as it's registered, too: the right length and, for Ed25519, not of small order.

**Rotation and history.** Keep every public key a party ever used, with its validity period. Verifying a 2027 instruction in 2031 needs the 2027 key, and trusted evidence of when the signature was made, which a *witnessed* daily seal provides.

**Inventory.** You can't migrate what you can't find. CycloneDX 1.6 (April 2024) added a Cryptography Bill of Materials (CBOM) for exactly this kind of inventory. RFC 10073 notes that composites complicate it, because deprecated algorithms stay present inside approved composites.

**Regulation.** For EU financial entities, DORA's technical standard on ICT risk management (Delegated Regulation 2024/1774, Article 6) requires the encryption policy to include "provisions for updating or changing, where necessary, the cryptographic technology on the basis of developments in cryptanalysis". Article 7 covers keys across their whole lifecycle. A written, phased migration plan is the kind of provision that clause asks for.

## A migration playbook

The four phases map to an operational sequence. Each step has an entry gate, and none happens automatically.

1. **Inventory (`accept-classical`).** Find every place a settlement signature is created, verified or stored, and record for each:
   - the algorithm;
   - where the keys live;
   - what format the message uses, and its size limits;
   - how long the record is kept.

   Choose the HSM path. *Gate: the inventory is complete and every size limit has headroom for 3.4 KB signatures.*
2. **Distribute keys before you need them.** Every party generates fresh hybrid key material, registers it with proof of possession, and publishes it to counterparties while everyone is still classical. This is the slowest step and needs no change to any signature. Start daily seals now. *Gate: every counterparty's hybrid keys are registered.*
3. **Signers go hybrid (`prefer-hybrid`).** Each party signs hybrid; verifiers accept both. Monitor, per counterparty:
   - the share of hybrid traffic;
   - rejections by reason (bad signature, malformed, or not accepted in the phase);
   - signing p99;
   - message sizes.

   *Gate: 100% hybrid from a counterparty for an agreed period.*
4. **Verifiers require hybrid (`hybrid-required`).** Classical signatures are refused. This is the step that matters against a quantum attacker: until it happens, anyone who can forge Ed25519 can forge a *classical* instruction, and a verifier that still accepts classical will take it. Real networks will flip per counterparty rather than all at once. The crate has one global phase for simplicity; production would key the phase by counterparty.

   Rolling back to `prefer-hybrid` for one counterparty, say after an HSM failure, is possible. But it reopens that window, so make it time-boxed, approved and logged.
5. **Retire classical (`post-quantum-ready`).** Accept ML-DSA alone, the "second transition" NIST expects. When to take this step is a policy decision about confidence in ML-DSA, not a technical one. Before destroying classical keys, make sure the archive seals cover the history, and remove Ed25519 from the CBOM.

## What this is not

This is educational code accompanying an article.
- **Not audited.** Nobody has reviewed it independently.
- **Demo key storage.** Private keys sit on disk as unencrypted PKCS#8; in production they belong in an HSM or KMS.
- **Side-channel resistance is borrowed.** It depends entirely on AWS-LC.
- **Not standard.** The envelope and `M'` are my own construction, not RFC 10073, and the crate reuses keys across modes, which the RFC forbids, for the reasons given above.
- **No authorisation.** A valid signature proves who signed, not that they were entitled to. Nothing checks that the signer is the deliverer; that is the application's job.
- **Minimal validation.** Text fields must be printable ASCII, which keeps out control, invisible and look-alike characters, but nothing checks ISIN check digits or calendar dates.
- **Missing pieces.** It has no key rotation, revocation, trusted timestamping or daily seals. The phase is global rather than per counterparty.

## Next step: encryption

Signatures protect integrity. The more urgent quantum threat to settlement messages is confidentiality: positions, counterparties and amounts recorded in transit today and decrypted later. The natural sequel is hybrid key establishment with ML-KEM (FIPS 203) for the channels that carry these instructions.

## Run it

The code is at https://github.com/luishsr/pq-settlement-signing. Requirements: a recent stable Rust (tested with 1.100) and `jq` for the demo.

```bash
cargo test                                       # 32 tests, including cross-implementation checks
./demo.sh                                        # two banks, four phases, five attacks
taskset -c 2 cargo run --release -- bench        # latency, tail, sizes and throughput (pin to a fast core)
taskset -c 2 cargo run --release --example compare   # aws-lc-rs vs RustCrypto ML-DSA-65
```

---

### Sources

- NIST, *FIPS 204: Module-Lattice-Based Digital Signature Standard* (August 2024): §3, §3.4, §3.6, §5.4, Tables 1–2. https://csrc.nist.gov/pubs/fips/204/final
- NIST, *FIPS 205: Stateless Hash-Based Digital Signature Standard* (August 2024), Table 2. https://csrc.nist.gov/pubs/fips/205/final
- NIST, *SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes* (October 2020), §1.1–1.2. https://csrc.nist.gov/pubs/sp/800/208/final
- NIST, *IR 8547: Transition to Post-Quantum Cryptography Standards* (final, October 2026), §3.2, §3.2.2, Table 2. https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf
- EU PQC Workstream (NIS Cooperation Group), *A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography*, Part 1 v1.1 (published 23 June 2025). https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography
- IETF, *RFC 10073: Composite ML-DSA for Use in X.509 Public Key Infrastructure* (November 2026), §2, §9.2–9.5. https://www.rfc-editor.org/rfc/rfc10073.html
- IETF, *RFC 9881: Algorithm Identifiers for ML-DSA in X.509* (October 2025). https://www.rfc-editor.org/rfc/rfc9881.html
- Roetteler, Naehrig, Svore, Lauter, *Quantum resource estimates for computing elliptic curve discrete logarithms* (2017). https://arxiv.org/abs/1706.06752
- Gidney, *How to factor 2048 bit RSA integers with less than a million noisy qubits* (2025). https://arxiv.org/abs/2505.15917
- Beullens, *Breaking Rainbow Takes a Weekend on a Laptop* (2022). https://eprint.iacr.org/2022/214
- Castryck, Decru, *An efficient key recovery attack on SIDH* (2022). https://eprint.iacr.org/2022/975
- de Valence, *It's 255:19AM. Do you know what your validation criteria are?* (2020). https://hdevalence.ca/blog/2020-10-04-its-25519am
- Chalkias, Garillot, Nikolaenko, *Taming the many EdDSAs* (2020). https://eprint.iacr.org/2020/1244
- Commission Delegated Regulation (EU) 2024/1774 (DORA RTS on ICT risk management), Articles 6–7. https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj
- OWASP CycloneDX 1.6 release (April 2024). https://owasp.org/blog/2024/04/09/CycloneDX-v1.6-Released
- Canton 3.7 Ledger API, `com/daml/ledger/api/v2/crypto.proto` (`SigningAlgorithmSpec`, `Signature.signed_by`), in the open-source distribution.
- aws-lc-rs: https://crates.io/crates/aws-lc-rs · RustCrypto `ml-dsa`: https://crates.io/crates/ml-dsa
