//! ML-DSA-65 speed: aws-lc-rs (C, what the crate signs with) vs RustCrypto `ml-dsa` (pure Rust,
//! a dev-dependency used only to cross-check). Each run signs a different message, so the number
//! of rejection-sampling rounds varies the way it does in production.
//!
//! The two libraries don't do the same work per call by default. RustCrypto's key objects cache
//! the expanded matrix A and NTT forms of the key; aws-lc re-derives them on every sign and verify,
//! and `UnparsedPublicKey` parses the key each time. The "per call" RustCrypto row decodes its keys
//! inside the timed call, so it does the same work as aws-lc.
//!
//!     cargo run --release --example compare

use std::hint::black_box;
use std::time::{Duration, Instant};

use aws_lc_rs::signature::{
    KeyPair, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Seed, Signature,
    SigningKey, VerifyingKey,
};

const N: usize = 2000;

/// (p50, p99) of `N` timed runs; `f` gets the run index.
fn measure<T>(mut f: impl FnMut(usize) -> T) -> (Duration, Duration) {
    for i in 0..N / 10 {
        black_box(f(i));
    }
    let mut samples: Vec<Duration> = (0..N)
        .map(|i| {
            let start = Instant::now();
            black_box(f(i));
            start.elapsed()
        })
        .collect();
    samples.sort_unstable();
    (samples[N / 2], samples[N * 99 / 100])
}

fn main() {
    // N distinct 86-byte messages, shaped like M'.
    let messages: Vec<Vec<u8>> = (0..N)
        .map(|i| {
            let mut m = b"PQSETTLE/v1/ml-dsa-65\0".to_vec();
            m.extend_from_slice(&(i as u64).to_be_bytes());
            m.resize(86, 0xab);
            m
        })
        .collect();
    let seed = [7u8; 32];

    // aws-lc-rs: hedged signing (the FIPS 204 default).
    let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed).unwrap();
    let pk = UnparsedPublicKey::new(&ML_DSA_65, kp.public_key().as_ref().to_vec());
    let mut buf = vec![0u8; 3309];
    let aws_sigs: Vec<Vec<u8>> = messages
        .iter()
        .map(|m| {
            kp.sign(m, &mut buf).unwrap();
            buf.clone()
        })
        .collect();
    let aws = (
        measure(|_| PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed)),
        measure(|i| kp.sign(&messages[i], &mut buf)),
        measure(|i| pk.verify(&messages[i], &aws_sigs[i]).is_ok()),
    );

    // RustCrypto: deterministic signing (its randomized variant needs an RNG feature).
    let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
    let esk = sk.expanded_key();
    let vk = esk.verifying_key();
    let rc_sigs: Vec<_> = messages
        .iter()
        .map(|m| esk.sign_deterministic(m, &[]).unwrap())
        .collect();
    assert!(vk.verify_with_context(&messages[0], &[], &rc_sigs[0]));
    let rc = (
        measure(|_| SigningKey::<MlDsa65>::from_seed(&Seed::from(seed))),
        measure(|i| esk.sign_deterministic(&messages[i], &[])),
        measure(|i| vk.verify_with_context(&messages[i], &[], &rc_sigs[i])),
    );

    // RustCrypto again, decoding the keys (and the signature) inside each call, like aws-lc.
    #[allow(deprecated)] // the expanded encoding is deprecated for storage, not for this purpose
    let esk_bytes = esk.to_expanded();
    let vk_bytes: EncodedVerifyingKey<MlDsa65> = vk.encode();
    let rc_sig_bytes: Vec<EncodedSignature<MlDsa65>> = rc_sigs.iter().map(|s| s.encode()).collect();
    #[allow(deprecated)]
    let rc_per_call = (
        rc.0,
        measure(|i| {
            ExpandedSigningKey::<MlDsa65>::from_expanded(&esk_bytes)
                .sign_deterministic(&messages[i], &[])
        }),
        measure(|i| {
            let sig = Signature::<MlDsa65>::decode(&rc_sig_bytes[i]).unwrap();
            VerifyingKey::<MlDsa65>::decode(&vk_bytes).verify_with_context(&messages[i], &[], &sig)
        }),
    );

    let us = |d: Duration| format!("{:.1}", d.as_secs_f64() * 1e6);
    println!("ML-DSA-65, {N} runs per operation, one thread, µs");
    println!(
        "| {:<38} | {:>16} | {:>8} | {:>8} | {:>10} | {:>10} |",
        "Implementation", "Keygen from seed", "Sign p50", "Sign p99", "Verify p50", "Verify p99"
    );
    println!(
        "|{:-<40}|{:->18}|{:->10}|{:->10}|{:->12}|{:->12}|",
        "", ":", ":", ":", ":", ":"
    );
    for (name, ((kg, _), (s50, s99), (v50, v99))) in [
        ("aws-lc-rs 1.19 (C, hedged)", aws),
        ("RustCrypto 0.1, cached keys", rc),
        ("RustCrypto 0.1, keys decoded per call", rc_per_call),
    ] {
        println!(
            "| {:<38} | {:>16} | {:>8} | {:>8} | {:>10} | {:>10} |",
            name,
            us(kg),
            us(s50),
            us(s99),
            us(v50),
            us(v99)
        );
    }
}
