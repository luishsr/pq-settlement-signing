//! Two independent ML-DSA-65 implementations must agree: aws-lc-rs (C, used by the crate) and
//! RustCrypto's `ml-dsa` (pure Rust, test-only). If our signatures only verified with the library
//! that made them, we'd have no evidence they follow FIPS 204.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, ML_DSA_65, UnparsedPublicKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Seed, Signature as RcSignature, SigningKey,
    VerifyingKey,
};
use pq_settlement_signing::{
    Mode, PartyKeys, PublicKeys, SettlementInstruction, Signature, SignedInstruction,
    message_to_sign, verify,
};

fn instruction() -> SettlementInstruction {
    SettlementInstruction {
        instruction_id: "SI-2027-000417".into(),
        trade_id: "T-88123".into(),
        settlement_date: "2027-02-17".into(),
        deliverer: "BANKAPTPLXXX".into(),
        receiver: "BANKBBEBBXXX".into(),
        isin: "XS1234567890".into(),
        nominal: 1_000_000,
        cash_amount_minor: 100_500_000,
        currency: "EUR".into(),
    }
}

fn rustcrypto_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let vk = VerifyingKey::<MlDsa65>::decode(
        &EncodedVerifyingKey::<MlDsa65>::try_from(public_key).expect("1952-byte key"),
    );
    let sig = RcSignature::<MlDsa65>::decode(
        &EncodedSignature::<MlDsa65>::try_from(signature).expect("3309-byte signature"),
    )
    .expect("well-formed signature");
    vk.verify_with_context(message, &[], &sig)
}

#[test]
fn our_hybrid_signatures_verify_with_rustcrypto() {
    let keys = PartyKeys::generate("bank-a").unwrap();
    let pk = keys.public_keys();
    let signed = keys.sign(Mode::Hybrid, &instruction()).unwrap();
    let m = message_to_sign(Mode::Hybrid, &signed.instruction);
    let pq = signed.signature.ml_dsa_65.as_ref().unwrap();

    assert!(
        rustcrypto_verify(&pk.ml_dsa_65, &m, pq),
        "RustCrypto must accept aws-lc-rs signatures"
    );
    // ...and must reject the same signature over a different instruction.
    let mut other = instruction();
    other.nominal += 1;
    assert!(!rustcrypto_verify(
        &pk.ml_dsa_65,
        &message_to_sign(Mode::Hybrid, &other),
        pq
    ));
}

#[test]
fn rustcrypto_signatures_verify_with_aws_lc_and_through_our_envelope() {
    // A post-quantum-only signature produced entirely by RustCrypto, from a fixed seed.
    let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from([7u8; 32]));
    let sk = sk.expanded_key();
    let vk = sk.verifying_key().encode().to_vec();
    let m = message_to_sign(Mode::PostQuantum, &instruction());
    let sig = sk.sign_deterministic(&m, &[]).unwrap().encode().to_vec();

    assert!(
        UnparsedPublicKey::new(&ML_DSA_65, &vk)
            .verify(&m, &sig)
            .is_ok(),
        "aws-lc-rs must accept RustCrypto signatures"
    );

    // The same signature in our envelope passes our verifier.
    let signer = PublicKeys {
        id: "rustcrypto-bank".into(),
        ed25519: Ed25519KeyPair::generate()
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec(), // unused in post-quantum mode
        ml_dsa_65: vk,
    };
    let signed = SignedInstruction {
        instruction: instruction(),
        signature: Signature {
            mode: Mode::PostQuantum,
            signer: "rustcrypto-bank".into(),
            ed25519: None,
            ml_dsa_65: Some(sig),
        },
    };
    assert_eq!(verify(&signed, &signer), Ok(Mode::PostQuantum));
}
