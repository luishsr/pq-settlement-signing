//! Properties a ledger relies on without saying so: that a third party can't produce a second valid
//! signature from an existing one, and what "the same signature" means when one half is randomized.

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use pq_settlement_signing::{Mode, PartyKeys, SettlementInstruction, verify};

fn instruction() -> SettlementInstruction {
    serde_json::from_str(include_str!("../examples/instruction.json")).unwrap()
}

/// L, the order of the Ed25519 base point, little-endian (RFC 8032, section 5.1).
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Little-endian 256-bit addition; S < L < 2^253, so S + L never overflows 32 bytes.
fn add_le(a: &[u8], b: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    out
}

#[test]
fn ed25519_rejects_the_malleated_s_plus_l_signature() {
    // (R, S) and (R, S + L) satisfy the same group equation. Accepting the second would let anyone
    // mint a different valid signature for an instruction they didn't sign. RFC 8032 requires S < L.
    let kp = Ed25519KeyPair::generate().unwrap();
    let msg = b"PQSETTLE/v1/ed25519\0 any message";
    let sig = kp.sign(msg).as_ref().to_vec();
    let pk = UnparsedPublicKey::new(&ED25519, kp.public_key().as_ref().to_vec());
    assert!(pk.verify(msg, &sig).is_ok());

    let mut malleated = sig[..32].to_vec();
    malleated.extend(add_le(&sig[32..], &L));
    assert_ne!(malleated, sig);
    assert!(
        pk.verify(msg, &malleated).is_err(),
        "aws-lc-rs must reject S >= L"
    );
}

#[test]
fn re_signing_changes_the_ml_dsa_half_but_not_the_ed25519_half() {
    // Ed25519 is deterministic; ML-DSA in its default hedged mode is not. Two honest hybrid
    // signatures of one instruction therefore differ, and both verify: never use signature bytes
    // as an identifier or a de-duplication key. Use the instruction (or its canonical hash).
    let keys = PartyKeys::generate("bank-a").unwrap();
    let pk = keys.public_keys();
    let first = keys.sign(Mode::Hybrid, &instruction()).unwrap();
    let second = keys.sign(Mode::Hybrid, &instruction()).unwrap();

    assert_eq!(first.signature.ed25519, second.signature.ed25519);
    assert_ne!(first.signature.ml_dsa_65, second.signature.ml_dsa_65);
    assert_eq!(verify(&first, &pk), Ok(Mode::Hybrid));
    assert_eq!(verify(&second, &pk), Ok(Mode::Hybrid));
}
