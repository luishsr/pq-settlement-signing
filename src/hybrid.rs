//! Signing settlement instructions with Ed25519, ML-DSA-65, or both (hybrid).
//!
//! Every signature covers the same message representative:
//!
//! ```text
//! M' = "PQSETTLE/v1/" || mode label || 0x00 || SHA-512(canonical instruction bytes)
//! ```
//!
//! The mode label is inside `M'`, so a signature made in one mode is worthless in another: the
//! Ed25519 half of a hybrid signature can't be stripped off and passed as a classical signature,
//! and an envelope's mode can't be rewritten. In hybrid mode *both* signatures must verify.
//! The construction is inspired by RFC 10073 (composite ML-DSA); it is not an implementation of
//! it, and unlike the RFC it reuses each component key across modes.

use std::fmt;

use aws_lc_rs::digest::{SHA512, digest};
use aws_lc_rs::signature::{
    ED25519, Ed25519KeyPair, KeyPair, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::instruction::{InvalidInstruction, SettlementInstruction};
use crate::policy::Phase;

pub const DOMAIN: &str = "PQSETTLE/v1/";
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// Encodings of the small-order points of edwards25519 (orders 1, 2, 4 and 8), compared with the
/// x-sign bit (bit 255) cleared, including the non-canonical encodings y = p and y = p + 1.
/// Under a small-order public key, a trivial signature (R = identity, S = 0) verifies for many
/// messages, and aws-lc-rs accepts such keys, so they are refused before any verification.
const ED25519_SMALL_ORDER: [[u8; 32]; 7] = [
    // y = 0 (order 4)
    [0; 32],
    // y = 1, the identity (order 1)
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // order 8
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // order 8
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // y = p - 1 (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p, a non-canonical y = 0 (order 4)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p + 1, a non-canonical identity (order 1)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Ed25519 only: today's world.
    Classical,
    /// Ed25519 and ML-DSA-65, both required: the migration path.
    Hybrid,
    /// ML-DSA-65 only: after classical keys are retired.
    PostQuantum,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Classical, Mode::Hybrid, Mode::PostQuantum];

    /// Bound into every signed message (labels contain no 0x00, so the terminator is unambiguous).
    pub fn label(self) -> &'static str {
        match self {
            Mode::Classical => "ed25519",
            Mode::Hybrid => "ed25519+ml-dsa-65",
            Mode::PostQuantum => "ml-dsa-65",
        }
    }

    pub fn uses_ed25519(self) -> bool {
        matches!(self, Mode::Classical | Mode::Hybrid)
    }

    pub fn uses_ml_dsa(self) -> bool {
        matches!(self, Mode::Hybrid | Mode::PostQuantum)
    }
}

/// The bytes every component signature covers: `M'` above.
pub fn message_to_sign(mode: Mode, instruction: &SettlementInstruction) -> Vec<u8> {
    let hash = digest(&SHA512, &instruction.canonical_bytes());
    let mut m = Vec::with_capacity(DOMAIN.len() + mode.label().len() + 1 + hash.as_ref().len());
    m.extend_from_slice(DOMAIN.as_bytes());
    m.extend_from_slice(mode.label().as_bytes());
    m.push(0x00);
    m.extend_from_slice(hash.as_ref());
    m
}

/// A party's two key pairs. Both always exist; the mode decides which ones sign.
pub struct PartyKeys {
    id: String,
    ed25519: Ed25519KeyPair,
    ml_dsa: PqdsaKeyPair,
}

/// What a counterparty needs to verify: the raw public keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeys {
    pub id: String,
    #[serde(with = "crate::hex::bytes")]
    pub ed25519: Vec<u8>,
    #[serde(with = "crate::hex::bytes")]
    pub ml_dsa_65: Vec<u8>,
}

impl PublicKeys {
    /// Refuses keys of the wrong length and Ed25519 keys of small order. Public keys come from
    /// registration, not from attackers, but a party that registered a small-order key could later
    /// disown its signatures, so `verify` checks this before anything else.
    pub fn validate(&self) -> Result<(), Error> {
        if self.ed25519.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(Error::Key(format!(
                "Ed25519 public key is {} bytes, expected {ED25519_PUBLIC_KEY_LEN}",
                self.ed25519.len()
            )));
        }
        if self.ml_dsa_65.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(Error::Key(format!(
                "ML-DSA-65 public key is {} bytes, expected {ML_DSA_65_PUBLIC_KEY_LEN}",
                self.ml_dsa_65.len()
            )));
        }
        let mut y = [0u8; 32];
        y.copy_from_slice(&self.ed25519);
        y[31] &= 0x7f;
        if ED25519_SMALL_ORDER.contains(&y) {
            return Err(Error::Key("Ed25519 public key has small order".into()));
        }
        Ok(())
    }
}

/// Private keys on disk as PKCS#8. DEMO ONLY: unencrypted; real keys belong in an HSM or KMS.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateKeyFile {
    pub id: String,
    #[serde(with = "crate::hex::bytes")]
    pub ed25519_pkcs8: Vec<u8>,
    #[serde(with = "crate::hex::bytes")]
    pub ml_dsa_65_pkcs8: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub mode: Mode,
    /// The signing party's key id.
    pub signer: String,
    #[serde(
        default,
        with = "crate::hex::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub ed25519: Option<Vec<u8>>,
    #[serde(
        default,
        with = "crate::hex::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub ml_dsa_65: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedInstruction {
    pub instruction: SettlementInstruction,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid(InvalidInstruction),
    /// The signature names a different signer than the keys we were given.
    WrongSigner {
        expected: String,
        found: String,
    },
    /// The components present don't match the mode (e.g. a "classical" signature carrying ML-DSA).
    Malformed(String),
    /// A component signature doesn't verify.
    BadSignature(&'static str),
    /// Cryptographically valid, but this mode isn't accepted in the verifier's migration phase.
    NotAccepted {
        phase: Phase,
        mode: Mode,
    },
    Key(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(e) => write!(f, "{e}"),
            Error::WrongSigner { expected, found } => {
                write!(f, "signed by {found:?}, expected {expected:?}")
            }
            Error::Malformed(m) => write!(f, "malformed signature: {m}"),
            Error::BadSignature(alg) => write!(f, "{alg} signature does not verify"),
            Error::NotAccepted { phase, mode } => {
                write!(
                    f,
                    "{} signatures are not accepted in phase {}",
                    mode.label(),
                    phase.name()
                )
            }
            Error::Key(m) => write!(f, "key error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl PartyKeys {
    pub fn generate(id: &str) -> Result<Self, Error> {
        Ok(Self {
            id: id.to_string(),
            ed25519: Ed25519KeyPair::generate()
                .map_err(|_| Error::Key("Ed25519 key generation failed".into()))?,
            ml_dsa: PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
                .map_err(|_| Error::Key("ML-DSA-65 key generation failed".into()))?,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_keys(&self) -> PublicKeys {
        PublicKeys {
            id: self.id.clone(),
            ed25519: self.ed25519.public_key().as_ref().to_vec(),
            ml_dsa_65: self.ml_dsa.public_key().as_ref().to_vec(),
        }
    }

    pub fn to_file(&self) -> Result<PrivateKeyFile, Error> {
        Ok(PrivateKeyFile {
            id: self.id.clone(),
            ed25519_pkcs8: self
                .ed25519
                .to_pkcs8()
                .map_err(|_| Error::Key("Ed25519 export failed".into()))?
                .as_ref()
                .to_vec(),
            ml_dsa_65_pkcs8: self
                .ml_dsa
                .to_pkcs8v1()
                .map_err(|_| Error::Key("ML-DSA-65 export failed".into()))?
                .as_ref()
                .to_vec(),
        })
    }

    pub fn from_file(file: &PrivateKeyFile) -> Result<Self, Error> {
        Ok(Self {
            id: file.id.clone(),
            ed25519: Ed25519KeyPair::from_pkcs8(&file.ed25519_pkcs8)
                .map_err(|e| Error::Key(format!("Ed25519 PKCS#8: {e}")))?,
            ml_dsa: PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, &file.ml_dsa_65_pkcs8)
                .map_err(|e| Error::Key(format!("ML-DSA-65 PKCS#8: {e}")))?,
        })
    }

    /// Signs a valid instruction in `mode`. Every component signs the same `M'`.
    pub fn sign(
        &self,
        mode: Mode,
        instruction: &SettlementInstruction,
    ) -> Result<SignedInstruction, Error> {
        instruction.validate().map_err(Error::Invalid)?;
        let m = message_to_sign(mode, instruction);
        let ed25519 = mode
            .uses_ed25519()
            .then(|| self.ed25519.sign(&m).as_ref().to_vec());
        let ml_dsa_65 = if mode.uses_ml_dsa() {
            let mut sig = vec![0u8; ML_DSA_65_SIGNATURE_LEN];
            let len = self
                .ml_dsa
                .sign(&m, &mut sig)
                .map_err(|_| Error::Key("ML-DSA-65 signing failed".into()))?;
            sig.truncate(len);
            Some(sig)
        } else {
            None
        };
        Ok(SignedInstruction {
            instruction: instruction.clone(),
            signature: Signature {
                mode,
                signer: self.id.clone(),
                ed25519,
                ml_dsa_65,
            },
        })
    }
}

/// Checks the signature against `signer`'s keys. Every component the mode requires must be present
/// and must verify (AND, never OR); components the mode doesn't use must be absent.
/// Returns the mode that was verified. Whether that mode is *acceptable* is the policy's job.
pub fn verify(signed: &SignedInstruction, signer: &PublicKeys) -> Result<Mode, Error> {
    signer.validate()?;
    let sig = &signed.signature;
    if sig.signer != signer.id {
        return Err(Error::WrongSigner {
            expected: signer.id.clone(),
            found: sig.signer.clone(),
        });
    }
    signed.instruction.validate().map_err(Error::Invalid)?;
    let mode = sig.mode;
    if mode.uses_ed25519() != sig.ed25519.is_some() || mode.uses_ml_dsa() != sig.ml_dsa_65.is_some()
    {
        return Err(Error::Malformed(format!(
            "the components present don't match mode {}",
            mode.label()
        )));
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::tests::{one_field_changes, sample};

    fn bank_a() -> PartyKeys {
        PartyKeys::generate("bank-a").unwrap()
    }

    /// SHA-512 of the sample's canonical bytes, computed independently (Python: hashlib.sha512).
    const SAMPLE_SHA512_HEX: &str = concat!(
        "759033a64473c763e434a451d46e9dbc5080fbbdb42a6090789287fbc94aa2f6",
        "a9c7ae7c7c43d1c78868e4e258ffeec411f13f6938cbe1fcc83760fa51f6c627",
    );

    #[test]
    fn the_signed_message_format_is_pinned_byte_for_byte() {
        // Changing this layout silently invalidates every stored signature, so it is fixed here,
        // including the exact labels, which are spelled out rather than taken from `label()`.
        let hash = crate::hex::decode(SAMPLE_SHA512_HEX).unwrap();
        for (mode, label) in [
            (Mode::Classical, "ed25519"),
            (Mode::Hybrid, "ed25519+ml-dsa-65"),
            (Mode::PostQuantum, "ml-dsa-65"),
        ] {
            let mut expected = format!("PQSETTLE/v1/{label}\0").into_bytes();
            expected.extend_from_slice(&hash);
            assert_eq!(message_to_sign(mode, &sample()), expected, "{mode:?}");
        }
    }

    #[test]
    fn a_hybrid_with_either_half_missing_is_malformed() {
        // The AND rule depends on this: `verify` only checks the components that are present.
        let a = bank_a();
        let pk = a.public_keys();
        let signed = a.sign(Mode::Hybrid, &sample()).unwrap();

        let mut no_pq = signed.clone();
        no_pq.signature.ml_dsa_65 = None;
        assert!(matches!(verify(&no_pq, &pk), Err(Error::Malformed(_))));

        let mut no_classical = signed.clone();
        no_classical.signature.ed25519 = None;
        assert!(matches!(
            verify(&no_classical, &pk),
            Err(Error::Malformed(_))
        ));
    }

    /// R = identity, S = 0: valid under any key `A` for which [k]A is the identity.
    fn trivial_signature() -> Vec<u8> {
        let mut sig = vec![0u8; 64];
        sig[0] = 1;
        sig
    }

    #[test]
    fn small_order_and_wrong_length_keys_are_refused() {
        let good = bank_a().public_keys();
        assert_eq!(good.validate(), Ok(()));
        for weak in ED25519_SMALL_ORDER {
            for sign_bit in [0x00, 0x80] {
                let mut pk = good.clone();
                pk.ed25519 = weak.to_vec();
                pk.ed25519[31] |= sign_bit;
                assert!(
                    matches!(pk.validate(), Err(Error::Key(_))),
                    "{:02x?}",
                    pk.ed25519
                );
            }
        }
        let mut short = good.clone();
        short.ed25519.pop();
        assert!(matches!(short.validate(), Err(Error::Key(_))));
        let mut long = good.clone();
        long.ml_dsa_65.push(0);
        assert!(matches!(long.validate(), Err(Error::Key(_))));
    }

    #[test]
    fn the_blocked_keys_are_really_weak_in_aws_lc_rs() {
        // Why the list exists: for each canonical small-order key, some message has a trivial
        // signature that aws-lc-rs accepts. (The non-canonical encodings are blocked regardless.)
        for weak in &ED25519_SMALL_ORDER[..5] {
            let accepted = (0u8..64).any(|i| {
                UnparsedPublicKey::new(&ED25519, weak)
                    .verify(&[i], &trivial_signature())
                    .is_ok()
            });
            assert!(accepted, "{weak:02x?}");
        }
    }

    #[test]
    fn verify_refuses_a_small_order_key_even_for_a_trivially_valid_signature() {
        let identity = &ED25519_SMALL_ORDER[1];
        assert!(
            UnparsedPublicKey::new(&ED25519, identity)
                .verify(
                    &message_to_sign(Mode::Classical, &sample()),
                    &trivial_signature()
                )
                .is_ok()
        );
        let mut pk = bank_a().public_keys();
        pk.ed25519 = identity.to_vec();
        let forged = SignedInstruction {
            instruction: sample(),
            signature: Signature {
                mode: Mode::Classical,
                signer: pk.id.clone(),
                ed25519: Some(trivial_signature()),
                ml_dsa_65: None,
            },
        };
        assert!(matches!(verify(&forged, &pk), Err(Error::Key(_))));
    }

    #[test]
    fn unknown_fields_in_the_signature_are_refused() {
        let a = bank_a();
        let signed = a.sign(Mode::Hybrid, &sample()).unwrap();
        let mut v = serde_json::to_value(&signed).unwrap();
        v["signature"]["note"] = "unsigned".into();
        assert!(serde_json::from_value::<SignedInstruction>(v).is_err());
    }

    #[test]
    fn every_mode_round_trips_with_the_expected_sizes() {
        let a = bank_a();
        let pk = a.public_keys();
        assert_eq!((pk.ed25519.len(), pk.ml_dsa_65.len()), (32, 1952));
        for mode in Mode::ALL {
            let signed = a.sign(mode, &sample()).unwrap();
            assert_eq!(verify(&signed, &pk), Ok(mode));
            let sig = &signed.signature;
            let lens = (
                sig.ed25519.as_ref().map(Vec::len),
                sig.ml_dsa_65.as_ref().map(Vec::len),
            );
            let expected = match mode {
                Mode::Classical => (Some(ED25519_SIGNATURE_LEN), None),
                Mode::Hybrid => (Some(ED25519_SIGNATURE_LEN), Some(ML_DSA_65_SIGNATURE_LEN)),
                Mode::PostQuantum => (None, Some(ML_DSA_65_SIGNATURE_LEN)),
            };
            assert_eq!(lens, expected, "{mode:?}");
        }
    }

    #[test]
    fn changing_any_field_breaks_every_mode() {
        let a = bank_a();
        let pk = a.public_keys();
        for mode in Mode::ALL {
            let signed = a.sign(mode, &sample()).unwrap();
            for (field, changed) in one_field_changes() {
                let forged = SignedInstruction {
                    instruction: changed,
                    signature: signed.signature.clone(),
                };
                assert!(
                    matches!(verify(&forged, &pk), Err(Error::BadSignature(_))),
                    "{mode:?}: changed {field}"
                );
            }
        }
    }

    #[test]
    fn hybrid_needs_both_signatures_to_verify() {
        let a = bank_a();
        let pk = a.public_keys();
        let signed = a.sign(Mode::Hybrid, &sample()).unwrap();

        let mut bad_pq = signed.clone();
        bad_pq.signature.ml_dsa_65.as_mut().unwrap()[100] ^= 1;
        assert_eq!(verify(&bad_pq, &pk), Err(Error::BadSignature("ML-DSA-65")));

        let mut bad_classical = signed.clone();
        bad_classical.signature.ed25519.as_mut().unwrap()[10] ^= 1;
        assert_eq!(
            verify(&bad_classical, &pk),
            Err(Error::BadSignature("Ed25519"))
        );
    }

    #[test]
    fn stripping_one_half_of_a_hybrid_signature_fails() {
        let a = bank_a();
        let pk = a.public_keys();
        let hybrid = a.sign(Mode::Hybrid, &sample()).unwrap();

        // Keep only the Ed25519 half and call it classical: the label in M' differs, so it fails.
        let mut as_classical = hybrid.clone();
        as_classical.signature.mode = Mode::Classical;
        as_classical.signature.ml_dsa_65 = None;
        assert_eq!(
            verify(&as_classical, &pk),
            Err(Error::BadSignature("Ed25519"))
        );

        // Keep only the ML-DSA half and call it post-quantum: same.
        let mut as_pq = hybrid.clone();
        as_pq.signature.mode = Mode::PostQuantum;
        as_pq.signature.ed25519 = None;
        assert_eq!(verify(&as_pq, &pk), Err(Error::BadSignature("ML-DSA-65")));
    }

    #[test]
    fn rewriting_the_mode_or_mixing_components_fails() {
        let a = bank_a();
        let pk = a.public_keys();
        let hybrid = a.sign(Mode::Hybrid, &sample()).unwrap();

        // Downgrade the label but keep both components: refused before any crypto.
        let mut relabelled = hybrid.clone();
        relabelled.signature.mode = Mode::Classical;
        assert!(matches!(verify(&relabelled, &pk), Err(Error::Malformed(_))));

        // Genuine classical and post-quantum signatures from the same signer, on the same instruction,
        // glued together as a "hybrid": each was made for a different label, so it fails.
        let classical = a.sign(Mode::Classical, &sample()).unwrap();
        let pq = a.sign(Mode::PostQuantum, &sample()).unwrap();
        let mut glued = hybrid.clone();
        glued.signature.ed25519 = classical.signature.ed25519;
        glued.signature.ml_dsa_65 = pq.signature.ml_dsa_65;
        assert!(matches!(verify(&glued, &pk), Err(Error::BadSignature(_))));
    }

    #[test]
    fn another_partys_keys_do_not_verify() {
        let a = bank_a();
        let b = PartyKeys::generate("bank-b").unwrap();
        let signed = a.sign(Mode::Hybrid, &sample()).unwrap();
        assert!(matches!(
            verify(&signed, &b.public_keys()),
            Err(Error::WrongSigner { .. })
        ));

        // Even if an attacker relabels B's keys as "bank-a", the signatures don't match them.
        let mut impostor = b.public_keys();
        impostor.id = "bank-a".into();
        assert_eq!(
            verify(&signed, &impostor),
            Err(Error::BadSignature("Ed25519"))
        );
    }

    #[test]
    fn invalid_instructions_are_never_signed_or_accepted() {
        let a = bank_a();
        let mut bad = sample();
        bad.currency = "euro".into();
        assert!(matches!(a.sign(Mode::Hybrid, &bad), Err(Error::Invalid(_))));

        // An envelope carrying an invalid instruction is refused before any signature is checked.
        let mut signed = a.sign(Mode::Hybrid, &sample()).unwrap();
        signed.instruction.currency = "euro".into();
        assert!(matches!(
            verify(&signed, &a.public_keys()),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn keys_and_signed_instructions_survive_json_files() {
        let a = bank_a();
        let file_json = serde_json::to_string(&a.to_file().unwrap()).unwrap();
        let reloaded = PartyKeys::from_file(&serde_json::from_str(&file_json).unwrap()).unwrap();
        assert_eq!(reloaded.public_keys(), a.public_keys());

        let pk_json = serde_json::to_string_pretty(&a.public_keys()).unwrap();
        let pk: PublicKeys = serde_json::from_str(&pk_json).unwrap();
        let signed_json =
            serde_json::to_string_pretty(&reloaded.sign(Mode::Hybrid, &sample()).unwrap()).unwrap();
        let signed: SignedInstruction = serde_json::from_str(&signed_json).unwrap();
        assert_eq!(verify(&signed, &pk), Ok(Mode::Hybrid));
    }
}
