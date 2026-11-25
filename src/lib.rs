//! Hybrid Ed25519 + ML-DSA-65 signatures for settlement instructions, with a verifier policy for
//! migrating a ledger from classical to post-quantum signatures.
//!
//! Educational code accompanying an article. Not audited; keys are stored unencrypted on disk.

pub mod hex;
pub mod hybrid;
pub mod instruction;
pub mod policy;

pub use hybrid::{
    Error, Mode, PartyKeys, PrivateKeyFile, PublicKeys, Signature, SignedInstruction,
    message_to_sign, verify,
};
pub use instruction::SettlementInstruction;
pub use policy::{Phase, verify_in_phase};
