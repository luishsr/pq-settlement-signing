//! The verifier's migration phase: which signature modes it accepts for new instructions.
//! A phase change is a deliberate configuration change, never an automatic fallback.
//! (Records signed under an earlier phase are a separate archive question: they stay valid as
//! what they were when signed, and long-lived ones get re-attested before classical keys retire.)

use serde::{Deserialize, Serialize};

use crate::hybrid::{Error, Mode, PublicKeys, SignedInstruction, verify};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// 0. Before migration: classical only.
    AcceptClassical,
    /// 1. Signers move to hybrid; classical still accepted while counterparties catch up.
    PreferHybrid,
    /// 2. Everyone signs hybrid; classical refused.
    HybridRequired,
    /// 3. Post-quantum only signatures accepted alongside hybrid; classical keys can be retired.
    PostQuantumReady,
}

impl Phase {
    pub const ALL: [Phase; 4] = [
        Phase::AcceptClassical,
        Phase::PreferHybrid,
        Phase::HybridRequired,
        Phase::PostQuantumReady,
    ];

    pub fn accepts(self, mode: Mode) -> bool {
        match self {
            Phase::AcceptClassical => mode == Mode::Classical,
            Phase::PreferHybrid => matches!(mode, Mode::Classical | Mode::Hybrid),
            Phase::HybridRequired => mode == Mode::Hybrid,
            Phase::PostQuantumReady => matches!(mode, Mode::Hybrid | Mode::PostQuantum),
        }
    }

    /// The mode a signer should produce in this phase.
    pub fn signing_mode(self) -> Mode {
        match self {
            Phase::AcceptClassical => Mode::Classical,
            Phase::PreferHybrid | Phase::HybridRequired => Mode::Hybrid,
            Phase::PostQuantumReady => Mode::PostQuantum,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Phase::AcceptClassical => "accept-classical",
            Phase::PreferHybrid => "prefer-hybrid",
            Phase::HybridRequired => "hybrid-required",
            Phase::PostQuantumReady => "post-quantum-ready",
        }
    }

    pub fn parse(name: &str) -> Option<Phase> {
        Phase::ALL.into_iter().find(|p| p.name() == name)
    }
}

/// Verifies the signature and checks its mode is acceptable in `phase`. The phase is checked first,
/// so an unacceptable mode is refused even when the cryptography is perfect.
pub fn verify_in_phase(
    signed: &SignedInstruction,
    signer: &PublicKeys,
    phase: Phase,
) -> Result<Mode, Error> {
    let mode = signed.signature.mode;
    if !phase.accepts(mode) {
        return Err(Error::NotAccepted { phase, mode });
    }
    verify(signed, signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::PartyKeys;
    use crate::instruction::tests::sample;

    #[test]
    fn acceptance_matrix() {
        use Mode::*;
        let expected = [
            (Phase::AcceptClassical, [true, false, false]),
            (Phase::PreferHybrid, [true, true, false]),
            (Phase::HybridRequired, [false, true, false]),
            (Phase::PostQuantumReady, [false, true, true]),
        ];
        for (phase, row) in expected {
            let got = [Classical, Hybrid, PostQuantum].map(|m| phase.accepts(m));
            assert_eq!(got, row, "{phase:?}");
            assert!(
                phase.accepts(phase.signing_mode()),
                "{phase:?} must accept what it signs"
            );
        }
    }

    #[test]
    fn the_phase_decides_even_for_valid_signatures() {
        let a = PartyKeys::generate("bank-a").unwrap();
        let pk = a.public_keys();
        for phase in Phase::ALL {
            for mode in Mode::ALL {
                let signed = a.sign(mode, &sample()).unwrap();
                let result = verify_in_phase(&signed, &pk, phase);
                if phase.accepts(mode) {
                    assert_eq!(result, Ok(mode), "{phase:?} {mode:?}");
                } else {
                    assert_eq!(
                        result,
                        Err(Error::NotAccepted { phase, mode }),
                        "{phase:?} {mode:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_phase_is_checked_before_any_cryptography() {
        // A classical envelope with a broken signature, under hybrid-required: the answer must be
        // "not accepted in this phase", which proves the policy ran before the signature check.
        let a = PartyKeys::generate("bank-a").unwrap();
        let mut signed = a.sign(Mode::Classical, &sample()).unwrap();
        signed.signature.ed25519.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            verify_in_phase(&signed, &a.public_keys(), Phase::HybridRequired),
            Err(Error::NotAccepted {
                phase: Phase::HybridRequired,
                mode: Mode::Classical
            })
        );
        // ...while in a phase that accepts classical, the same envelope fails on the signature.
        assert_eq!(
            verify_in_phase(&signed, &a.public_keys(), Phase::PreferHybrid),
            Err(Error::BadSignature("Ed25519"))
        );
    }

    #[test]
    fn names_round_trip() {
        for p in Phase::ALL {
            assert_eq!(Phase::parse(p.name()), Some(p));
        }
        assert_eq!(Phase::parse("yolo"), None);
    }
}
