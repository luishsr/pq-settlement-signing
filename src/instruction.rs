//! A delivery-versus-payment settlement instruction and its canonical encoding: the exact bytes
//! that get hashed and signed. JSON is only for files and transport; signatures never cover JSON,
//! so whitespace, key order or number formatting can't change what was signed.

use std::fmt;

use serde::{Deserialize, Serialize};

/// "Bank A delivers `nominal` of `isin` to Bank B, against `cash_amount_minor` of `currency`,
/// on `settlement_date`."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementInstruction {
    pub instruction_id: String,
    pub trade_id: String,
    /// ISO date, e.g. "2027-02-17".
    pub settlement_date: String,
    /// Party delivering the securities (and receiving the cash).
    pub deliverer: String,
    /// Party receiving the securities (and paying the cash).
    pub receiver: String,
    pub isin: String,
    /// Nominal of the securities leg, in whole units of the currency.
    pub nominal: u64,
    /// Cash leg in minor units (cents), so amounts are exact.
    pub cash_amount_minor: u64,
    /// ISO 4217 code, e.g. "EUR".
    pub currency: String,
}

/// Version of the encoding below. Bump it if fields change, so old and new bytes never collide.
const ENCODING_VERSION: &[u8] = b"SI/1";
/// Longest accepted text field, in bytes.
pub const MAX_FIELD_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidInstruction(pub String);

impl fmt::Display for InvalidInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid instruction: {}", self.0)
    }
}

impl std::error::Error for InvalidInstruction {}

impl SettlementInstruction {
    /// Refuses instructions a bank would never sign: empty or oversized fields, text outside
    /// printable ASCII (no control, invisible or look-alike characters), malformed codes.
    pub fn validate(&self) -> Result<(), InvalidInstruction> {
        let bad = |msg: String| Err(InvalidInstruction(msg));
        for (name, value) in self.text_fields() {
            if value.is_empty() {
                return bad(format!("{name} is empty"));
            }
            if value.len() > MAX_FIELD_LEN {
                return bad(format!("{name} is longer than {MAX_FIELD_LEN} bytes"));
            }
            if !value.bytes().all(|b| (b' '..=b'~').contains(&b)) {
                return bad(format!("{name} must be printable ASCII"));
            }
            if value.starts_with(' ') || value.ends_with(' ') {
                return bad(format!("{name} has leading or trailing spaces"));
            }
        }
        if !is_iso_date(&self.settlement_date) {
            return bad(format!(
                "settlement_date {:?} is not YYYY-MM-DD",
                self.settlement_date
            ));
        }
        if self.isin.len() != 12
            || !self
                .isin
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return bad(format!(
                "isin {:?} is not 12 upper-case letters and digits",
                self.isin
            ));
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_uppercase()) {
            return bad(format!(
                "currency {:?} is not a 3-letter ISO code",
                self.currency
            ));
        }
        if self.deliverer.eq_ignore_ascii_case(&self.receiver) {
            return bad("deliverer and receiver are the same party".into());
        }
        if self.nominal == 0 || self.cash_amount_minor == 0 {
            return bad("nominal and cash amount must be positive".into());
        }
        Ok(())
    }

    /// The canonical bytes: a version tag, then every field in a fixed order as
    /// `tag (1 byte) || length (4 bytes, big-endian) || value`. Because every value carries its
    /// length, no two different instructions encode to the same bytes (("ab","c") vs ("a","bc")).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(ENCODING_VERSION);
        let mut tag = 0u8;
        for (_, value) in self.text_fields() {
            tag += 1;
            push_field(&mut out, tag, value.as_bytes());
        }
        push_field(&mut out, tag + 1, &self.nominal.to_be_bytes());
        push_field(&mut out, tag + 2, &self.cash_amount_minor.to_be_bytes());
        out
    }

    fn text_fields(&self) -> [(&'static str, &str); 7] {
        [
            ("instruction_id", &self.instruction_id),
            ("trade_id", &self.trade_id),
            ("settlement_date", &self.settlement_date),
            ("deliverer", &self.deliverer),
            ("receiver", &self.receiver),
            ("isin", &self.isin),
            ("currency", &self.currency),
        ]
    }
}

fn push_field(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
        && matches!(s[5..7].parse::<u8>(), Ok(1..=12))
        && matches!(s[8..10].parse::<u8>(), Ok(1..=31))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample() -> SettlementInstruction {
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

    /// Every way to change one field, used by the tamper tests here and in `hybrid`.
    pub(crate) fn one_field_changes() -> Vec<(&'static str, SettlementInstruction)> {
        let s = sample();
        let with = |f: fn(&mut SettlementInstruction)| {
            let mut c = s.clone();
            f(&mut c);
            c
        };
        vec![
            ("instruction_id", with(|i| i.instruction_id.push('9'))),
            ("trade_id", with(|i| i.trade_id = "T-88124".into())),
            (
                "settlement_date",
                with(|i| i.settlement_date = "2027-02-18".into()),
            ),
            ("deliverer", with(|i| i.deliverer = "BANKCFRPPXXX".into())),
            ("receiver", with(|i| i.receiver = "BANKCFRPPXXX".into())),
            ("isin", with(|i| i.isin = "XS1234567891".into())),
            ("nominal", with(|i| i.nominal += 1)),
            ("cash_amount_minor", with(|i| i.cash_amount_minor -= 1)),
            ("currency", with(|i| i.currency = "USD".into())),
        ]
    }

    #[test]
    fn canonical_bytes_are_deterministic_and_change_with_every_field() {
        let s = sample();
        assert_eq!(s.canonical_bytes(), s.clone().canonical_bytes());
        for (field, changed) in one_field_changes() {
            assert_ne!(
                s.canonical_bytes(),
                changed.canonical_bytes(),
                "changing {field} must change the bytes"
            );
        }
    }

    #[test]
    fn length_prefixes_keep_field_boundaries_unambiguous() {
        let pair = |id: &str, trade: &str| {
            let mut i = sample();
            (i.instruction_id, i.trade_id) = (id.into(), trade.into());
            i.canonical_bytes()
        };
        // Plain concatenation would make these equal.
        assert_ne!(pair("SI-1", "23"), pair("SI-12", "3"));
        // Field tags alone aren't enough: a value can contain the next field's tag byte (0x02), so
        // without length prefixes ("A\x02B", "C") and ("A", "B\x02C") would encode identically.
        assert_ne!(pair("A\u{2}B", "C"), pair("A", "B\u{2}C"));
    }

    /// The sample's canonical bytes, computed independently of this crate (Python: struct.pack).
    /// Stored signatures depend on every one of these bytes: a format change must be a new version.
    pub(crate) const SAMPLE_CANONICAL_HEX: &str = concat!(
        "53492f31", // "SI/1"
        "010000000e",
        "53492d323032372d303030343137", // 1 instruction_id
        "0200000007",
        "542d3838313233", // 2 trade_id
        "030000000a",
        "323032372d30322d3137", // 3 settlement_date
        "040000000c",
        "42414e4b415054504c585858", // 4 deliverer
        "050000000c",
        "42414e4b4242454242585858", // 5 receiver
        "060000000c",
        "585331323334353637383930", // 6 isin
        "0700000003",
        "455552", // 7 currency
        "0800000008",
        "00000000000f4240", // 8 nominal, u64 big-endian
        "0900000008",
        "0000000005fd8220", // 9 cash_amount_minor, u64 big-endian
    );

    #[test]
    fn the_encoding_is_pinned_byte_for_byte() {
        let expected = crate::hex::decode(SAMPLE_CANONICAL_HEX).unwrap();
        assert_eq!(expected.len(), 135);
        assert_eq!(sample().canonical_bytes(), expected);
    }

    #[test]
    fn json_formatting_and_key_order_do_not_change_the_signed_bytes() {
        // Written by hand, not produced by serde, so this can't agree with the code by construction.
        let compact = r#"{"instruction_id":"SI-2027-000417","trade_id":"T-88123","settlement_date":"2027-02-17","deliverer":"BANKAPTPLXXX","receiver":"BANKBBEBBXXX","isin":"XS1234567890","nominal":1000000,"cash_amount_minor":100500000,"currency":"EUR"}"#;
        let reordered = r#"
            { "currency" : "EUR",   "cash_amount_minor": 100500000, "nominal": 1000000,
              "isin": "XS1234567890", "receiver": "BANKBBEBBXXX", "deliverer": "BANKAPTPLXXX",
              "settlement_date": "2027-02-17", "trade_id": "T-88123",
              "instruction_id": "SI-2027-000417" }"#;
        let expected = crate::hex::decode(SAMPLE_CANONICAL_HEX).unwrap();
        for json in [compact, reordered] {
            let i: SettlementInstruction = serde_json::from_str(json).unwrap();
            assert_eq!(i.canonical_bytes(), expected);
        }
    }

    type Breakage = (&'static str, fn(&mut SettlementInstruction));

    #[test]
    fn validation_refuses_malformed_instructions() {
        assert!(sample().validate().is_ok());
        let cases: Vec<Breakage> = vec![
            ("empty", |i| i.trade_id.clear()),
            ("printable ASCII", |i| i.deliverer.push('\u{2}')),
            ("printable ASCII", |i| i.deliverer.push('\u{200b}')), // zero-width space
            ("printable ASCII", |i| i.isin.insert(0, '\u{202e}')), // right-to-left override
            ("trailing spaces", |i| i.receiver.push(' ')),
            ("same party", |i| i.receiver = i.deliverer.to_lowercase()),
            ("longer than", |i| {
                i.instruction_id = "x".repeat(MAX_FIELD_LEN + 1)
            }),
            ("YYYY-MM-DD", |i| i.settlement_date = "17/02/2027".into()),
            ("YYYY-MM-DD", |i| i.settlement_date = "2027-13-01".into()),
            ("isin", |i| i.isin = "XS123".into()),
            ("currency", |i| i.currency = "eur".into()),
            ("same party", |i| i.receiver = i.deliverer.clone()),
            ("positive", |i| i.nominal = 0),
        ];
        for (fragment, f) in cases {
            let mut i = sample();
            f(&mut i);
            let err = i.validate().expect_err(fragment).to_string();
            assert!(
                err.contains(fragment),
                "{err:?} should mention {fragment:?}"
            );
        }
    }

    #[test]
    fn unknown_json_fields_are_refused() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["memo"] = "pay to another account".into();
        assert!(serde_json::from_value::<SettlementInstruction>(v).is_err());
    }
}
