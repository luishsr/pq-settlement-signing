//! Hex for keys and signatures in JSON files: dependency-free and easy to eyeball.

pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex string has an odd length".into());
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("not a hex digit: {:?}", c as char)),
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Ok(nibble(p[0])? << 4 | nibble(p[1])?))
        .collect()
}

/// `#[serde(with = "crate::hex::bytes")]` on a `Vec<u8>`.
pub mod bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        super::decode(&String::deserialize(d)?).map_err(D::Error::custom)
    }
}

/// `#[serde(with = "crate::hex::option")]` on an `Option<Vec<u8>>`.
pub mod option {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&super::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|h| super::decode(&h).map_err(D::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(super::decode(&super::encode(&bytes)).unwrap(), bytes);
        assert_eq!(super::decode("0A0b").unwrap(), vec![0x0a, 0x0b]);
        assert!(super::decode("abc").is_err());
        assert!(super::decode("zz").is_err());
    }
}
