use bls_signatures::{PublicKey, Serialize, Signature, verify};
use json::JsonValue;
use crate::{ChainInfo, Scheme, SchemeError};
use thiserror::Error;

pub(crate) struct ChainedBeacon {
    pub round_number: u64,
    pub randomness: Vec<u8>,
    pub signature: Vec<u8>,
    pub previous_signature: Vec<u8>,
}


#[derive(Error, Debug)]
pub enum JsonParseError {
    #[error("unknown error")]
    UnknownError,
    #[error("empty payload")]
    EmptyPayload,
    #[error("could not parse")]
    CouldNotParse,
    #[error("invalid json")]
    InvalidJson,
    #[error("invalid type")]
    InvalidType { key: String },
    #[error("could not parse value")]
    CouldNotParseValue { key: String },
    #[error("unknown key")]
    UnknownKey { key: String },
}

impl TryFrom<JsonValue> for ChainedBeacon {
    type Error = JsonParseError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        if !value.is_object() {
            return Err(JsonParseError::CouldNotParse);
        }

        let mut out = ChainedBeacon {
            round_number: 0,
            randomness: vec![],
            signature: vec![],
            previous_signature: vec![],
        };

        for (key, value) in value.entries() {
            match key {
                "round" => {
                    if !value.is_number() {
                        return Err(JsonParseError::CouldNotParseValue { key: key.to_string() });
                    }
                    if let Some(round_number) = value.as_u64() {
                        out.round_number = round_number
                    } else {
                        return Err(JsonParseError::CouldNotParseValue { key: key.to_string() });
                    }
                }
                "randomness" => {
                    out.randomness = parse_bytes(key, value)?
                }
                "signature" => {
                    out.signature = parse_bytes(key, value)?
                }
                "previous_signature" => {
                    out.previous_signature = parse_bytes(key, value)?
                }
                _ => return Err(JsonParseError::UnknownKey { key: key.to_string() })
            }
        }

        return Ok(out);
    }
}

fn parse_bytes<'a>(key: &str, value: &JsonValue) -> Result<Vec<u8>, JsonParseError> {
    if !value.is_string() {
        return Err(JsonParseError::InvalidType { key: key.to_string() });
    }
    return match value.as_str() {
        None =>
            Err(JsonParseError::CouldNotParseValue { key: key.to_string() }),
        Some(hex_str) =>
            hex::decode(hex_str)
                .map_err(|_| JsonParseError::CouldNotParseValue { key: key.to_string() })
    };
}

pub struct ChainedScheme {}

impl Scheme<ChainedBeacon> for ChainedScheme {
    fn supports(&self, scheme_id: &str) -> bool {
        return scheme_id.eq_ignore_ascii_case("bls-pedersen-chained");
    }

    fn verify(&self, info: &ChainInfo, beacon: ChainedBeacon) -> Result<ChainedBeacon, SchemeError> {
        if !self.supports(&info.scheme_id) {
            return Err(SchemeError::InvalidScheme);
        }

        let public_key = PublicKey::from_bytes(info.public_key.as_slice())
            .map_err(|_| SchemeError::InvalidChainInfo)?;

        let signature = Signature::from_bytes(&beacon.signature.as_slice())
            .map_err(|_| SchemeError::InvalidBeacon)?;

        if !verify(&signature, &[], &[public_key]) {
            return Err(SchemeError::InvalidBeacon);
        }

        return Ok(beacon);
    }
}