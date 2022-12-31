use crate::bls::BlsVerifiable;
use crate::chain_info::ChainInfo;
use crate::{bls, Scheme, SchemeError};
use serde::Deserialize;
use std::io::Write;

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct ChainedBeacon {
    #[serde(alias = "round")]
    pub round_number: u64,
    #[serde(with = "hex")]
    pub randomness: Vec<u8>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
    #[serde(with = "hex")]
    pub previous_signature: Vec<u8>,
}

pub struct ChainedScheme {}

impl Scheme<ChainedBeacon> for ChainedScheme {
    fn supports(&self, scheme_id: &str) -> bool {
        scheme_id.eq_ignore_ascii_case("pedersen-bls-chained")
    }

    fn verify(
        &self,
        info: &ChainInfo,
        beacon: ChainedBeacon,
    ) -> Result<ChainedBeacon, SchemeError> {
        if !self.supports(&info.scheme_id) {
            Err(SchemeError::InvalidScheme)
        } else {
            bls::bls_verify(info, beacon)
        }
    }
}

impl BlsVerifiable for ChainedBeacon {
    fn signature(&self) -> &Vec<u8> {
        &self.signature
    }

    fn to_message(&self) -> Result<Vec<u8>, SchemeError> {
        let mut bytes: Vec<u8> = vec![];

        if bytes.write_all(self.previous_signature.as_slice()).is_err() {
            return Err(SchemeError::InvalidBeacon);
        }
        if bytes.write_all(&self.round_number.to_be_bytes()).is_err() {
            Err(SchemeError::InvalidBeacon)
        } else {
            Ok(bytes)
        }
    }
}
