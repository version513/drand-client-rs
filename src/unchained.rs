use std::io::Write;
use crate::{bls, Scheme, SchemeError};
use crate::chain_info::ChainInfo;
use serde::Deserialize;
use crate::bls::BlsVerifiable;

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct UnchainedBeacon {
    #[serde(alias = "round")]
    pub round_number: u64,
    #[serde(with = "hex")]
    pub randomness: Vec<u8>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

pub struct UnchainedScheme {}

impl Scheme<UnchainedBeacon> for UnchainedScheme {
    fn supports(&self, scheme_id: &str) -> bool {
        return scheme_id.eq_ignore_ascii_case("pedersen-bls-unchained");
    }

    fn verify(&self, info: &ChainInfo, beacon: UnchainedBeacon) -> Result<UnchainedBeacon, SchemeError> {
        if !self.supports(&info.scheme_id) {
            return Err(SchemeError::InvalidScheme);
        }

        return bls::bls_verify(info, beacon);
    }
}

impl BlsVerifiable for UnchainedBeacon {
    fn signature(&self) -> &Vec<u8> {
        &self.signature
    }

    fn to_message(&self) -> Result<Vec<u8>, SchemeError> {
        let mut bytes: Vec<u8> = vec![];

        if bytes.write_all(&self.round_number.to_be_bytes()).is_err() {
            return Err(SchemeError::InvalidBeacon);
        };

        return Ok(bytes);
    }
}