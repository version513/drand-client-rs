use bls_signatures::{hash, PublicKey, Serialize, Signature, verify};
use crate::chain_info::ChainInfo;
use crate::SchemeError;

pub trait BlsVerifiable {
    fn signature(&self) -> &Vec<u8>;
    fn to_message(&self) -> Result<Vec<u8>, SchemeError>;
}

pub(crate) fn bls_verify<B: BlsVerifiable>(info: &ChainInfo, beacon: B) -> Result<B, SchemeError> {
    let public_key = PublicKey::from_bytes(info.public_key.as_slice())
        .map_err(|_| SchemeError::InvalidChainInfo)?;

    let signature = Signature::from_bytes(&beacon.signature().as_slice())
        .map_err(|_| SchemeError::InvalidBeacon)?;

    let bls_message_bytes = beacon.to_message()
        .map(|bytes| sha256::digest(bytes.as_slice()))
        .and_then(|hex_str| hex::decode(hex_str)
            .map_err(|_| SchemeError::InvalidBeacon)
        )?;


    let point_on_curve = hash(bls_message_bytes.as_slice());
    if !verify(&signature, &[point_on_curve], &[public_key]) {
        return Err(SchemeError::InvalidBeacon);
    }

    return Ok(beacon);
}
