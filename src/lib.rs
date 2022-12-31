extern crate core;

mod chained;
mod unchained;
mod http;
mod chain_info;
mod bls;

use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use thiserror::Error;
use crate::chain_info::ChainInfo;
use crate::chained::{ChainedBeacon, ChainedScheme};
use crate::DrandClientError::{InvalidChainInfo, InvalidRound};
use crate::http::HttpTransport;
use crate::unchained::{UnchainedBeacon, UnchainedScheme};

struct DrandClient<'a, B> {
    scheme: &'a dyn Scheme<B>,
    transport: HttpTransport,
    base_url: &'a str,
    chain_info: ChainInfo,
}

fn new_chained_client(base_url: &str) -> Result<DrandClient<ChainedBeacon>, DrandClientError> {
    return new_client(&ChainedScheme {}, base_url);
}

fn new_unchained_client(base_url: &str) -> Result<DrandClient<UnchainedBeacon>, DrandClientError> {
    return new_client(&UnchainedScheme {}, base_url);
}

fn new_client<'a, S: Scheme<B>, B>(scheme: &'a S, base_url: &'a str) -> Result<DrandClient<'a, B>, DrandClientError> {
    let http_transport = HttpTransport {
        client: Client::new(),
    };
    let chain_info = fetch_chain_info(&http_transport, base_url)?;
    let client = DrandClient {
        transport: http_transport,
        chain_info,
        scheme,
        base_url,
    };
    return Ok(client);
}

#[derive(Error, Debug, PartialEq)]
enum DrandClientError {
    #[error("invalid round")]
    InvalidRound,
    #[error("invalid beacon")]
    InvalidBeacon,
    #[error("invalid chain info")]
    InvalidChainInfo,
    #[error("not responding")]
    NotResponding,
}

fn fetch_chain_info(transport: &HttpTransport, base_url: &str) -> Result<ChainInfo, DrandClientError> {
    let url = format!("{}/info", base_url);
    return match transport.fetch(&url) {
        Err(_) => Err(DrandClientError::NotResponding),
        Ok(body) => serde_json::from_str(&body)
            .map_err(|_| InvalidChainInfo)
    };
}

impl<'a, B> DrandClient<'a, B> where B: DeserializeOwned {
    fn latest_randomness(&self) -> Result<B, DrandClientError> {
        return self.fetch_beacon_tag("latest");
    }

    fn randomness(&self, round_number: u64) -> Result<B, DrandClientError> {
        if round_number == 0 {
            return Err(InvalidRound);
        }
        return self.fetch_beacon_tag(&format!("{}", round_number));
    }

    fn fetch_beacon_tag(&self, tag: &str) -> Result<B, DrandClientError> {
        let url = format!("{}/public/{}", self.base_url, tag);
        return match self.transport.fetch(&url) {
            Err(_) =>
                Err(DrandClientError::NotResponding),

            Ok(body) => match serde_json::from_str(&body) {
                Ok(json) => self.scheme.verify(&self.chain_info, json)
                    .map_err(|_| DrandClientError::InvalidBeacon),
                Err(e) => {
                    println!("{:?}", e);
                    Err(DrandClientError::InvalidBeacon)
                }
            }
        };
    }
}

#[derive(Error, Debug)]
pub enum SchemeError {
    #[error("invalid beacon")]
    InvalidBeacon,
    #[error("invalid scheme")]
    InvalidScheme,
    #[error("invalid chain info")]
    InvalidChainInfo,
}

trait Scheme<B> {
    fn supports(&self, scheme_id: &str) -> bool;
    fn verify(&self, info: &ChainInfo, beacon: B) -> Result<B, SchemeError>;
}

#[cfg(test)]
mod test {
    use crate::{DrandClientError, new_chained_client, new_unchained_client};
    use crate::DrandClientError::InvalidRound;

    #[test]
    fn request_chained_randomness_success() -> Result<(), DrandClientError> {
        let chained_url = "https://api.drand.sh";
        let client = new_chained_client(chained_url)?;
        let randomness = client.latest_randomness()?;
        assert!(randomness.round_number > 0);
        return Ok(());
    }

    #[test]
    fn request_unchained_randomness_success() -> Result<(), DrandClientError> {
        let unchained_url = "https://pl-eu.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf";
        let client = new_unchained_client(unchained_url)?;
        let randomness = client.latest_randomness()?;
        assert!(randomness.round_number > 0);
        return Ok(());
    }

    #[test]
    fn request_unchained_randomness_wrong_client_error() -> Result<(), DrandClientError> {
        let unchained_url = "https://pl-eu.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf";
        let client = new_chained_client(unchained_url)?;
        let result = client.latest_randomness();
        assert!(result.is_err());
        return Ok(());
    }

    #[test]
    fn request_chained_randomness_wrong_client_error() -> Result<(), DrandClientError> {
        let chained_url = "https://api.drand.sh";
        let client = new_unchained_client(chained_url)?;
        let result = client.latest_randomness();
        assert!(result.is_err());
        return Ok(());
    }

    #[test]
    fn request_genesis_returns_error() -> Result<(), DrandClientError> {
        let chained_url = "https://api.drand.sh";
        let client = new_chained_client(chained_url);
        let result = client?.randomness(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InvalidRound);
        return Ok(());
    }
}