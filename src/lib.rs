mod chained;

use json::JsonValue;
use reqwest::{StatusCode};
use reqwest::blocking::Client;
use thiserror::Error;
use crate::chained::{ChainedBeacon, ChainedScheme};


#[derive(Error, Debug)]
enum HttpError {
    #[error("not found")]
    NotFound,
    #[error("unexpected")]
    Unexpected,
}

struct HttpTransport {
    client: Client,
}

impl HttpTransport {
    fn fetch(&self, url: &str) -> Result<String, HttpError> {
        let res = self.client.get(url)
            .send()
            .map_err(|_| HttpError::Unexpected)?;

        return match res.status() {
            StatusCode::OK => res.text()
                .map_err(|_| HttpError::Unexpected),

            StatusCode::NOT_FOUND =>
                Err(HttpError::NotFound),

            _ => Err(HttpError::Unexpected),
        };
    }
}

#[derive(Error, Debug)]
enum ParseError<E> {
    #[error("malformed input")]
    MalformedInput,
    #[error("did not parse")]
    DidNotParse(#[from] E),
}

struct JsonParser {}

impl JsonParser {
    fn parse<B: TryFrom<JsonValue>>(&self, input: &str) -> Result<B, ParseError<B::Error>> {
        return json::parse(input)
            .map_err(|_| ParseError::MalformedInput)
            .map(|json|
                B::try_from(json)
                    .map_err(|e| ParseError::DidNotParse(e))
            )?;
    }
}

struct DrandClient<'a, B> {
    scheme: &'a dyn Scheme<B>,
    transport: HttpTransport,
    parser: JsonParser,
    base_url: &'a str,
}

fn new_chained_client(base_url: &str) -> DrandClient<ChainedBeacon> {
    return DrandClient {
        scheme: &ChainedScheme {},
        transport: HttpTransport {
            client: reqwest::blocking::Client::new(),
        },
        parser: JsonParser {},
        base_url,
    };
}

#[derive(Error, Debug)]
enum DrandClientError {
    #[error("invalid round")]
    InvalidRound,
    #[error("invalid beacon")]
    InvalidBeacon,
    #[error("not responding")]
    NotResponding,
}

impl<'a, B> DrandClient<'a, B> where B: TryFrom<JsonValue> {
    fn latest_randomness(&self) -> Result<B, DrandClientError> {
        return self.fetch_beacon_tag("latest");
    }

    fn randomness(&self, round_number: u64) -> Result<B, DrandClientError> {
        return self.fetch_beacon_tag(&format!("{}", round_number));
    }

    fn fetch_beacon_tag(&self, tag: &str) -> Result<B, DrandClientError> {
        let url = format!("{}/public/{}", self.base_url, tag);
        return match self.transport.fetch(&url) {
            Err(_) =>
                Err(DrandClientError::NotResponding),

            Ok(beacon_str) => {
                self.parser.parse::<B>(&beacon_str)
                    .map_err(|_| DrandClientError::InvalidBeacon)
            }
        };
    }
}

#[derive(Error, Debug)]
enum SchemeError {
    #[error("invalid beacon")]
    InvalidBeacon,
    #[error("invalid scheme")]
    InvalidScheme,
    #[error("invalid chain info")]
    InvalidChainInfo,
}

struct ChainInfo {
    scheme_id: String,
    public_key: Vec<u8>,
    chain_hash: Vec<u8>,
    hash: Vec<u8>,
    group_hash: Vec<u8>,
    genesis_time: u64,
    period_seconds: usize,
    metadata: ChainInfoMetadata,
}

struct ChainInfoMetadata {
    beacon_id: String,
}

trait Scheme<B> {
    fn supports(&self, scheme_id: &str) -> bool;
    fn verify(&self, info: &ChainInfo, beacon: B) -> Result<B, SchemeError>;
}

#[cfg(test)]
mod test {
    use crate::{DrandClientError, new_chained_client};

    #[test]
    fn request_some_randomness() -> Result<(), DrandClientError> {
        let client = new_chained_client("https://api.drand.sh");
        let randomness = client.latest_randomness()?;
        assert!(randomness.round_number > 0);
        return Ok(());
    }
}