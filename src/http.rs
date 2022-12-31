use reqwest::blocking::Client;
use reqwest::StatusCode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("not found")]
    NotFound,
    #[error("unexpected")]
    Unexpected,
}

pub struct HttpTransport {
    pub client: Client,
}

impl HttpTransport {
    pub fn fetch(&self, url: &str) -> Result<String, HttpError> {
        let res = self
            .client
            .get(url)
            .send()
            .map_err(|_| HttpError::Unexpected)?;

        match res.status() {
            StatusCode::OK => res.text().map_err(|_| HttpError::Unexpected),

            StatusCode::NOT_FOUND => Err(HttpError::NotFound),

            _ => Err(HttpError::Unexpected),
        }
    }
}
