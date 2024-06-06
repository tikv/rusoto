use std::io::Error as IoError;
use std::io::ErrorKind;
use std::time::Duration;

use futures::StreamExt;
use hyper::client::HttpConnector;
use hyper::{Body, Client as HyperClient, Request, Uri};
use tokio::time;

/// Http client for use in a credentials provider.
#[derive(Debug, Clone)]
pub struct HttpClient {
    inner: HyperClient<HttpConnector>,
}

impl HttpClient {
    /// Create an http client.
    pub fn new() -> HttpClient {
        HttpClient {
            inner: HyperClient::new(),
        }
    }

    pub async fn get(
        &self,
        uri: Uri,
        timeout: Duration,
        ec2_metadata_token: Option<&str>,
    ) -> Result<String, IoError> {
        let mut builder = Request::get(uri);
        if let Some(token) = ec2_metadata_token {
            builder = builder.header("X-aws-ec2-metadata-token", token);
        }
        match builder.body(Body::empty()) {
            Ok(request) => self.request(request, timeout).await,
            Err(err) => Err(IoError::new(
                ErrorKind::Other,
                format!("Invalid request: {}", err),
            )),
        }
    }

    pub async fn request(&self, req: Request<Body>, timeout: Duration) -> Result<String, IoError> {
        match time::timeout(timeout, self.inner.request(req)).await {
            Err(_elapsed) => Err(IoError::new(ErrorKind::TimedOut, "Request timed out")),
            Ok(try_resp) => {
                let mut resp = try_resp.map_err(|err| {
                    IoError::new(ErrorKind::Other, format!("Response failed: {}", err))
                })?;
                let body = resp.body_mut();
                let mut text = vec![];
                while let Some(chunk) = body.next().await {
                    let chunk = chunk.map_err(|err| {
                        IoError::new(ErrorKind::Other, format!("Could not get chunk: {}", err))
                    })?;
                    text.extend(chunk.to_vec());
                }
                let body_str = String::from_utf8(text)
                    .map_err(|_| IoError::new(ErrorKind::InvalidData, "Non UTF-8 Data returned"))?;
                if resp.status().is_success() {
                    Ok(body_str)
                } else {
                    Err(IoError::new(
                        ErrorKind::Other,
                        format!("Response with error: {}: {}", resp.status(), body_str),
                    ))
                }
            }
        }
    }
}
