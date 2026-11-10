//! AWS API requests.
//!
//! Wraps the `hyper` library to send PUT, POST, DELETE and GET requests.

use std::env;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::io::Error as IoError;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures::{FutureExt, StreamExt};
use http::{HeaderMap, StatusCode};
use http1::header::{HeaderName, HeaderValue};
use http1::Method;
use http_body_util::BodyExt;
use hyper::Error as HyperError;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use hyper_util::client::legacy::connect::Connect;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Builder as HyperBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use lazy_static::lazy_static;
use tokio::time;

use log::Level::Debug;
use log::*;

use crate::signature::{Body, SignedRequest, SignedRequestPayload};
use crate::stream::ByteStream;
use crate::tls::HttpsConnector;

// Pulls in the statically generated rustc version.
include!(concat!(env!("OUT_DIR"), "/user_agent_vars.rs"));

// Use a lazy static to cache the default User-Agent header
// because it never changes once it's been computed.
lazy_static! {
    static ref DEFAULT_USER_AGENT: String = format!(
        "rusoto/{} rust/{} {}",
        env!("CARGO_PKG_VERSION"),
        RUST_VERSION,
        env::consts::OS
    );
}

/// Stores the response from a HTTP request.
pub struct HttpResponse {
    /// Status code of HTTP Request
    pub status: StatusCode,
    /// Contents of Response
    pub body: ByteStream,
    /// Response headers
    pub headers: HeaderMap<String>,
}

/// Stores the buffered response from a HTTP request.
#[derive(PartialEq)]
pub struct BufferedHttpResponse {
    /// Status code of HTTP Request
    pub status: StatusCode,
    /// Contents of Response
    pub body: Bytes,
    /// Response headers
    pub headers: HeaderMap<String>,
}

impl BufferedHttpResponse {
    ///! Best effort to turn response body into more readable &str.
    pub fn body_as_str(&self) -> &str {
        match std::str::from_utf8(&self.body) {
            Ok(msg) => msg,
            _ => "unknown error",
        }
    }
}

/// Best effort based Debug implementation to make generic error's body more readable.
impl fmt::Debug for BufferedHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match std::str::from_utf8(&self.body) {
            Ok(msg) => write!(
                f,
                "BufferedHttpResponse {{status: {:?}, body: {:?}, headers: {:?} }}",
                self.status, msg, self.headers
            ),
            _ => write!(
                f,
                "BufferedHttpResponse {{ status: {:?}, body: {:?}, headers: {:?} }}",
                self.status, self.body, self.headers
            ),
        }
    }
}

impl HttpResponse {
    /// Buffer the full response body in memory, resulting in a `BufferedHttpResponse`.
    pub async fn buffer(&mut self) -> Result<BufferedHttpResponse, HttpDispatchError> {
        let mut bytes = BytesMut::new();
        while let Some(try_chunk) = self.body.next().await {
            let chunk = try_chunk.map_err(|e| HttpDispatchError {
                message: format!("Error obtaining body: {}", e),
            })?;
            bytes.extend(chunk);
        }
        Ok(BufferedHttpResponse {
            status: self.status,
            headers: self.headers.clone(),
            body: bytes.freeze(),
        })
    }

    async fn from_hyper(hyper_response: HyperResponse<hyper::body::Incoming>) -> HttpResponse {
        let status = StatusCode::from_u16(hyper_response.status().as_u16()).unwrap();
        let headers = hyper_response
            .headers()
            .iter()
            .map(|(h, v)| {
                let value_string = v.to_str().unwrap().to_owned();
                (
                    http::header::HeaderName::from_bytes(h.as_str().as_bytes()).unwrap(),
                    value_string,
                )
            })
            .collect();
        let body = hyper_response
            .into_body()
            .into_data_stream()
            .map(|try_chunk| {
                try_chunk.map_err(|e| {
                    IoError::new(
                        io::ErrorKind::Other,
                        format!("Error obtaining chunk: {:?}", e),
                    )
                })
            });

        HttpResponse {
            status,
            headers,
            body: ByteStream::new(body),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
/// An error produced when sending the request, such as a timeout error.
pub struct HttpDispatchError {
    message: String,
}

impl HttpDispatchError {
    /// Construct a new HttpDispatchError for testing purposes
    pub fn new(message: String) -> HttpDispatchError {
        HttpDispatchError { message }
    }
}

impl Error for HttpDispatchError {}

impl fmt::Display for HttpDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<HyperError> for HttpDispatchError {
    fn from(err: HyperError) -> HttpDispatchError {
        // Hyper 1 Display omits the source; Debug retains the cause for diagnostics.
        HttpDispatchError {
            message: format!("{:?}", err),
        }
    }
}

impl From<IoError> for HttpDispatchError {
    fn from(err: IoError) -> HttpDispatchError {
        HttpDispatchError {
            message: err.to_string(),
        }
    }
}

/// Type returned from `dispatch` for a `DispatchSignedRequest` implementor
pub type DispatchSignedRequestFuture =
    Pin<Box<dyn Future<Output = Result<HttpResponse, HttpDispatchError>> + Send>>;

/// Trait for implementing HTTP Request/Response
pub trait DispatchSignedRequest {
    /// Dispatch Request, and then return a Response
    fn dispatch(
        &self,
        request: SignedRequest,
        timeout: Option<Duration>,
    ) -> DispatchSignedRequestFuture;
}

impl<D: DispatchSignedRequest> DispatchSignedRequest for Rc<D> {
    fn dispatch(
        &self,
        request: SignedRequest,
        timeout: Option<Duration>,
    ) -> DispatchSignedRequestFuture {
        D::dispatch(&*self, request, timeout)
    }
}

impl<D: DispatchSignedRequest> DispatchSignedRequest for Arc<D> {
    fn dispatch(
        &self,
        request: SignedRequest,
        timeout: Option<Duration>,
    ) -> DispatchSignedRequestFuture {
        D::dispatch(&*self, request, timeout)
    }
}

/// Http client for use with AWS services.
pub struct HttpClient<C = HttpsConnector<HttpConnector>> {
    inner: HyperClient<C, Body>,
    local_agent_prepend: Option<String>,
    local_agent_append: Option<String>,
}

impl HttpClient {
    /// Create a tls-enabled http client.
    pub fn new() -> Result<Self, TlsError> {
        Self::new_with_config(HttpConfig::new())
    }

    /// Create a tls-enabled http client.
    pub fn new_with_config(config: HttpConfig) -> Result<Self, TlsError> {
        #[cfg(feature = "native-tls")]
        let connector = HttpsConnector::new();

        #[cfg(feature = "rustls")]
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls::crypto::ring::default_provider())
            .map_err(|error| TlsError {
                message: error.to_string(),
            })?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();

        Ok(Self::from_connector_with_config(connector, config))
    }

    /// An alias for [`local_agent_prepend`] for backwards compatibility
    pub fn local_agent(&mut self, local_agent: String) {
        self.local_agent_prepend(local_agent)
    }

    /// Sets a local agent that is prepended to the default HTTP
    /// `User-Agent` used by Rusoto.
    pub fn local_agent_prepend(&mut self, local_agent: String) {
        self.local_agent_prepend = Some(local_agent)
    }

    /// Sets a local agent that is appended to the default HTTP
    /// `User-Agent` used by Rusoto.
    pub fn local_agent_append(&mut self, local_agent: String) {
        self.local_agent_append = Some(local_agent)
    }
}

impl<C> HttpClient<C>
where
    C: Connect + Clone + Send + Sync,
{
    /// Allows for a custom Hyper 1 connector to be used with the HttpClient.
    /// Connectors use `hyper_util::client::legacy::connect::Connect`.
    pub fn from_connector(connector: C) -> Self {
        let inner = HyperClient::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .build(connector);
        HttpClient {
            inner,
            local_agent_prepend: None,
            local_agent_append: None,
        }
    }

    /// Allows for a custom connector to be used with the HttpClient
    /// with extra configuration options
    pub fn from_connector_with_config(connector: C, config: HttpConfig) -> Self {
        let mut builder = HyperClient::builder(TokioExecutor::new());
        builder.pool_timer(TokioTimer::new());
        config
            .read_buf_size
            .map(|sz| builder.http1_read_buf_exact_size(sz));
        config
            .pool_idle_timeout
            .map(|t| builder.pool_idle_timeout(t));
        let inner = builder.build(connector);

        HttpClient {
            inner,
            local_agent_prepend: None,
            local_agent_append: None,
        }
    }

    /// Uses a Hyper 1 connector and a `hyper_util::client::legacy::Builder`.
    pub fn from_builder(builder: HyperBuilder, connector: C) -> Self {
        let inner = builder.build(connector);
        HttpClient {
            inner,
            local_agent_prepend: None,
            local_agent_append: None,
        }
    }
}

/// Configuration options for the HTTP Client
pub struct HttpConfig {
    read_buf_size: Option<usize>,
    pool_idle_timeout: Option<Duration>,
}

impl HttpConfig {
    /// Create a new HttpConfig
    pub fn new() -> HttpConfig {
        HttpConfig {
            read_buf_size: None,
            pool_idle_timeout: None,
        }
    }
    /// Sets the size of the read buffer for inbound data
    /// A larger buffer size might result in better performance
    /// by requiring fewer copies out of the socket buffer.
    pub fn read_buf_size(&mut self, sz: usize) {
        self.read_buf_size = Some(sz);
    }

    /// Set an timeout for idle sockets being kept-alive.
    /// Some AWS services, [like S3](https://aws.amazon.com/premiumsupport/knowledge-center/s3-socket-connection-timeout-error/)
    /// require this value to match the one configured at the server's level
    /// in order to avoid connection closed errors.
    pub fn pool_idle_timeout<D>(&mut self, timeout: D)
    where
        D: Into<Option<Duration>>,
    {
        self.pool_idle_timeout = timeout.into();
    }
}

impl Default for HttpConfig {
    /// Create a new HttpConfig. Same as HttpConfig::new().
    fn default() -> HttpConfig {
        HttpConfig::new()
    }
}

async fn http_client_dispatch<'a, C>(
    client: HyperClient<C, Body>,
    request: SignedRequest,
    timeout: Option<Duration>,
    user_agent: HeaderValue,
) -> Result<HttpResponse, HttpDispatchError>
where
    C: Connect + Send + Sync + Clone + 'static,
{
    let hyper_method = match request.method().as_ref() {
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "GET" => Method::GET,
        "HEAD" => Method::HEAD,
        "PATCH" => Method::PATCH,
        v => {
            return Err(HttpDispatchError {
                message: format!("Unsupported HTTP verb {}", v),
            });
        }
    };

    // translate the headers map to a format Hyper likes
    let mut hyper_headers = http1::HeaderMap::new();
    for h in request.headers().iter() {
        let header_name = match h.0.parse::<HeaderName>() {
            Ok(name) => name,
            Err(err) => {
                return Err(HttpDispatchError {
                    message: format!("error parsing header name: {}", err),
                });
            }
        };
        for v in h.1.iter() {
            let header_value = match HeaderValue::from_bytes(v) {
                Ok(value) => value,
                Err(err) => {
                    return Err(HttpDispatchError {
                        message: format!("error parsing header value: {}", err),
                    });
                }
            };
            hyper_headers.append(&header_name, header_value);
        }
    }

    // Add a default user-agent header if one is not already present.
    if !hyper_headers.contains_key("user-agent") {
        hyper_headers.insert("user-agent", user_agent);
    }

    let mut final_uri = format!(
        "{}://{}{}",
        request.scheme(),
        request.hostname(),
        request.canonical_path()
    );
    if !request.canonical_query_string().is_empty() {
        final_uri = final_uri + &format!("?{}", request.canonical_query_string());
    }

    if log_enabled!(Debug) {
        debug!(
            "Full request: \n method: {}\n final_uri: {}\nHeaders:\n",
            hyper_method, final_uri
        );
        for (h, v) in hyper_headers.iter() {
            debug!("{}:{:?}", h.as_str(), v);
        }
    }

    let http_request_builder = HyperRequest::builder().method(hyper_method).uri(final_uri);

    let try_http_request = if let Some(p) = request.payload {
        http_request_builder.body(p.into_body())
    } else {
        http_request_builder.body(SignedRequestPayload::Buffer(Bytes::new()).into_body())
    };

    let mut http_request = try_http_request.map_err(|err| HttpDispatchError {
        message: format!("error building request: {}", err),
    })?;

    *http_request.headers_mut() = hyper_headers;

    let f = client.request(http_request);

    let try_resp = match timeout {
        None => f.await,
        Some(duration) => match time::timeout(duration, f).await {
            Err(_e) => {
                return Err(HttpDispatchError {
                    message: "Timeout while dispatching request".to_owned(),
                })
            }
            Ok(try_req) => try_req,
        },
    };
    // Hyper-util Display omits connection and TLS causes; preserve them in Debug.
    let resp = try_resp.map_err(|e| HttpDispatchError {
        message: format!("Error during dispatch: {:?}", e),
    })?;
    Ok(HttpResponse::from_hyper(resp).await)
}

impl<C> DispatchSignedRequest for HttpClient<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    fn dispatch(
        &self,
        request: SignedRequest,
        timeout: Option<Duration>,
    ) -> DispatchSignedRequestFuture {
        let user_agent = build_user_agent(&self.local_agent_prepend, &self.local_agent_append);
        http_client_dispatch::<C>(self.inner.clone(), request, timeout, user_agent).boxed()
    }
}

/// Builds a [`HeaderValue`] using [`DEFAULT_USER_AGENT`] as a base string and,
/// optionally, prepending/appending additional strings, taking care to trim
/// whitespace.
fn build_user_agent(prepend: &Option<String>, append: &Option<String>) -> HeaderValue {
    let (pre, post) = (
        prepend.as_deref().unwrap_or(""),
        append.as_deref().unwrap_or(""),
    );
    let agent = format!("{} {} {}", pre, *DEFAULT_USER_AGENT, post)
        .trim()
        .parse();
    agent.unwrap_or_else(|_| DEFAULT_USER_AGENT.parse().unwrap())
}

#[derive(Debug, PartialEq)]
/// An error produced when the user has an invalid TLS client
pub struct TlsError {
    message: String,
}

impl Error for TlsError {}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::SignedRequest;
    use crate::Region;

    #[test]
    fn http_client_is_send_and_sync() {
        fn is_send_and_sync<T: Send + Sync>() {}

        is_send_and_sync::<HttpClient>();
    }

    #[test]
    fn custom_region_http() {
        let a_region = Region::Custom {
            endpoint: "http://localhost".to_owned(),
            name: "eu-west-3".to_owned(),
        };
        let request = SignedRequest::new("POST", "sqs", &a_region, "/");
        assert_eq!("http", request.scheme());
        assert_eq!("localhost", request.hostname());
    }

    #[test]
    fn custom_region_https() {
        let a_region = Region::Custom {
            endpoint: "https://localhost".to_owned(),
            name: "eu-west-3".to_owned(),
        };
        let request = SignedRequest::new("POST", "sqs", &a_region, "/");
        assert_eq!("https", request.scheme());
        assert_eq!("localhost", request.hostname());
    }

    #[test]
    fn custom_region_with_port() {
        let a_region = Region::Custom {
            endpoint: "https://localhost:8000".to_owned(),
            name: "eu-west-3".to_owned(),
        };
        let request = SignedRequest::new("POST", "sqs", &a_region, "/");
        assert_eq!("https", request.scheme());
        assert_eq!("localhost:8000", request.hostname());
    }

    #[test]
    fn custom_region_no_scheme() {
        let a_region = Region::Custom {
            endpoint: "localhost".to_owned(),
            name: "eu-west-3".to_owned(),
        };
        let request = SignedRequest::new("POST", "sqs", &a_region, "/");
        assert_eq!("https", request.scheme());
        assert_eq!("localhost", request.hostname());
    }

    #[test]
    fn from_io_error_preserves_error_message() {
        let io_error = ::std::io::Error::new(::std::io::ErrorKind::Other, "my error message");
        let error = HttpDispatchError::from(io_error);
        assert_eq!(error.to_string(), "my error message")
    }

    #[test]
    fn building_user_agents() {
        let base = format!("{}", *DEFAULT_USER_AGENT);
        assert_eq!(
            base.parse::<HeaderValue>().unwrap(),
            build_user_agent(&None, &None)
        );
        assert_eq!(
            format!("before {}", base).parse::<HeaderValue>().unwrap(),
            build_user_agent(&Some("before".to_string()), &None)
        );
        assert_eq!(
            format!("{} after", base).parse::<HeaderValue>().unwrap(),
            build_user_agent(&None, &Some("after".to_string()))
        );
    }

    async fn check_streamed_request_and_response(http2: bool) {
        use http_body_util::StreamBody;
        use hyper::body::Frame;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use std::convert::Infallible;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(|request: HyperRequest<hyper::body::Incoming>| async move {
                assert_eq!(request.method(), Method::PUT);
                assert_eq!(request.uri().path(), "/object");
                let data = request.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(data, "upload-body");
                let mut trailers = http1::HeaderMap::new();
                trailers.insert("x-checksum", HeaderValue::from_static("done"));
                let frames = vec![
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"first-"))),
                    Ok(Frame::data(Bytes::from_static(b"second"))),
                    Ok(Frame::trailers(trailers)),
                ];
                Ok::<_, Infallible>(
                    HyperResponse::builder()
                        .status(206)
                        .header("x-response", "present")
                        .header("trailer", "x-checksum")
                        .body(StreamBody::new(futures::stream::iter(frames)))
                        .unwrap(),
                )
            });
            let stream = TokioIo::new(stream);
            if http2 {
                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(stream, service)
                    .await
            } else {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(stream, service)
                    .await
            }
        });
        let mut builder = HyperClient::builder(TokioExecutor::new());
        builder.http2_only(http2).pool_timer(TokioTimer::new());
        let client = HttpClient::from_builder(builder, HttpConnector::new());
        let region = Region::Custom {
            name: "test".into(),
            endpoint,
        };
        let mut request = SignedRequest::new("PUT", "s3", &region, "/object");
        request.set_payload_stream(ByteStream::new(futures::stream::iter(vec![
            Ok(Bytes::from_static(b"upload-")),
            Ok(Bytes::from_static(b"body")),
        ])));
        let mut response = client
            .dispatch(request, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers.get("x-response").unwrap(), "present");
        assert_eq!(response.buffer().await.unwrap().body, "first-second");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn http1_streams_payload_and_response_frames() {
        check_streamed_request_and_response(false).await;
    }

    #[tokio::test]
    async fn http2_streams_payload_and_response_frames() {
        check_streamed_request_and_response(true).await;
    }

    #[tokio::test]
    async fn dispatch_timeout_covers_waiting_for_response() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let region = Region::Custom {
            name: "test".into(),
            endpoint: format!("http://{}", listener.local_addr().unwrap()),
        };
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            futures::future::pending::<()>().await;
        });
        let mut config = HttpConfig::new();
        config.read_buf_size(256 * 1024);
        config.pool_idle_timeout(Some(Duration::from_secs(1)));
        let client = HttpClient::new_with_config(config).unwrap();
        let request = SignedRequest::new("GET", "s3", &region, "/object");
        let error = client
            .dispatch(request, Some(Duration::from_millis(50)))
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "Timeout while dispatching request");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn dispatch_error_preserves_dns_failure_cause() {
        use hyper_util::client::legacy::connect::dns::Name;
        use std::net::SocketAddr;
        use std::task::{Context, Poll};
        use tower_service::Service;

        #[derive(Clone)]
        struct FailingResolver;

        impl Service<Name> for FailingResolver {
            type Response = std::iter::Empty<SocketAddr>;
            type Error = IoError;
            type Future = futures::future::Ready<Result<Self::Response, Self::Error>>;

            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _: Name) -> Self::Future {
                futures::future::ready(Err(IoError::other("sentinel DNS failure")))
            }
        }

        let client = HttpClient::from_connector(HttpConnector::new_with_resolver(FailingResolver));
        let region = Region::Custom {
            name: "test".into(),
            endpoint: "http://sentinel.invalid".into(),
        };
        let request = SignedRequest::new("GET", "s3", &region, "/object");
        let error = client
            .dispatch(request, Some(Duration::from_secs(5)))
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("sentinel DNS failure"),
            "{}",
            error
        );
    }

    #[tokio::test]
    async fn truncated_response_preserves_body_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let region = Region::Custom {
            name: "test".into(),
            endpoint: format!("http://{}", listener.local_addr().unwrap()),
        };
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 256];
            while !request.ends_with(b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buf[..read]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nshort",
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        let client = HttpClient::from_connector(HttpConnector::new());
        let request = SignedRequest::new("GET", "s3", &region, "/object");
        let mut response = client
            .dispatch(request, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        let error = response.buffer().await.err().unwrap();
        assert!(error.to_string().contains("IncompleteBody"), "{}", error);
        server.await.unwrap();
    }

    async fn check_https_certificate(trusted: bool, matching_name: bool) -> bool {
        use http_body_util::Full;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use tokio::net::TcpListener;

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = if matching_name {
            "localhost"
        } else {
            "127.0.0.1"
        };
        let endpoint = format!("https://{}:{}", host, listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
            if let Ok(stream) = acceptor.accept(stream).await {
                let service = service_fn(|_| async {
                    Ok::<_, std::convert::Infallible>(HyperResponse::new(Full::new(
                        Bytes::from_static(b"verified"),
                    )))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            }
        });
        #[cfg(feature = "native-tls")]
        let connector = {
            let mut tls = hyper_tls::native_tls::TlsConnector::builder();
            if trusted {
                tls.add_root_certificate(
                    hyper_tls::native_tls::Certificate::from_der(cert.der()).unwrap(),
                );
            }
            let mut http = HttpConnector::new();
            http.enforce_http(false);
            HttpsConnector::from((http, tls.build().unwrap().into()))
        };
        #[cfg(feature = "rustls")]
        let connector = {
            let mut roots = rustls::RootCertStore::empty();
            if trusted {
                roots.add(cert.der().clone()).unwrap();
            }
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_only()
                .enable_http1()
                .build()
        };
        let client = HttpClient::from_connector(connector);
        let region = Region::Custom {
            name: "test".into(),
            endpoint,
        };
        let request = SignedRequest::new("GET", "s3", &region, "/object");
        let result = client.dispatch(request, Some(Duration::from_secs(5))).await;
        let success = match result {
            Ok(mut response) => {
                assert_eq!(response.buffer().await.unwrap().body, "verified");
                true
            }
            Err(_) => false,
        };
        server.abort();
        let _ = server.await;
        success
    }

    #[tokio::test]
    async fn https_accepts_trusted_certificate() {
        assert!(check_https_certificate(true, true).await);
    }

    #[tokio::test]
    async fn https_rejects_untrusted_certificate() {
        assert!(!check_https_certificate(false, true).await);
    }

    #[tokio::test]
    async fn https_rejects_wrong_hostname() {
        assert!(!check_https_certificate(true, false).await);
    }
}
