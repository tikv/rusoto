use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use hyper::service;
use hyper::{Body, Method, Request, Response, Server, StatusCode};

#[tokio::main]
async fn main() {
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
    Server::bind(&listen_addr)
        .serve(service::make_service_fn(|_conn| async {
            Ok::<_, Infallible>(service::service_fn(|req| async {
                Ok::<_, Infallible>(handle(req).await)
            }))
        }))
        .await
        .unwrap();
}

const ROLE_JSON: &str = r#"{
  "Code" : "Success",
  "LastUpdated" : "2015-08-04T00:09:23Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "Access_key_id_value",
  "SecretAccessKey" : "Secret_access_key_value",
  "Token" : "AAAAA",
  "Expiration" : "2015-08-04T06:32:37Z"
}"#;

const TOKEN: &str = "toKEn";

const TOKEN_HEADER: &str = "X-aws-ec2-metadata-token";

fn check_token(req: &Request<Body>) -> bool {
    if let Some(v) = req.headers().get(TOKEN_HEADER) {
        return String::from_utf8_lossy(v.as_bytes()).as_ref() == TOKEN;
    }
    true
}

async fn handle(req: Request<Body>) -> Response<Body> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/latest/meta-data/iam/security-credentials/") => {
            if !check_token(&req) {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from("invalid token"))
                    .unwrap();
            }
            Response::new(Body::from("testrole"))
        }
        (&Method::GET, "/latest/meta-data/iam/security-credentials/testrole") => {
            if !check_token(&req) {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from("invalid token"))
                    .unwrap();
            }
            Response::new(Body::from(ROLE_JSON))
        }
        (&Method::PUT, "/latest/api/token") => {
            if !req
                .headers()
                .contains_key("X-aws-ec2-metadata-token-ttl-seconds")
            {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("missing header"))
                    .unwrap();
            }
            Response::new(Body::from(TOKEN))
        }
        _ => Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("unsupported"))
            .unwrap(),
    }
}
