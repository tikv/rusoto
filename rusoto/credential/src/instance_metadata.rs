//! The Credentials Provider for an AWS Resource's IAM Role.

use async_trait::async_trait;
use hyper::{Body, Request, Uri};
use std::time::Duration;

use crate::request::HttpClient;
use crate::{
    parse_credentials_from_aws_service, AwsCredentials, CredentialsError, ProvideAwsCredentials,
};

const AWS_CREDENTIALS_PROVIDER_IP: &str = "169.254.169.254";
const AWS_CREDENTIALS_PROVIDER_PATH: &str = "latest/meta-data/iam/security-credentials";
const AWS_API_TOKEN_PATH: &str = "latest/api/token";
const AWS_INSTANCE_METADATA_TOKEN_TTL_SECONDS: &str = "21600"; // 6 hours

/// The version of the Instance Metadata Service (IMDS) to use.
/// Ref: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
#[derive(Clone, Debug)]
pub enum IMDSVersion {
    /// Use IMDSv1.
    V1,
    /// Use IMDSv2.
    V2,
}

/// Provides AWS credentials from a resource's IAM role.
///
/// The provider has a default timeout of 30 seconds. While it should work well for most setups,
/// you can change the timeout using the `set_timeout` method.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
///
/// use rusoto_credential::InstanceMetadataProvider;
///
/// let mut provider = InstanceMetadataProvider::new();
/// // you can overwrite the default timeout like this:
/// provider.set_timeout(Duration::from_secs(60));
/// ```
///
/// The source location can be changed from the default of 169.254.169.254:
///
/// ```rust
/// use std::time::Duration;
///
/// use rusoto_credential::InstanceMetadataProvider;
///
/// let mut provider = InstanceMetadataProvider::new();
/// // you can overwrite the default endpoint like this:
/// provider.set_ip_addr_with_port("127.0.0.1", "8080");
/// ```
#[derive(Clone, Debug)]
pub struct InstanceMetadataProvider {
    client: HttpClient,
    timeout: Duration,
    metadata_ip_addr: String,
    ver: IMDSVersion,
}

impl InstanceMetadataProvider {
    /// Create a new provider with the given handle.
    /// Use IMDSv2 as default, as IMDSv1 may be disabled.
    pub fn new() -> Self {
        InstanceMetadataProvider {
            client: HttpClient::new(),
            timeout: Duration::from_secs(30),
            metadata_ip_addr: AWS_CREDENTIALS_PROVIDER_IP.to_string(),
            ver: IMDSVersion::V2,
        }
    }

    /// Set the timeout on the provider to the specified duration.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Allow overriding host and port of instance metadata service.
    pub fn set_ip_addr_with_port(&mut self, ip: &str, port: &str) {
        self.metadata_ip_addr = format!("{}:{}", ip, port);
    }

    /// Set the version of the Instance Metadata Service (IMDS) to use.
    pub fn set_version(&mut self, ver: IMDSVersion) {
        self.ver = ver;
    }
}

impl Default for InstanceMetadataProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProvideAwsCredentials for InstanceMetadataProvider {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        let token = match self.ver {
            IMDSVersion::V1 => None,
            IMDSVersion::V2 => Some(
                get_token(&self.client, self.timeout, &self.metadata_ip_addr)
                    .await
                    .map_err(|err| CredentialsError {
                        message: format!(
                            "Could not get token from metadata service: {}",
                            err.to_string()
                        ),
                    })?,
            ),
        };
        let role_name = get_role_name(
            &self.client,
            self.timeout,
            &self.metadata_ip_addr,
            token.as_deref(),
        )
        .await
        .map_err(|err| CredentialsError {
            message: format!("Could not get credentials from iam: {}", err.to_string()),
        })?;

        let cred_str = get_credentials_from_role(
            &self.client,
            self.timeout,
            &role_name,
            &self.metadata_ip_addr,
            token.as_deref(),
        )
        .await
        .map_err(|err| CredentialsError {
            message: format!("Could not get credentials from iam: {}", err.to_string()),
        })?;

        parse_credentials_from_aws_service(&cred_str)
    }
}

/// Gets a token from the EC2 Instance Metadata Service.
/// Ref: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html#instance-metadata-returns
async fn get_token(
    client: &HttpClient,
    timeout: Duration,
    ip_addr: &str,
) -> Result<String, CredentialsError> {
    let token_address = format!("http://{}/{}", ip_addr, AWS_API_TOKEN_PATH);
    let uri = match token_address.parse::<Uri>() {
        Ok(u) => u,
        Err(e) => {
            return Err(CredentialsError {
                message: format!("Invalid address to get token: {}: {:?}", token_address, e),
            })
        }
    };
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header(
            "X-aws-ec2-metadata-token-ttl-seconds",
            AWS_INSTANCE_METADATA_TOKEN_TTL_SECONDS,
        )
        .body(Body::empty())
        .map_err(|e| CredentialsError {
            message: format!("Could not create request for get token: {:?}", e),
        })?;
    Ok(client.request(req, timeout).await?)
}

/// Gets the role name to get credentials for using the IAM Metadata Service (169.254.169.254).
async fn get_role_name(
    client: &HttpClient,
    timeout: Duration,
    ip_addr: &str,
    token: Option<&str>,
) -> Result<String, CredentialsError> {
    let role_name_address = format!("http://{}/{}/", ip_addr, AWS_CREDENTIALS_PROVIDER_PATH);
    let uri = match role_name_address.parse::<Uri>() {
        Ok(u) => u,
        Err(e) => return Err(CredentialsError::new(e)),
    };

    Ok(client.get(uri, timeout, token).await?)
}

/// Gets the credentials for an EC2 Instances IAM Role.
async fn get_credentials_from_role(
    client: &HttpClient,
    timeout: Duration,
    role_name: &str,
    ip_addr: &str,
    token: Option<&str>,
) -> Result<String, CredentialsError> {
    let credentials_provider_url = format!(
        "http://{}/{}/{}",
        ip_addr, AWS_CREDENTIALS_PROVIDER_PATH, role_name
    );

    let uri = match credentials_provider_url.parse::<Uri>() {
        Ok(u) => u,
        Err(e) => return Err(CredentialsError::new(e)),
    };

    Ok(client.get(uri, timeout, token).await?)
}
