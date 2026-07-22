//! Auth Arcana client-credentials provider for the dedicated KB reader.
//!
//! The provider is deliberately fixed to the `arcana-agent-kb-reader`
//! principal, the Scrutator LTM audience, and the read-only KB scope. It reads
//! the client secret from a restrictive regular file (normally a systemd
//! credential), mints short-lived Bearer JWTs, and serializes refreshes so a
//! process never creates a token stampede.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;

pub const KB_READER_CLIENT_ID: &str = "arcana-agent-kb-reader";
pub const SCRUTATOR_LTM_RESOURCE: &str = "urn:arcanada:scrutator:ltm";
pub const SCRUTATOR_LTM_SCOPE: &str = "kb:ltm.read";
const DEFAULT_TOKEN_URL: &str = "https://auth.arcanada.one/oidc/token";
const DEFAULT_CREDENTIAL_NAME: &str = "arcana-agent-kb-reader-client-secret";
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 300;
const MAX_SECRET_BYTES: u64 = 4096;

#[derive(Debug, thiserror::Error)]
pub enum AuthTokenError {
    #[error("Auth token configuration is invalid: {0}")]
    Configuration(String),
    #[error("client credential file is unavailable")]
    SecretFileUnavailable(#[source] std::io::Error),
    #[error("client credential path must be a regular non-symlink file")]
    SecretFileType,
    #[error("client credential file has insecure permissions: {mode:o}")]
    SecretFilePermissions { mode: u32 },
    #[error("client credential file owner does not match the running user")]
    SecretFileOwner,
    #[error("client credential file is empty or exceeds the size limit")]
    SecretFileSize,
    #[error("Auth token endpoint transport failed")]
    Transport(#[source] reqwest::Error),
    #[error("Auth token endpoint returned HTTP {0}")]
    EndpointStatus(u16),
    #[error("Auth token response is invalid: {0}")]
    InvalidResponse(&'static str),
}

#[async_trait]
pub trait BearerTokenProvider: Send + Sync {
    async fn bearer_token(&self) -> Result<SecretString, AuthTokenError>;

    async fn invalidate(&self) {}
}

#[derive(Clone)]
pub struct ClientCredentialsConfig {
    pub token_url: Url,
    pub client_id: String,
    pub secret_file: PathBuf,
    pub resource: String,
    pub scope: String,
    pub refresh_margin_seconds: u64,
}

impl ClientCredentialsConfig {
    /// Resolve the fixed KB-reader token profile and credential file from the
    /// process environment.
    ///
    /// # Errors
    /// Returns [`AuthTokenError::Configuration`] when the token URL or
    /// credential path is missing or malformed.
    pub fn from_env() -> Result<Self, AuthTokenError> {
        let token_url = std::env::var("ARCANA_AUTH_TOKEN_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_TOKEN_URL.to_owned());
        let secret_file = match std::env::var("ARCANA_KB_CLIENT_SECRET_FILE") {
            Ok(path) if !path.trim().is_empty() => PathBuf::from(path),
            _ => {
                let directory = std::env::var("CREDENTIALS_DIRECTORY").map_err(|_| {
                    AuthTokenError::Configuration(
                        "CREDENTIALS_DIRECTORY or ARCANA_KB_CLIENT_SECRET_FILE is required".into(),
                    )
                })?;
                PathBuf::from(directory).join(DEFAULT_CREDENTIAL_NAME)
            }
        };
        let token_url = Url::parse(&token_url)
            .map_err(|_| AuthTokenError::Configuration("token URL is malformed".into()))?;
        let approved = Url::parse(DEFAULT_TOKEN_URL)
            .map_err(|_| AuthTokenError::Configuration("approved token URL is invalid".into()))?;
        if token_url != approved {
            return Err(AuthTokenError::Configuration(
                "production token URL is not approved".into(),
            ));
        }
        Ok(Self {
            token_url,
            client_id: KB_READER_CLIENT_ID.into(),
            secret_file,
            resource: SCRUTATOR_LTM_RESOURCE.into(),
            scope: SCRUTATOR_LTM_SCOPE.into(),
            refresh_margin_seconds: 30,
        })
    }

    fn validate(&self) -> Result<(), AuthTokenError> {
        if self.client_id != KB_READER_CLIENT_ID
            || self.resource != SCRUTATOR_LTM_RESOURCE
            || self.scope != SCRUTATOR_LTM_SCOPE
        {
            return Err(AuthTokenError::Configuration(
                "KB reader identity, audience, and scope are fixed".into(),
            ));
        }
        if !self.secret_file.is_absolute() {
            return Err(AuthTokenError::Configuration(
                "client credential path must be absolute".into(),
            ));
        }
        if self.refresh_margin_seconds == 0
            || self.refresh_margin_seconds >= MAX_TOKEN_LIFETIME_SECONDS
        {
            return Err(AuthTokenError::Configuration(
                "refresh margin must be between 1 and 299 seconds".into(),
            ));
        }
        let secure_transport = self.token_url.scheme() == "https"
            || self.token_url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
        if !secure_transport {
            return Err(AuthTokenError::Configuration(
                "token URL must use HTTPS except on loopback".into(),
            ));
        }
        Ok(())
    }
}

struct CachedToken {
    token: SecretString,
    refresh_at: Instant,
}

pub struct ClientCredentialsTokenProvider {
    config: ClientCredentialsConfig,
    http: reqwest::Client,
    cached: Mutex<Option<CachedToken>>,
}

impl ClientCredentialsTokenProvider {
    /// Construct a provider after validating the fixed identity, audience,
    /// scope, transport, and refresh policy.
    ///
    /// # Errors
    /// Returns [`AuthTokenError::Configuration`] for a widened or malformed
    /// profile, or [`AuthTokenError::Transport`] if the HTTP client cannot be
    /// built.
    pub fn new(config: ClientCredentialsConfig) -> Result<Self, AuthTokenError> {
        config.validate()?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("arcana/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(AuthTokenError::Transport)?;
        Ok(Self {
            config,
            http,
            cached: Mutex::new(None),
        })
    }

    /// Construct the production provider from environment and systemd
    /// credential paths.
    ///
    /// # Errors
    /// Returns any configuration or HTTP-client error from [`Self::new`] or
    /// [`ClientCredentialsConfig::from_env`].
    pub fn try_from_env() -> Result<Arc<Self>, AuthTokenError> {
        Ok(Arc::new(Self::new(ClientCredentialsConfig::from_env()?)?))
    }

    fn read_secret(path: &Path) -> Result<SecretString, AuthTokenError> {
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(AuthTokenError::Configuration(
                "systemd credential file validation is currently supported only on Unix".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let descriptor = rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map_err(|err| {
                if err == rustix::io::Errno::LOOP {
                    AuthTokenError::SecretFileType
                } else {
                    AuthTokenError::SecretFileUnavailable(std::io::Error::from_raw_os_error(
                        err.raw_os_error(),
                    ))
                }
            })?;
            let file = File::from(descriptor);
            let metadata = file
                .metadata()
                .map_err(AuthTokenError::SecretFileUnavailable)?;
            if !metadata.file_type().is_file() {
                return Err(AuthTokenError::SecretFileType);
            }
            if metadata.len() == 0 || metadata.len() > MAX_SECRET_BYTES {
                return Err(AuthTokenError::SecretFileSize);
            }
            let mode = metadata.mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(AuthTokenError::SecretFilePermissions { mode });
            }
            if metadata.uid() != rustix::process::geteuid().as_raw() {
                return Err(AuthTokenError::SecretFileOwner);
            }
            let mut raw = String::new();
            file.take(MAX_SECRET_BYTES + 1)
                .read_to_string(&mut raw)
                .map_err(AuthTokenError::SecretFileUnavailable)?;
            if raw.len() as u64 > MAX_SECRET_BYTES {
                return Err(AuthTokenError::SecretFileSize);
            }
            let secret = raw.trim();
            if secret.is_empty() {
                return Err(AuthTokenError::SecretFileSize);
            }
            Ok(SecretString::from(secret.to_owned()))
        }
    }

    async fn mint(&self) -> Result<CachedToken, AuthTokenError> {
        let secret = Self::read_secret(&self.config.secret_file)?;
        let response = self
            .http
            .post(self.config.token_url.clone())
            .basic_auth(&self.config.client_id, Some(secret.expose_secret()))
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", self.config.scope.as_str()),
                ("resource", self.config.resource.as_str()),
            ])
            .send()
            .await
            .map_err(AuthTokenError::Transport)?;
        if !response.status().is_success() {
            return Err(AuthTokenError::EndpointStatus(response.status().as_u16()));
        }
        let body: TokenResponse = response
            .json()
            .await
            .map_err(|_| AuthTokenError::InvalidResponse("response is not valid JSON"))?;
        if body.token_type != "Bearer" {
            return Err(AuthTokenError::InvalidResponse("token_type must be Bearer"));
        }
        if body.access_token.is_empty() {
            return Err(AuthTokenError::InvalidResponse("access_token is empty"));
        }
        if body.expires_in <= self.config.refresh_margin_seconds
            || body.expires_in > MAX_TOKEN_LIFETIME_SECONDS
        {
            return Err(AuthTokenError::InvalidResponse(
                "expires_in is outside the accepted range",
            ));
        }
        if body
            .scope
            .as_deref()
            .is_some_and(|scope| scope != self.config.scope)
        {
            return Err(AuthTokenError::InvalidResponse(
                "scope does not match the requested scope",
            ));
        }
        let usable_for = body.expires_in - self.config.refresh_margin_seconds;
        Ok(CachedToken {
            token: SecretString::from(body.access_token),
            refresh_at: Instant::now() + Duration::from_secs(usable_for),
        })
    }
}

#[async_trait]
impl BearerTokenProvider for ClientCredentialsTokenProvider {
    async fn bearer_token(&self) -> Result<SecretString, AuthTokenError> {
        let mut cache = self.cached.lock().await;
        if let Some(cached) = cache
            .as_ref()
            .filter(|cached| Instant::now() < cached.refresh_at)
        {
            return Ok(cached.token.clone());
        }
        let minted = self.mint().await?;
        let token = minted.token.clone();
        *cache = Some(minted);
        Ok(token)
    }

    async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    scope: Option<String>,
}
