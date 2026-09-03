//! `arcana login` — Auth Arcana sign-in via the OIDC device-authorization
//! grant, RFC 8628.
//!
//! The device grant, rather than a loopback authorization-code redirect,
//! because this CLI is normally used over SSH on a remote host: there is no
//! local browser to open and binding a callback port helps nobody. The user
//! reads a short code off the terminal and approves it wherever they already
//! have a browser. enables the matching grant on the provider.
//!
//! ## Fail-closed
//!
//! Every failure path here returns a process exit code with a sentence saying
//! what was wrong — never a panic, and never a partial success that leaves a
//! half-written credential behind. In particular, an identity provider that
//! does not offer the device grant is reported as exactly that, because at the
//! time of writing that is the live state of `auth.arcanada.*` until
//! is rolled out: discovery advertises no `device_authorization_endpoint`.

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Deserialize;

/// Default issuer. `ARCANA_AUTH_ISSUER` overrides it, which is what the
/// integration tests point at a mock provider.
const DEFAULT_ISSUER: &str = "https://auth.arcanada.ai";

/// The public client registered by. A CLI cannot hold a secret, so
/// this client is registered with `token_endpoint_auth_method: none`.
const CLIENT_ID: &str = "arcana";

/// Scopes requested. `offline_access` buys a refresh token, so the operator is
/// not sent back through a browser on every expiry.
const SCOPES: &str = "openid profile email offline_access";

/// Absolute ceiling on polling, independent of the provider's `expires_in`, so
/// a provider that reports an absurd lifetime cannot hang the CLI forever.
const MAX_POLL: Duration = Duration::from_secs(15 * 60);

/// Fallback poll interval when the provider omits one (RFC 8628 §3.2).
const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct Discovery {
    device_authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct DeviceAuth {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

/// What gets persisted. Deliberately NOT the whole token response — only what
/// a later command needs to authenticate.
#[derive(serde::Serialize)]
struct StoredCredentials {
    issuer: String,
    client_id: String,
    access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,
}

/// Normalise a configured issuer value, trimming a trailing slash so URL joins
/// stay predictable and falling back when the value is absent or blank.
///
/// Pure so it can be tested without setting a process-wide environment
/// variable, which parallel tests would race on.
fn resolve_issuer(configured: Option<&str>) -> String {
    configured
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .unwrap_or(DEFAULT_ISSUER)
        .trim_end_matches('/')
        .to_owned()
}

/// Resolve the issuer from the environment.
fn issuer() -> String {
    resolve_issuer(std::env::var("ARCANA_AUTH_ISSUER").ok().as_deref())
}

/// Directory credentials live in: the per-user XDG state home, the same place
/// the interactive session writes its audit log.
fn state_dir() -> PathBuf {
    xdg::BaseDirectories::with_prefix("arcana").map_or_else(
        |_| PathBuf::from(".arcana-state"),
        |base| base.get_state_home(),
    )
}

/// Path of the credential file.
#[must_use]
pub fn credentials_path() -> PathBuf {
    state_dir().join("credentials.json")
}

/// Entry point for `arcana login`. Returns a process exit code.
#[must_use]
pub fn run_login() -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("arcana login: failed to start async runtime: {err}");
            return 1;
        }
    };
    runtime.block_on(login_async())
}

async fn login_async() -> i32 {
    let issuer = issuer();
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            eprintln!("arcana login: could not build an HTTP client: {err}");
            return 1;
        }
    };

    let (device_endpoint, token_endpoint) = match discover(&client, &issuer).await {
        Ok(endpoints) => endpoints,
        Err(code) => return code,
    };

    let device = match request_device_code(&client, &device_endpoint).await {
        Ok(device) => device,
        Err(code) => return code,
    };

    announce(&device);

    poll_for_token(&client, &token_endpoint, &device, issuer).await
}

/// Fetch the discovery document and pull out the two endpoints the device
/// grant needs. `Err(code)` is a process exit code; the reason is already on
/// stderr.
async fn discover(client: &reqwest::Client, issuer: &str) -> Result<(String, String), i32> {
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let discovery: Discovery = match client.get(&discovery_url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(doc) => doc,
            Err(err) => {
                eprintln!(
                    "arcana login: {issuer} returned an unreadable discovery document: {err}"
                );
                return Err(1);
            }
        },
        Ok(resp) => {
            eprintln!(
                "arcana login: {discovery_url} returned HTTP {}. The identity provider is reachable but not serving OIDC discovery.",
                resp.status().as_u16()
            );
            return Err(1);
        }
        Err(err) => {
            eprintln!("arcana login: cannot reach {issuer}: {err}");
            return Err(1);
        }
    };

    let Some(device_endpoint) = discovery.device_authorization_endpoint else {
        // The live state of auth.arcanada.* until ARAS-0069 ships. Say so
        // precisely instead of failing with a generic transport error.
        eprintln!(
            "arcana login: {issuer} does not offer the device-authorization grant \
             (no `device_authorization_endpoint` in its discovery document), so there is \
             nothing for this command to talk to."
        );
        eprintln!(
            "arcana login: this is a capability of the identity provider, not of this CLI — \
             it has to be enabled there before sign-in can work."
        );
        return Err(2);
    };
    let Some(token_endpoint) = discovery.token_endpoint else {
        eprintln!("arcana login: {issuer} advertises no `token_endpoint`; cannot continue.");
        return Err(1);
    };
    Ok((device_endpoint, token_endpoint))
}

/// Ask the provider for a device code + user code.
async fn request_device_code(
    client: &reqwest::Client,
    device_endpoint: &str,
) -> Result<DeviceAuth, i32> {
    match client
        .post(device_endpoint)
        .form(&[("client_id", CLIENT_ID), ("scope", SCOPES)])
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(body) => Ok(body),
            Err(err) => {
                eprintln!("arcana login: device authorization returned an unreadable body: {err}");
                Err(1)
            }
        },
        Ok(resp) => {
            let status = resp.status().as_u16();
            let detail = resp.text().await.unwrap_or_default();
            eprintln!("arcana login: device authorization refused (HTTP {status}): {detail}");
            Err(1)
        }
        Err(err) => {
            eprintln!("arcana login: device authorization request failed: {err}");
            Err(1)
        }
    }
}

/// Print the code and where to enter it.
fn announce(device: &DeviceAuth) {
    println!("To sign in, open:\n\n    {}\n", device.verification_uri);
    println!("and enter the code:\n\n    {}\n", device.user_code);
    if let Some(complete) = device.verification_uri_complete.as_deref() {
        println!("Or open this link, which carries the code already:\n\n    {complete}\n");
    }
    println!("Waiting for approval — Ctrl-C to cancel.");
    let _ = std::io::stdout().flush();
}

/// Poll the token endpoint until the code is approved, declined, or expires.
async fn poll_for_token(
    client: &reqwest::Client,
    token_endpoint: &str,
    device: &DeviceAuth,
    issuer: String,
) -> i32 {
    let mut interval = Duration::from_secs(device.interval.unwrap_or(5).max(1));
    let budget = device
        .expires_in
        .map_or(MAX_POLL, |secs| Duration::from_secs(secs).min(MAX_POLL));
    let started = Instant::now();

    loop {
        if started.elapsed() >= budget {
            eprintln!(
                "arcana login: the code expired before it was approved. Run `arcana login` again."
            );
            return 1;
        }
        tokio::time::sleep(interval).await;

        let resp = match client
            .post(token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device.device_code),
                ("client_id", CLIENT_ID),
            ])
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                // A blip mid-poll is not a failed login; keep polling until the
                // budget runs out rather than discarding a pending approval.
                eprintln!("arcana login: poll failed ({err}); retrying");
                continue;
            }
        };

        let body: TokenResponse = match resp.json().await {
            Ok(body) => body,
            Err(err) => {
                eprintln!("arcana login: token endpoint returned an unreadable body: {err}");
                return 1;
            }
        };

        match body.error.as_deref() {
            // RFC 8628 §3.5 — still waiting for the human.
            Some("authorization_pending") => continue,
            // The provider is asking us to back off; obey it.
            Some("slow_down") => {
                interval += DEFAULT_INTERVAL;
                continue;
            }
            // RFC 8628 §3.5 specifies `expired_token`, but the provider in
            // front of us answers an expired device code with `invalid_grant`
            // — observed on a live run, where the operator saw the useless
            // "sign-in failed (invalid_grant): grant request is invalid"
            // instead of being told to ask for a new code. Both are handled,
            // because the spec says one thing and the deployment does another.
            Some("expired_token" | "invalid_grant") => {
                eprintln!(
                    "arcana login: the code expired or was already used. Run `arcana login` again for a fresh one."
                );
                return 1;
            }
            Some("access_denied") => {
                eprintln!("arcana login: the request was declined.");
                return 1;
            }
            Some(other) => {
                let detail = body
                    .error_description
                    .as_deref()
                    .unwrap_or("no description");
                eprintln!("arcana login: sign-in failed ({other}): {detail}");
                return 1;
            }
            None => {}
        }

        let Some(access_token) = body.access_token else {
            eprintln!("arcana login: the provider reported success but returned no access token.");
            return 1;
        };

        let credentials = StoredCredentials {
            issuer,
            client_id: CLIENT_ID.to_owned(),
            access_token,
            refresh_token: body.refresh_token,
            id_token: body.id_token,
            token_type: body.token_type.unwrap_or_else(|| "Bearer".to_owned()),
            expires_in: body.expires_in,
        };

        return match persist(&credentials) {
            Ok(path) => {
                // Never print the token itself — only where it went.
                println!("Signed in. Credentials stored at {}", path.display());
                0
            }
            Err(err) => {
                eprintln!("arcana login: signed in, but could not store the credentials: {err}");
                1
            }
        };
    }
}

/// Write credentials to the state dir with owner-only permissions.
///
/// The file is created `0600` BEFORE any secret reaches it — a token must
/// never exist on disk in a world-readable file, not even briefly.
fn persist(credentials: &StoredCredentials) -> std::io::Result<PathBuf> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("credentials.json");

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;

    // An existing file may predate the mode above, so restate it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    let json = serde_json::to_vec_pretty(credentials)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    file.write_all(&json)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::{resolve_issuer, DEFAULT_ISSUER};

    #[test]
    fn issuer_defaults_when_unset() {
        // Guards the default rather than assuming it: a wrong default would
        // silently send credentials to the wrong host.
        assert_eq!(resolve_issuer(None), DEFAULT_ISSUER);
    }

    #[test]
    fn issuer_override_drops_a_trailing_slash() {
        assert_eq!(
            resolve_issuer(Some("https://idp.example/")),
            "https://idp.example"
        );
    }

    #[test]
    fn blank_issuer_override_falls_back_to_the_default() {
        assert_eq!(resolve_issuer(Some("   ")), DEFAULT_ISSUER);
        assert_eq!(resolve_issuer(Some("")), DEFAULT_ISSUER);
    }
}
