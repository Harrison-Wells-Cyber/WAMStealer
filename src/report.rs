use serde::Serialize;
use serde_json::{json, Value};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub account_id: String,
    pub username: String,
    pub state: &'static str,
}

pub struct Failure {
    pub exit_code: u8,
    pub report: Value,
}

impl Failure {
    pub fn input(message: impl AsRef<str>) -> Self {
        Self {
            exit_code: 2,
            report: json!({"status": "input_error", "message": message.as_ref()}),
        }
    }

    pub fn runtime(hresult: i32) -> Self {
        Self {
            exit_code: 40,
            report: json!({"status": "runtime_error", "hresult": hex_code(hresult as u32)}),
        }
    }

    pub fn provider_unavailable() -> Self {
        Self {
            exit_code: 30,
            report: json!({"status": "account_provider_not_available"}),
        }
    }

    pub fn discovery(status: i32) -> Self {
        Self {
            exit_code: 31,
            report: json!({"status": "account_discovery_failed", "accountStatus": status}),
        }
    }

    pub fn account_not_found() -> Self {
        Self {
            exit_code: 33,
            report: json!({"status": "account_not_found"}),
        }
    }

    pub fn token(status: i32, provider_error: Option<(u32, Option<u32>)>) -> Self {
        let mut report = json!({"status": "token_error", "responseStatus": status});
        if let Some((code, length)) = provider_error {
            report["providerError"] = Value::String(hex_code(code));
            if let Some(length) = length.filter(|n| *n != 0) {
                report["providerMessageLength"] = json!(length);
            }
        }
        Self {
            exit_code: if status == 3 { 20 } else { 32 },
            report,
        }
    }
}

pub fn hex_code(code: u32) -> String {
    format!("0x{code:08X}")
}

pub fn accounts(client_id: &str, authority: &str, accounts: Vec<Account>) -> Value {
    json!({"status": "success", "operation": "account_enumeration",
        "clientId": client_id, "authority": authority,
        "accountCount": accounts.len(), "accounts": accounts})
}

pub fn token(
    resource_mode: bool,
    claims_requested: bool,
    token: &str,
    token_length: usize,
    hide: bool,
    account: Option<Account>,
) -> Value {
    let mut output = json!({"status": "success",
        "requestMode": if resource_mode { "resource" } else { "scope" },
        "claimsRequested": claims_requested, "tokenLength": token_length});
    if !hide {
        output["accessToken"] = Value::String(token.into());
    }
    if let Some(account) = account {
        output["account"] = json!(account);
    }
    output
}

/// Require exactly one match; duplicate usernames must never pick an arbitrary account.
pub fn unique_match<T>(matches: impl IntoIterator<Item = T>) -> Result<T, Failure> {
    let mut matches = matches.into_iter();
    let first = matches.next();
    let count = usize::from(first.is_some()) + matches.count();
    if count != 1 {
        return Err(Failure {
            exit_code: if count == 0 { 33 } else { 34 },
            report: json!({"status": if count == 0 { "account_not_found" } else { "account_ambiguous" },
                "matchCount": count}),
        });
    }
    Ok(first.expect("one match was counted"))
}
