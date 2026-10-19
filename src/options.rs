use std::{collections::BTreeMap, ffi::OsString, time::Duration};

use crate::{
    report::Failure, CAE_CLAIMS, DEFAULT_AUTHORITY, DEFAULT_CLIENT_ID, DEFAULT_SCOPE,
    RESERVED_SCOPES,
};

// Do not derive Debug: custom claims may contain sensitive data.
#[derive(Clone)]
pub struct Options {
    pub client_id: String,
    pub scope: String,
    pub resource: Option<String>,
    pub authority: String,
    pub claims: Option<String>,
    pub timeout: Duration,
    pub hide_token: bool,
    pub enumerate_accounts: bool,
    pub account_id: Option<String>,
    pub username: Option<String>,
    pub server: Option<String>,
    pub secret: Option<String>,
}

pub enum Command {
    Help,
    Run(Options),
}

pub struct RequestSpec {
    pub scope: String,
    pub properties: BTreeMap<&'static str, String>,
}

impl Options {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, Failure> {
        let mut args = args.into_iter();
        let mut options = Self {
            client_id: DEFAULT_CLIENT_ID.into(),
            scope: DEFAULT_SCOPE.into(),
            resource: None,
            authority: DEFAULT_AUTHORITY.into(),
            claims: None,
            timeout: Duration::from_secs(30),
            hide_token: false,
            enumerate_accounts: false,
            account_id: None,
            username: None,
            server: None,
            secret: None,
        };
        let mut scope_supplied = false;
        let mut cae = false;
        while let Some(arg) = args.next() {
            let arg = arg
                .into_string()
                .map_err(|_| Failure::input("Arguments must be valid Unicode."))?;
            match arg.as_str() {
                "-h" | "--help" => return Ok(Command::Help),
                "--cae" => cae = true,
                "--hide" => options.hide_token = true,
                "--enum" => options.enumerate_accounts = true,
                "--client-id" | "--scope" | "--resource" | "--authority" | "--account-id"
                | "--username" | "--claims-json" | "--timeout-seconds" | "--server"
                | "--secret" => {
                    let value = args
                        .next()
                        .ok_or_else(|| Failure::input(format!("Missing value for {arg}.")))?;
                    let value = value.into_string().map_err(|_| {
                        Failure::input(format!("Value for {arg} must be valid Unicode."))
                    })?;
                    if value.trim().is_empty() || value.starts_with("--") || value == "-h" {
                        return Err(Failure::input(format!("Missing value for {arg}.")));
                    }
                    if value.contains('\0') {
                        return Err(Failure::input(format!(
                            "Value for {arg} contains a NUL character."
                        )));
                    }
                    match arg.as_str() {
                        "--client-id" => options.client_id = value,
                        "--scope" => {
                            options.scope = value;
                            scope_supplied = true;
                        }
                        "--resource" => options.resource = Some(value),
                        "--authority" => options.authority = value,
                        "--account-id" => options.account_id = Some(value),
                        "--username" => options.username = Some(value),
                        "--server" => options.server = Some(value.trim_end_matches('/').to_string()),
                        "--secret" => options.secret = Some(value),
                        "--claims-json" => options.claims = Some(value),
                        "--timeout-seconds" => {
                            let seconds = value
                                .parse::<u64>()
                                .ok()
                                .filter(|n| (1..=300).contains(n))
                                .ok_or_else(|| {
                                    Failure::input("--timeout-seconds must be between 1 and 300.")
                                })?;
                            options.timeout = Duration::from_secs(seconds);
                        }
                        _ => unreachable!(),
                    }
                }
                _ => {
                    return Err(Failure::input(
                        "Unknown option. Use --help for supported options.",
                    ))
                }
            }
        }
        if cae && options.claims.is_some() {
            return Err(Failure::input(
                "Use either --cae or --claims-json, not both.",
            ));
        }
        if scope_supplied && options.resource.is_some() {
            return Err(Failure::input(
                "Use either --scope or --resource, not both.",
            ));
        }
        if options.account_id.is_some() && options.username.is_some() {
            return Err(Failure::input(
                "Use either --account-id or --username, not both.",
            ));
        }
        if options.enumerate_accounts
            && (options.account_id.is_some() || options.username.is_some())
        {
            return Err(Failure::input(
                "--enum cannot be combined with an account selector.",
            ));
        }
        if options.server.is_some() != options.secret.is_some() {
            return Err(Failure::input(
                "--server and --secret must be used together.",
            ));
        }
        if let Some(server) = options.server.as_deref() {
            if !(server.starts_with("https://") || server.starts_with("http://")) {
                return Err(Failure::input(
                    "--server must be an http:// or https:// URL.",
                ));
            }
            if options.enumerate_accounts
                || options.account_id.is_some()
                || options.username.is_some()
            {
                return Err(Failure::input(
                    "--server cannot be combined with --enum, --account-id, or --username.",
                ));
            }
        }
        if let Some(claims) = &options.claims {
            // Report location only, never echo the supplied challenge into diagnostics.
            let parsed: serde_json::Value = serde_json::from_str(claims).map_err(|e| {
                Failure::input(format!(
                    "Invalid claims JSON at line {}, column {}.",
                    e.line(),
                    e.column()
                ))
            })?;
            if !parsed.is_object() {
                return Err(Failure::input(
                    "--claims-json must have a JSON object root.",
                ));
            }
        }
        if cae {
            options.claims = Some(CAE_CLAIMS.into());
        }
        // Match the C client's 4096 UTF-16-code-unit buffer, including reserved scopes
        // and the terminating NUL. Rust byte length is incorrect for non-ASCII input.
        if options.resource.is_none()
            && options.scope.encode_utf16().count() + RESERVED_SCOPES.len() + 1 > 4096
        {
            return Err(Failure::input("scope is too long"));
        }
        Ok(Command::Run(options))
    }

    pub fn request_spec(&self) -> RequestSpec {
        let mut properties = BTreeMap::new();
        let scope = if let Some(resource) = &self.resource {
            properties.insert("resource", resource.clone());
            String::new()
        } else {
            properties.insert("wam_compat", "2.0".into());
            // Preserve the native executable's string semantics, including duplicates.
            format!("{}{RESERVED_SCOPES}", self.scope)
        };
        if let Some(claims) = &self.claims {
            properties.insert("claims", claims.clone());
        }
        RequestSpec { scope, properties }
    }
}
