use std::{ffi::OsString, time::Duration};

use wamstealer::{
    options::{Command, Options},
    report::{self, Account, Failure},
    CAE_CLAIMS, DEFAULT_AUTHORITY, DEFAULT_CLIENT_ID, DEFAULT_SCOPE, RESERVED_SCOPES,
};
use serde_json::{json, Value};

fn parse(args: &[&str]) -> Result<Command, Failure> {
    Options::parse(args.iter().map(OsString::from))
}

fn options(args: &[&str]) -> Options {
    match parse(args) {
        Ok(Command::Run(options)) => options,
        Ok(Command::Help) => panic!("unexpected help"),
        Err(failure) => panic!("{}", failure.report),
    }
}

fn input_error(args: &[&str]) -> Failure {
    match parse(args) {
        Err(failure) => {
            assert_eq!(failure.exit_code, 2);
            assert_eq!(failure.report["status"], "input_error");
            failure
        }
        Ok(_) => panic!("expected invalid input"),
    }
}

#[test]
fn defaults_match_native_request() {
    let options = options(&[]);
    assert_eq!(options.client_id, DEFAULT_CLIENT_ID);
    assert_eq!(options.authority, DEFAULT_AUTHORITY);
    assert_eq!(options.timeout, Duration::from_secs(30));
    assert!(!options.hide_token);
    assert!(!options.enumerate_accounts);
    assert!(options.account_id.is_none());
    assert!(options.username.is_none());
    assert!(options.claims.is_none());
    let spec = options.request_spec();
    assert_eq!(spec.scope, format!("{DEFAULT_SCOPE}{RESERVED_SCOPES}"));
    assert_eq!(spec.properties.len(), 1);
    assert_eq!(spec.properties["wam_compat"], "2.0");
}

#[test]
fn resource_flow_has_empty_scope_and_no_wam_compat() {
    let spec = options(&["--resource", "https://graph.microsoft.com", "--cae"]).request_spec();
    assert!(spec.scope.is_empty());
    assert!(!spec.properties.contains_key("wam_compat"));
    assert_eq!(spec.properties["resource"], "https://graph.microsoft.com");
    assert_eq!(spec.properties["claims"], CAE_CLAIMS);
}

#[test]
fn scope_strings_and_repeated_options_match_native_semantics() {
    let spec = options(&["--scope", "old", "--scope", "User.Read openid profile"]).request_spec();
    assert_eq!(
        spec.scope,
        "User.Read openid profile openid offline_access profile"
    );
    assert!(!spec.properties.contains_key("resource"));
}

#[test]
fn custom_claims_are_validated_but_passed_verbatim() {
    let claims = " {\n\"access_token\":{\"example\":{\"essential\":true}}} \n";
    let spec = options(&["--claims-json", claims]).request_spec();
    assert_eq!(spec.properties["claims"], claims);
}

#[test]
fn incompatible_options_fail_in_either_order() {
    for args in [
        vec!["--scope", "x", "--resource", "y"],
        vec!["--resource", "y", "--scope", "x"],
        vec!["--claims-json", "{}", "--cae"],
        vec!["--cae", "--claims-json", "{}"],
        vec!["--account-id", "id", "--username", "user"],
        vec!["--username", "user", "--account-id", "id"],
        vec!["--enum", "--account-id", "id"],
        vec!["--username", "user", "--enum"],
    ] {
        input_error(&args);
    }
}

#[test]
fn timeout_bounds_and_invalid_values() {
    for value in ["1", "300"] {
        assert_eq!(
            options(&["--timeout-seconds", value]).timeout.as_secs(),
            value.parse::<u64>().unwrap()
        );
    }
    for value in [
        "0",
        "301",
        "-1",
        "1.5",
        "abc",
        "18446744073709551616",
        "30seconds",
    ] {
        input_error(&["--timeout-seconds", value]);
    }
}

#[test]
fn malformed_or_nonobject_claims_are_rejected_without_echoing() {
    for claims in [
        "[]",
        "null",
        "true",
        "42",
        "\"secret\"",
        "{private}",
        "{\"secret\":\"private\",}",
        "{} trailing",
        "{} {}",
    ] {
        let failure = input_error(&["--claims-json", claims]);
        let output = failure.report.to_string();
        assert!(!output.contains("secret"));
        assert!(!output.contains("private"));
    }
}

#[test]
fn missing_values_and_unknown_options_are_input_errors() {
    for arg in [
        "--client-id",
        "--scope",
        "--resource",
        "--authority",
        "--account-id",
        "--username",
        "--claims-json",
        "--timeout-seconds",
    ] {
        input_error(&[arg]);
        input_error(&[arg, ""]);
        input_error(&[arg, "  "]);
        input_error(&[arg, "--hide"]);
    }
    input_error(&["--bogus"]);
    input_error(&["positional"]);
}

#[test]
fn help_does_not_need_windows_or_authentication() {
    assert!(matches!(parse(&["--help"]), Ok(Command::Help)));
    assert!(matches!(parse(&["-h"]), Ok(Command::Help)));
}

#[test]
fn unicode_selectors_are_preserved_exactly() {
    let options = options(&[
        "--username",
        "Änne@example.com",
        "--authority",
        "organizations",
    ]);
    assert_eq!(options.username.as_deref(), Some("Änne@example.com"));
    let options = self::options(&["--account-id", "opaque/日本語:42"]);
    assert_eq!(options.account_id.as_deref(), Some("opaque/日本語:42"));
}

#[test]
fn scope_limit_counts_windows_utf16_units() {
    let limit = 4096 - RESERVED_SCOPES.len() - 1;
    let max_scope = "a".repeat(limit);
    options(&["--scope", &max_scope]);
    input_error(&["--scope", &(max_scope + "a")]);
    let unicode_scope = "🦀".repeat(limit / 2);
    options(&["--scope", &unicode_scope]);
    input_error(&["--scope", &(unicode_scope + "🦀")]);
}

#[test]
fn beacon_arguments_require_each_other_and_reject_account_selection() {
    input_error(&["--server", "https://example.com"]);
    input_error(&["--secret", "shared-secret"]);
    for extra in [
        vec!["--enum"],
        vec!["--username", "user@example.com"],
        vec!["--account-id", "id"],
    ] {
        let mut args = vec!["--server", "https://example.com", "--secret", "shared-secret"];
        args.extend(extra);
        input_error(&args);
    }
    input_error(&["--server", "ftp://example.com", "--secret", "shared-secret"]);
    let options = options(&["--server", "https://example.com/", "--secret", "shared-secret"]);
    assert_eq!(options.server.as_deref(), Some("https://example.com"));
    assert_eq!(options.secret.as_deref(), Some("shared-secret"));
}

#[test]
fn embedded_nuls_are_rejected_before_windows_calls() {
    input_error(&["--username", "alice\0bob"]);
    input_error(&["--claims-json", "{}\0"]);
}

#[cfg(unix)]
#[test]
fn invalid_unicode_is_an_input_error_not_a_panic() {
    use std::os::unix::ffi::OsStringExt;
    assert!(Options::parse([OsString::from_vec(vec![0xff])]).is_err());
    assert!(
        Options::parse([OsString::from("--username"), OsString::from_vec(vec![0xff])]).is_err()
    );
}

fn account() -> Account {
    Account {
        account_id: "opaque\\\"id".into(),
        username: "日本語\n@example.com".into(),
        state: "Connected",
    }
}

#[test]
fn account_json_matches_native_schema_and_escapes_unicode_and_controls() {
    let report = report::accounts("client", "organizations", vec![account()]);
    let encoded = serde_json::to_string(&report).unwrap();
    let decoded: Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        decoded,
        json!({"status":"success", "operation":"account_enumeration",
        "clientId":"client", "authority":"organizations", "accountCount":1,
        "accounts":[{"accountId":"opaque\\\"id", "username":"日本語\n@example.com", "state":"Connected"}]})
    );
    assert_eq!(encoded.lines().count(), 1);
    assert_eq!(
        report::accounts("client", "authority", vec![])["accounts"],
        json!([])
    );
}

#[test]
fn hide_removes_the_token_but_preserves_metadata() {
    let report = report::token(
        false,
        true,
        "DO_NOT_PRINT_THIS_TOKEN",
        23,
        true,
        Some(account()),
    );
    assert_eq!(report["requestMode"], "scope");
    assert_eq!(report["claimsRequested"], true);
    assert_eq!(report["tokenLength"], 23);
    assert!(report.get("accessToken").is_none());
    assert!(!report.to_string().contains("DO_NOT_PRINT_THIS_TOKEN"));
    assert!(report.get("account").is_some());
}

#[test]
fn visible_token_is_json_escaped_and_optional_account_is_omitted() {
    let report = report::token(true, false, "a\"b\\c\n", 7, false, None);
    assert_eq!(report["requestMode"], "resource");
    assert_eq!(report["accessToken"], "a\"b\\c\n");
    assert!(report.get("account").is_none());
    assert_eq!(
        serde_json::from_str::<Value>(&report.to_string()).unwrap(),
        report
    );
}

#[test]
fn username_selection_refuses_missing_and_ambiguous_matches() {
    assert_eq!(report::unique_match([42]).ok(), Some(42));
    let missing = report::unique_match::<usize>([]).err().unwrap();
    assert_eq!(missing.exit_code, 33);
    assert_eq!(
        missing.report,
        json!({"status":"account_not_found", "matchCount":0})
    );
    let ambiguous = report::unique_match([1, 2, 3]).err().unwrap();
    assert_eq!(ambiguous.exit_code, 34);
    assert_eq!(
        ambiguous.report,
        json!({"status":"account_ambiguous", "matchCount":3})
    );
}

#[test]
fn native_failure_codes_and_hresult_format_are_preserved() {
    assert_eq!(Failure::provider_unavailable().exit_code, 30);
    assert_eq!(Failure::discovery(1).exit_code, 31);
    assert_eq!(Failure::account_not_found().exit_code, 33);
    assert_eq!(Failure::token(3, None).exit_code, 20);
    for status in [1, 2, 4, 5] {
        assert_eq!(Failure::token(status, None).exit_code, 32);
    }
    let failure = Failure::runtime(0x80070102u32 as i32);
    assert_eq!(failure.exit_code, 40);
    assert_eq!(
        failure.report,
        json!({"status":"runtime_error", "hresult":"0x80070102"})
    );
    let failure = Failure::token(5, Some((0xCAA20003, Some("broker said no".into()))));
    assert_eq!(
        failure.report,
        json!({"status":"token_error", "responseStatus":5,
        "providerError":"0xCAA20003", "providerMessage":"broker said no"})
    );
    assert!(Failure::token(5, Some((0, Some(String::new()))))
        .report
        .get("providerMessage")
        .is_none());
}
