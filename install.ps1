<#
.SYNOPSIS
    Digger — Deterministic Blockchain Security Platform
    Install script for Windows (PowerShell)

.DESCRIPTION
    Downloads and installs the latest Digger CLI binary.
    Falls back to building from source if pre-built binary is unavailable.

.EXAMPLE
    irm https://raw.githubusercontent.com/digger-determsec/digger/main/install.ps1 | iex
#>

$ErrorActionPreference = "Stop"

$Repo = "digger-determsec/digger"
$Binary = "digger"
$InstallDir = if ($env:DIGGER_INSTALL_DIR) { $env:DIGGER_INSTALL_DIR } else { "$env:USERPROFILE\.digger\bin" }

function Write-Info    { param($msg) Write-Host "[digger] $msg" -ForegroundColor Blue }
function Write-Ok      { param($msg) Write-Host "[digger] $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[digger] $msg" -ForegroundColor Yellow }
function Write-Err     { param($msg) Write-Host "[digger] $msg" -ForegroundColor Red; exit 1 }

function Get-LatestVersion {
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
        return $release.tag_name -replace '^v', ''
    } catch {
        return $null
    }
}

function Build-FromSource {
    Write-Info "Attempting to build from source..."

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Err "Rust/cargo not found. Install from https://rustup.rs first, then retry."
    }

    $tmpdir = Join-Path $env:TEMP "digger-build-$(Get-Random)"
    New-Item -ItemType Directory -Path $tmpdir -Force | Out-Null

    Write-Info "Cloning to $tmpdir..."
    git clone --depth 1 "https://github.com/$Repo" $tmpdir 2>$null

    Write-Info "Building release binary (this may take a few minutes)..."
    Push-Location $tmpdir
    cargo build --release --bin digger 2>$null
    Pop-Location

    if (-not (Test-Path "$tmpdir\target\release\digger.exe")) {
        Remove-Item -Recurse -Force $tmpdir -ErrorAction SilentlyContinue
        Write-Err "Build failed. Install Rust from https://rustup.rs and retry."
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    Copy-Item "$tmpdir\target\release\digger.exe" "$InstallDir\digger.exe" -Force
    Remove-Item -Recurse -Force $tmpdir -ErrorAction SilentlyContinue
    Write-Ok "Built and installed from source."
}

function Install-Digger {
    Write-Host ""
    Write-Info "Installing Digger..."

    # Detect architecture
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { Write-Err "32-bit systems not supported" }
    $platform = "windows_$arch"
    Write-Info "Detected platform: $platform"

    # Get version
    $version = Get-LatestVersion
    if (-not $version) {
        Write-Warn "Could not fetch latest version"
        Write-Err "Please download manually from https://github.com/$Repo/releases"
    }
    Write-Info "Latest version: v$version"

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Try platform-specific name first, then generic name
    $filenames = @("digger-$platform.exe", "digger.exe", "digger")
    $downloaded = $false

    foreach ($filename in $filenames) {
        $url = "https://github.com/$Repo/releases/download/v$version/$filename"
        $dest = Join-Path $InstallDir "$Binary.exe"

        Write-Info "Trying $filename..."
        try {
            Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
            # Verify it's actually an executable (not an HTML error page)
            $bytes = [System.IO.File]::ReadAllBytes($dest)
            $isPe = $bytes.Length -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A  # MZ header
            if ($isPe) {
                $downloaded = $true
                Write-Ok "Downloaded $filename v$version"
                break
            } else {
                Remove-Item $dest -Force -ErrorAction SilentlyContinue
                Write-Warn "$filename is not a Windows executable, trying next..."
            }
        } catch {
            Remove-Item $dest -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $downloaded) {
        Write-Warn "No pre-built Windows binary available for v$version"
        Build-FromSource
    }

    # Add to PATH if not already there
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($currentPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$InstallDir;$currentPath", "User")
        $env:Path = "$InstallDir;$env:Path"
        Write-Info "Added $InstallDir to PATH"
        Write-Warn "Restart your terminal for PATH changes to take effect"
    }

    # Verify
    if (Test-Path (Join-Path $InstallDir "$Binary.exe")) {
        Write-Ok "Digger installed successfully!"
        Write-Host ""
        Write-Host "  Usage:" -ForegroundColor Green
        Write-Host "    digger scan --code '<solidity>' --lang solidity"
        Write-Host "    digger synthesize --code '<solidity>' --lang solidity"
        Write-Host "    digger benchmark"
        Write-Host ""
        Write-Host "  Dashboard (API + UI):" -ForegroundColor Green
        Write-Host "    digger-api"
        Write-Host "    Start-Process http://localhost:3000"
        Write-Host ""
    } else {
        Write-Err "Installation failed"
    }
}

Install-Digger
