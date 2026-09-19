#Requires -Version 5.1
<#
.SYNOPSIS
    akey installer for Windows.

.DESCRIPTION
    Downloads the prebuilt akey release for this machine and installs it, or builds from
    source with cargo when asked to (or when no release matches).

.EXAMPLE
    irm https://raw.githubusercontent.com/coder-knock/akey/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Version v0.1.0 -Dir "$env:LOCALAPPDATA\Programs\akey" -Force

.PARAMETER Version
    Release tag to install (default: the latest release). Also $env:AKEY_VERSION.

.PARAMETER Dir
    Where to put akey.exe (default: $env:LOCALAPPDATA\Programs\akey). Also $env:AKEY_INSTALL_DIR.

.PARAMETER FromSource
    Build with cargo instead of downloading a release.

.PARAMETER Force
    Reinstall even if the requested version is already present.

.NOTES
    $env:AKEY_DIST_BASE overrides the download root, which is how the release workflow
    installs from the archive it just built. $env:AKEY_NONINTERACTIVE suppresses the
    PATH prompt, for scripted installs.
#>
[CmdletBinding()]
param(
    [string]$Version = $env:AKEY_VERSION,
    [string]$Dir = $env:AKEY_INSTALL_DIR,
    [switch]$FromSource,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'coder-knock/akey'
$Bin = 'akey'
# Overridable so the script can be tested against a local "release" directory.
$DistBase = if ($env:AKEY_DIST_BASE) { $env:AKEY_DIST_BASE } else { "https://github.com/$Repo/releases/download" }
if (-not $Version) { $Version = 'latest' }
if (-not $Dir) { $Dir = Join-Path $env:LOCALAPPDATA 'Programs\akey' }

function Say  { param([string]$Text) Write-Host $Text }
function Step { param([string]$Text) Write-Host "==> $Text" -ForegroundColor White }
function Warn { param([string]$Text) Write-Warning $Text }
function Die  { param([string]$Text) Write-Host "error: $Text" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------- platform

function Get-TargetTriple {
    $arch = $env:PROCESSOR_ARCHITECTURE
    # PROCESSOR_ARCHITEW6432 is set when a 32-bit host runs on 64-bit Windows.
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    switch ($arch) {
        'AMD64' { 'x86_64-pc-windows-msvc' }
        'ARM64' { 'aarch64-pc-windows-msvc' }
        default { $null }
    }
}

function Get-LatestTag {
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ 'User-Agent' = 'akey-installer' } -TimeoutSec 20
        return $release.tag_name
    } catch {
        return $null
    }
}

function Get-Sha256 {
    param([string]$Path)
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

# One download path for both the network and a local mirror. The local branch exists so the
# release workflow can point the installer at the archive it just built: `Invoke-WebRequest`
# cannot fetch `file://` under PowerShell 7 (.NET's HttpClient has no such scheme), so a
# directory path is the portable way to test this script offline.
function Get-RemoteFile {
    param([string]$Uri, [string]$OutFile)
    if ($Uri -match '^https?://') {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -TimeoutSec 120 -UseBasicParsing
    } else {
        Copy-Item -Path ($Uri -replace '^file:///', '' -replace '^file://', '') -Destination $OutFile -Force
    }
}

function Install-Binary {
    param([string]$Source)
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $dest = Join-Path $Dir "$Bin.exe"
    Step "installing to $dest"
    # Replace beside the destination then move: overwriting a running .exe fails on Windows.
    $staged = "$dest.new"
    Copy-Item -Force $Source $staged
    Move-Item -Force $staged $dest
    $installed = & $dest --version 2>$null
    if (-not $installed) { Die 'the installed binary does not run; please report this' }
    Say "installed $installed -> $dest"
}

# ---------------------------------------------------------------- release

function Install-FromRelease {
    param([string]$Triple, [string]$Tag)

    $asset = "$Bin-$Tag-$Triple.zip"
    $url = "$DistBase/$Tag/$asset"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("akey-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null

    try {
        Step "downloading $asset"
        try {
            Get-RemoteFile -Uri $url -OutFile (Join-Path $tmp $asset)
        } catch {
            Say "    no prebuilt binary at $url"
            return $false
        }

        # Verify before extracting. An unverifiable download is a failed download: silently
        # installing an unverified binary from the network is worse than stopping.
        Step 'verifying sha256'
        # Fetching the checksum is best-effort; comparing it is not. Keep the two apart so a
        # missing .sha256 warns instead of aborting, while a *mismatch* always stops. The
        # fetch is deliberately caught untyped: PS 5.1 reports a 404 as WebException and PS 7
        # as HttpResponseException, and naming one of them lets the other through as fatal.
        $expected = $null
        try {
            Get-RemoteFile -Uri "$url.sha256" -OutFile (Join-Path $tmp "$asset.sha256")
            $expected = ((Get-Content (Join-Path $tmp "$asset.sha256") -Raw).Trim() -split '\s+')[0].ToLower()
        } catch {
            Warn "no checksum published for $asset"
        }
        if ($expected) {
            $actual = Get-Sha256 (Join-Path $tmp $asset)
            if ($expected -ne $actual) {
                Die "checksum mismatch for $asset`n  expected $expected`n  actual   $actual`n" +
                    'This is either a corrupted download or a tampered one. Nothing was installed.'
            }
        }

        Step 'extracting'
        Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $tmp -Force
        $exe = Get-ChildItem -Path $tmp -Recurse -Filter "$Bin.exe" | Select-Object -First 1
        if (-not $exe) { Die 'the archive did not contain akey.exe' }
        Install-Binary $exe.FullName
        return $true
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- source

function Install-FromSource {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Die 'cargo not found. Install Rust from https://rustup.rs and re-run, or use a release build.'
    }
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("akey-build-" + [guid]::NewGuid().ToString('N'))
    Step 'building from source (this takes a couple of minutes)'
    $cargoArgs = @('install', '--git', "https://github.com/$Repo", '--locked', '--root', $root, $Bin)
    if ($Version -ne 'latest') { $cargoArgs += @('--tag', $Version) }
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { Die 'cargo install failed' }
    Install-Binary (Join-Path $root "bin\$Bin.exe")
}

# ---------------------------------------------------------------- PATH

function Ensure-OnPath {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    $entries = $userPath -split ';' | Where-Object { $_ }
    if ($entries -contains $Dir) { return }

    Say ''
    if ($env:AKEY_NONINTERACTIVE -or -not [Environment]::UserInteractive -or [Console]::IsInputRedirected) {
        # No one is there to answer, and a prompt would block forever. Say what to do instead.
        # AKEY_NONINTERACTIVE exists so a scripted install (CI, a container build, an agent)
        # can state that up front rather than depend on how its console happens to look.
        Say "$Dir is not on your user PATH. Add it with:"
        Say "  `$env:Path += ';$Dir'"
        return
    }

    Say "$Dir is not on your user PATH. Add it now?"
    $answer = Read-Host 'Add to PATH? [y/N]'
    if ($answer -match '^(y|yes)$') {
        $newPath = (@($entries) + $Dir) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Say 'Added. Open a new terminal for it to take effect.'
    } else {
        Say "Add it yourself, or run: `$env:Path += ';$Dir'"
    }
}

# ---------------------------------------------------------------- main

Say 'akey installer (Windows; x86_64 and arm64)'

if ($FromSource) {
    Install-FromSource
    exit 0
}

$triple = Get-TargetTriple
if (-not $triple) {
    Warn "unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
    Say 'Prebuilt binaries are published for x86_64 and arm64 Windows.'
    exit 2
}
Say "    platform: $triple"

if ($Version -eq 'latest') {
    Step 'looking up the latest release'
    $tag = Get-LatestTag
    if (-not $tag) {
        Warn 'could not reach GitHub to find the latest release'
        Install-FromSource
        exit 0
    }
    $Version = $tag
}
Say "    version: $Version"

$existing = Join-Path $Dir "$Bin.exe"
if ((-not $Force) -and (Test-Path $existing)) {
    $current = (& $existing --version 2>$null) -replace '^akey\s+', ''
    if ("v$current" -eq $Version -or $current -eq $Version.TrimStart('v')) {
        Say "akey $Version is already installed at $existing"
        Say 'Use -Force to reinstall.'
        exit 0
    }
    Say "    replacing $current with $Version"
}

if (-not (Install-FromRelease -Triple $triple -Tag $Version)) {
    Say ''
    Warn 'no usable prebuilt binary; falling back to a source build'
    Install-FromSource
}

Ensure-OnPath
Say ''
Say 'Next:'
Say "  akey init --remote <git-url> --device `$env:COMPUTERNAME    create a vault"
Say '  akey --help'
