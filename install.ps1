<#
.SYNOPSIS
  Install the PAT single binary into a user directory and add it to PATH.

.DESCRIPTION
  This script only downloads / verifies / extracts / copies a binary. It never
  executes a downloaded payload and never runs remote code. When you invoke it
  with `irm <raw-url> | iex`, the only script being interpreted is this checked-
  in file; the binary is copied, not run.

  Two modes:
    -BuildFrom <repo> : build locally with the Go toolchain (default demo path)
    -ReleaseUrl <url> : download a release zip, verify -Sha256, copy pat.exe

.EXAMPLE
  # local build + install (recommended for the demo)
  .\install.ps1 -BuildFrom .

.EXAMPLE
  # remote one-liner (only runs THIS reviewed installer)
  irm https://raw.githubusercontent.com/literature95/PAT/main/install.ps1 | iex

.EXAMPLE
  # verified release artifact
  .\install.ps1 -ReleaseUrl https://example/pat_0.1.0_windows_amd64.zip -Sha256 <hex>
#>
[CmdletBinding()]
param(
    [string]$BuildFrom,
    [string]$ReleaseUrl,
    [string]$Sha256,
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\pat"
)

$ErrorActionPreference = 'Stop'
$tmp = Join-Path $env:TEMP ("pat-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

function Find-Go {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $local = Join-Path $env:LOCALAPPDATA 'go-toolchain\go\bin\go.exe'
    if (Test-Path $local) { return $local }
    return $null
}

function Add-ToUserPath([string]$dir) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    $parts = $userPath -split ';' | Where-Object { $_ }
    if ($parts -notcontains $dir) {
        [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $dir), 'User')
        Write-Host "[+] added to user PATH: $dir (restart the terminal)"
    } else {
        Write-Host "[=] already on user PATH: $dir"
    }
}

try {
    $exe = Join-Path $tmp 'pat.exe'

    if ($BuildFrom) {
        $go = Find-Go
        if (-not $go) { throw "Go toolchain not found. Install Go 1.22+ or pass -ReleaseUrl." }
        $repo = (Resolve-Path $BuildFrom).Path
        Write-Host "[*] building from $repo"
        Push-Location $repo
        try { & $go build -o $exe ./cmd/pat }
        finally { Pop-Location }
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) { throw "go build failed" }
    }
    elseif ($ReleaseUrl) {
        $zip = Join-Path $tmp 'pat.zip'
        Write-Host "[*] downloading release artifact"
        Invoke-WebRequest -Uri $ReleaseUrl -OutFile $zip -UseBasicParsing
        if ($Sha256) {
            $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
            if ($actual -ne $Sha256.ToLowerInvariant()) {
                throw "SHA256 mismatch: expected $Sha256, got $actual"
            }
            Write-Host "[+] checksum verified"
        } else {
            Write-Warning "No -Sha256 supplied: artifact was downloaded without checksum verification."
        }
        $expand = Join-Path $tmp 'expanded'
        Expand-Archive -Path $zip -DestinationPath $expand -Force
        $candidate = Get-ChildItem -Path $expand -Filter 'pat.exe' -Recurse | Select-Object -First 1
        if (-not $candidate) { throw "pat.exe not found in release archive" }
        $exe = $candidate.FullName
    }
    else {
        throw "Specify -BuildFrom <repo> or -ReleaseUrl <url>. See Get-Help .\install.ps1 -Full."
    }

    $target = Join-Path $InstallDir 'pat.exe'
    Copy-Item -LiteralPath $exe -Destination $target -Force
    Write-Host "[+] installed $target"
    Add-ToUserPath $InstallDir
    Write-Host "[+] done. Run: pat -c ""/help"""
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
