#Requires -Version 5.1
<#
.SYNOPSIS
    Wazuh Home Lab - prerequisite checker and launcher.
.DESCRIPTION
    Validates every system requirement for the Wazuh Home Lab, then offers to
    start the full lab stack. Double-click START.bat, or run directly in PowerShell.
.PARAMETER ConfigPath
    Lab JSON config path. Defaults to .\config\lab.json if present, otherwise
    falls back to .\config\lab.example.json.
.PARAMETER CheckOnly
    Run prerequisite checks only; do not offer to launch the lab.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "",
    [switch]$CheckOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# Ensure box-drawing / Unicode chars render correctly in all Windows terminals
if ($Host.Name -eq 'ConsoleHost') {
    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
}

$RepoRoot = $PSScriptRoot

# Inject Docker Desktop CLI into PATH (mirrors scripts/common.ps1)
$_ddBin = "C:\Program Files\Docker\Docker\resources\bin"
if ((Test-Path $_ddBin) -and ($env:PATH -notlike "*$_ddBin*")) {
    $env:PATH = "$_ddBin;$env:PATH"
}

# ── State ─────────────────────────────────────────────────────────────────────
$Script:Passes = 0
$Script:Warns  = 0
$Script:Fails  = 0

# ── UI helpers ────────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       Wazuh Home Lab  ·  Prerequisites Check            ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor DarkYellow
    Write-Host ("  " + [string]([char]0x2500) * 55) -ForegroundColor DarkGray
}

function Write-Check {
    param(
        [string]$Label,
        [ValidateSet("PASS","WARN","FAIL","INFO","SKIP")][string]$Result,
        [string]$Detail = "",
        [string]$Fix    = ""
    )
    $icon  = switch ($Result) {
        "PASS" { " OK " }; "WARN" { "WARN" }; "FAIL" { "FAIL" }
        "INFO" { "INFO" }; "SKIP" { "SKIP" }
    }
    $color = switch ($Result) {
        "PASS" { "Green" }; "WARN" { "Yellow" }; "FAIL" { "Red" }
        "INFO" { "Cyan"  }; "SKIP" { "DarkGray" }
    }

    Write-Host -NoNewline "  ["
    Write-Host -NoNewline $icon -ForegroundColor $color
    Write-Host -NoNewline "]  "
    Write-Host -NoNewline ("{0,-38}  " -f $Label)
    if ($Detail) { Write-Host $Detail -ForegroundColor DarkGray } else { Write-Host "" }

    if ($Fix -and ($Result -eq "FAIL" -or $Result -eq "WARN")) {
        Write-Host "               Fix: $Fix" -ForegroundColor DarkGray
    }

    switch ($Result) {
        "PASS" { $Script:Passes++ }
        "WARN" { $Script:Warns++  }
        "FAIL" { $Script:Fails++  }
    }
}

function Format-Bytes([long]$Bytes) {
    if ($Bytes -ge 1GB) { return "{0:N1} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N0} MB" -f ($Bytes / 1MB) }
    return "$Bytes B"
}

function Test-PortFree([int]$Port) {
    try {
        $props = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        return -not ($props.GetActiveTcpListeners() | Where-Object { $_.Port -eq $Port })
    } catch { return $true }
}

function Get-PythonVersion {
    # Check known install dirs first (mirrors scripts/common.ps1 logic)
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python313",
        "$env:LOCALAPPDATA\Programs\Python\Python312",
        "$env:LOCALAPPDATA\Programs\Python\Python311",
        "C:\Python313", "C:\Python312", "C:\Python311"
    )
    foreach ($dir in $candidates) {
        $exe = Join-Path $dir "python.exe"
        if (Test-Path $exe) {
            try {
                $raw = & $exe --version 2>&1
                if ($raw -match "Python (\d+\.\d+)") { return $Matches[1] }
            } catch {}
        }
    }
    # py launcher
    if (Get-Command py -ErrorAction SilentlyContinue) {
        try {
            $raw = & py -3 --version 2>&1
            if ($raw -match "Python (\d+\.\d+)") { return $Matches[1] }
        } catch {}
    }
    # python / python3 on PATH — skip Windows Store stubs (they are tiny placeholder EXEs)
    foreach ($cmd in @("python", "python3")) {
        $c = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($c) {
            try {
                $item = Get-Item $c.Source -ErrorAction SilentlyContinue
                if ($item -and $item.Length -gt 10KB) {
                    $raw = & $c.Source --version 2>&1
                    if ($raw -match "Python (\d+\.\d+)") { return $Matches[1] }
                }
            } catch {}
        }
    }
    return $null
}

# ──────────────────────────────────────────────────────────────────────────────
Write-Banner
# ──────────────────────────────────────────────────────────────────────────────

# ═══ SECTION 1 — System ═══════════════════════════════════════════════════════
Write-Section "System"

# OS version
try {
    $osBuild   = [System.Environment]::OSVersion.Version.Build
    $osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
    if ($osBuild -ge 19041) {
        Write-Check "Operating system" PASS "$osCaption (build $osBuild)"
    } elseif ($osBuild -ge 17763) {
        Write-Check "Operating system" WARN "$osCaption (build $osBuild) — WSL 2 requires 19041+" `
            -Fix "Update Windows to version 20H1 or later via Windows Update."
    } else {
        Write-Check "Operating system" FAIL "$osCaption (build $osBuild) — minimum is build 19041" `
            -Fix "Update Windows 10 to version 20H1 (build 19041) or later."
    }
} catch {
    Write-Check "Operating system" WARN "Could not determine OS version"
}

# CPU cores
try {
    $cores = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors
    if ($cores -ge 4) {
        Write-Check "CPU logical cores" PASS "$cores cores"
    } else {
        Write-Check "CPU logical cores" WARN "$cores logical core(s) detected (4+ recommended)" `
            -Fix "The stack may be sluggish. Enable Hyper-Threading in BIOS if available."
    }
} catch {
    Write-Check "CPU logical cores" INFO "Could not determine"
}

# System RAM
try {
    $totalRam = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory
    $ramLabel  = Format-Bytes $totalRam
    if ($totalRam -ge 16GB) {
        Write-Check "System RAM" PASS $ramLabel
    } elseif ($totalRam -ge 12GB) {
        Write-Check "System RAM" WARN "$ramLabel installed (16 GB+ recommended for comfort)"
    } else {
        Write-Check "System RAM" FAIL "$ramLabel installed — Docker needs 10 GB; 16 GB total recommended" `
            -Fix "Add more RAM, or reduce agent count in the config to lower memory pressure."
    }
} catch {
    Write-Check "System RAM" INFO "Could not determine"
}

# Free disk space on the repo's drive
try {
    $drive     = Split-Path -Qualifier $RepoRoot
    $psDrive   = Get-PSDrive -Name ($drive.TrimEnd(':')) -ErrorAction Stop
    $freeBytes = $psDrive.Free
    $freeLabel = Format-Bytes $freeBytes
    if ($freeBytes -ge 60GB) {
        Write-Check "Free disk space" PASS "$freeLabel free on $drive"
    } elseif ($freeBytes -ge 30GB) {
        Write-Check "Free disk space" WARN "$freeLabel free on $drive (60 GB+ recommended)" `
            -Fix "Docker images and agent logs can consume up to 60 GB. Free more space before a full run."
    } else {
        Write-Check "Free disk space" FAIL "$freeLabel free on $drive — 60 GB minimum recommended" `
            -Fix "Free at least 60 GB on drive $drive before starting."
    }
} catch {
    Write-Check "Free disk space" INFO "Could not determine"
}

# Hardware virtualization
try {
    $proc = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $hvPresent = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent

    if ($proc.VirtualizationFirmwareEnabled -or $hvPresent) {
        # If a hypervisor is already running (e.g. Hyper-V / WSL 2 backend),
        # VirtualizationFirmwareEnabled may read False even though virt is on.
        Write-Check "Hardware virtualization" PASS "Enabled"
    } else {
        Write-Check "Hardware virtualization" FAIL "Disabled in firmware" `
            -Fix "Enable VT-x (Intel) or AMD-V (AMD) in your BIOS / UEFI settings."
    }
} catch {
    Write-Check "Hardware virtualization" WARN "Could not verify — confirm VT-x/AMD-V is on in BIOS"
}

# ═══ SECTION 2 — WSL 2 ════════════════════════════════════════════════════════
Write-Section "WSL 2"

$wslAvailable = $false
$wslHasDistro = $false

$wslExe = Get-Command wsl -ErrorAction SilentlyContinue
if ($wslExe) {
    $wslAvailable = $true
    Write-Check "WSL installed" PASS $wslExe.Source
} else {
    Write-Check "WSL installed" FAIL "wsl.exe not found on PATH" `
        -Fix "Open an elevated PowerShell and run: wsl --install  (then reboot)"
}

if ($wslAvailable) {

    # Default version
    try {
        $wslStatus = (wsl --status 2>&1) | Out-String
        if ($wslStatus -match "Default Version\s*:\s*2") {
            Write-Check "WSL 2 default version" PASS "Default is WSL 2"
        } elseif ($wslStatus -match "Default Version\s*:\s*1") {
            Write-Check "WSL 2 default version" WARN "Default is WSL 1" `
                -Fix "Run: wsl --set-default-version 2"
        } else {
            Write-Check "WSL 2 default version" INFO "Cannot determine — run: wsl --set-default-version 2"
        }
    } catch {
        Write-Check "WSL 2 default version" INFO "wsl --status unavailable on this build"
    }

    # Working default distro (simple echo test — avoids UTF-16 parse issues)
    try {
        $wslEcho = (wsl echo wsl_ok 2>&1) | Out-String
        if ($wslEcho -match "wsl_ok") {
            $wslHasDistro = $true
            Write-Check "WSL default distro" PASS "Responding"
        } else {
            Write-Check "WSL default distro" WARN "No responding default distro" `
                -Fix "Run: wsl --install  to add Ubuntu, then reboot."
        }
    } catch {
        Write-Check "WSL default distro" WARN "Could not communicate with WSL" `
            -Fix "Run: wsl --install  to add Ubuntu, then reboot."
    }

    # vm.max_map_count (required by Wazuh indexer)
    if ($wslHasDistro) {
        try {
            $rawVal = ((wsl -- sysctl -n vm.max_map_count 2>&1) | Out-String) -replace '\s', ''
            if ($rawVal -match '^\d+$') {
                $mapCount = [long]$rawVal
                if ($mapCount -ge 262144) {
                    Write-Check "vm.max_map_count" PASS "$mapCount"
                } else {
                    Write-Check "vm.max_map_count" FAIL "$mapCount — Wazuh indexer requires >= 262144" `
                        -Fix "In WSL: sudo sysctl -w vm.max_map_count=262144  |  To persist: echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf"
                }
            } else {
                Write-Check "vm.max_map_count" WARN "Could not read value — set it manually in WSL" `
                    -Fix "In WSL: sudo sysctl -w vm.max_map_count=262144"
            }
        } catch {
            Write-Check "vm.max_map_count" WARN "Check failed — set manually in WSL" `
                -Fix "In WSL: sudo sysctl -w vm.max_map_count=262144"
        }
    } else {
        Write-Check "vm.max_map_count" SKIP "Skipped — no WSL distro available"
    }
}

# ═══ SECTION 3 — Docker ═══════════════════════════════════════════════════════
Write-Section "Docker"

$dockerCliOk  = $false
$dockerDaemon = $false
$dockerInfo   = $null

# Docker Desktop installed?
$ddExe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
if (Test-Path $ddExe) {
    try {
        $ddVer = (Get-Item $ddExe).VersionInfo.ProductVersion
        Write-Check "Docker Desktop installed" PASS "v$ddVer"
    } catch {
        Write-Check "Docker Desktop installed" PASS "Found"
    }
} else {
    # Registry fallback
    $ddFound = $false
    $regRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($rp in $regRoots) {
        if ($ddFound) { break }
        try {
            Get-ChildItem $rp -ErrorAction SilentlyContinue | ForEach-Object {
                if (-not $ddFound -and ($_.GetValue("DisplayName") -like "*Docker Desktop*")) {
                    $ddVer   = $_.GetValue("DisplayVersion")
                    $ddFound = $true
                    Write-Check "Docker Desktop installed" PASS "v$ddVer"
                }
            }
        } catch {}
    }
    if (-not $ddFound) {
        Write-Check "Docker Desktop installed" FAIL "Not found" `
            -Fix "Download from: https://docs.docker.com/desktop/install/windows-install/"
    }
}

# Docker CLI accessible?
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCmd) {
    try {
        $cliVer = docker version --format "{{.Client.Version}}" 2>&1
        $dockerCliOk = $true
        if ($LASTEXITCODE -eq 0 -and $cliVer -match "\d") {
            Write-Check "Docker CLI" PASS "Client v$cliVer"
        } else {
            Write-Check "Docker CLI" PASS "Available"
        }
    } catch {
        $dockerCliOk = $true
        Write-Check "Docker CLI" PASS "Available"
    }
} else {
    Write-Check "Docker CLI" FAIL "docker not found on PATH" `
        -Fix "Install Docker Desktop — it registers the CLI in PATH automatically."
}

# Docker daemon running?
if ($dockerCliOk) {
    try {
        $rawInfo = docker info --format "{{json .}}" 2>&1
        $rawStr  = ($rawInfo | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $rawStr.StartsWith("{")) {
            $dockerInfo   = $rawStr | ConvertFrom-Json
            $dockerDaemon = $true
            Write-Check "Docker daemon" PASS "Running"
        } else {
            Write-Check "Docker daemon" FAIL "Not responding" `
                -Fix "Open Docker Desktop and wait for the whale icon in the system tray to go solid, then re-run."
        }
    } catch {
        Write-Check "Docker daemon" FAIL "Cannot connect to Docker daemon" `
            -Fix "Open Docker Desktop and wait for it to fully start, then re-run."
    }
} else {
    Write-Check "Docker daemon" SKIP "Skipped (Docker CLI not available)"
}

if ($dockerDaemon -and $dockerInfo) {

    # Linux containers mode
    try {
        $osType = $dockerInfo.OSType
        if ($osType -eq "linux") {
            Write-Check "Linux containers mode" PASS "Linux"
        } else {
            Write-Check "Linux containers mode" FAIL "Mode is '$osType' — must be Linux" `
                -Fix "Right-click the Docker Desktop tray icon → 'Switch to Linux containers...'"
        }
    } catch {
        Write-Check "Linux containers mode" WARN "Could not determine container OS type"
    }

    # Docker Compose plugin
    try {
        $composeVer = docker compose version --short 2>&1
        if ($LASTEXITCODE -eq 0 -and $composeVer -match "\d") {
            Write-Check "Docker Compose" PASS "v$composeVer"
        } else {
            Write-Check "Docker Compose" FAIL "docker compose plugin not available" `
                -Fix "Update Docker Desktop to a recent version (Compose v2 is bundled)."
        }
    } catch {
        Write-Check "Docker Compose" FAIL "docker compose plugin not available" `
            -Fix "Update Docker Desktop to a recent version (Compose v2 is bundled)."
    }

    # Docker memory allocation
    try {
        $memBytes = [long]$dockerInfo.MemTotal
        if ($memBytes -gt 0) {
            $memLabel = Format-Bytes $memBytes
            if ($memBytes -ge 10GB) {
                Write-Check "Docker memory allocation" PASS $memLabel
            } elseif ($memBytes -ge 6GB) {
                Write-Check "Docker memory allocation" WARN "$memLabel allocated (10 GB+ required)" `
                    -Fix "Docker Desktop → Settings → Resources → Memory → set to at least 10 GB."
            } else {
                Write-Check "Docker memory allocation" FAIL "$memLabel allocated (10 GB required)" `
                    -Fix "Docker Desktop → Settings → Resources → Memory → set to at least 10 GB."
            }
        } else {
            Write-Check "Docker memory allocation" INFO "Could not read allocation"
        }
    } catch {
        Write-Check "Docker memory allocation" INFO "Could not read allocation"
    }

} else {
    Write-Check "Linux containers mode"    SKIP "Skipped (daemon not running)"
    Write-Check "Docker Compose"           SKIP "Skipped (daemon not running)"
    Write-Check "Docker memory allocation" SKIP "Skipped (daemon not running)"
}

# ═══ SECTION 4 — Required Tools ═══════════════════════════════════════════════
Write-Section "Required Tools"

# Git
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    try {
        $gitRaw = git --version 2>&1
        $gitVer = if ($gitRaw -match "git version (\S+)") { $Matches[1] } else { "installed" }
        Write-Check "Git" PASS $gitVer
    } catch {
        Write-Check "Git" PASS "Installed"
    }
} else {
    Write-Check "Git" FAIL "Not found on PATH" `
        -Fix "Install from https://git-scm.com/download/win  (select 'Add Git to PATH' during setup)"
}

# Python 3.11+
$pyVer = Get-PythonVersion
if ($pyVer) {
    $parts = $pyVer -split '\.'
    $maj   = [int]$parts[0]
    $min   = [int]$parts[1]
    if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 11)) {
        Write-Check "Python 3.11+" PASS "v$pyVer"
    } else {
        Write-Check "Python 3.11+" FAIL "v$pyVer detected — 3.11+ required" `
            -Fix "Install Python 3.11+ from https://www.python.org/downloads/windows/  (check 'Add to PATH')"
    }
} else {
    Write-Check "Python 3.11+" FAIL "Not found" `
        -Fix "Install Python 3.11+ from https://www.python.org/downloads/windows/  (check 'Add to PATH')"
}

# ═══ SECTION 5 — Lab Configuration ═══════════════════════════════════════════
Write-Section "Lab Configuration"

# Config file resolution
$resolvedConfigPath = ""
if ($ConfigPath) {
    if (Test-Path $ConfigPath) {
        $resolvedConfigPath = $ConfigPath
        Write-Check "Config file" PASS $ConfigPath
    } else {
        Write-Check "Config file" FAIL "Not found: $ConfigPath" `
            -Fix "Check the path you passed with -ConfigPath."
    }
} else {
    $labJson    = Join-Path $RepoRoot "config\lab.json"
    $labExample = Join-Path $RepoRoot "config\lab.example.json"
    if (Test-Path $labJson) {
        $resolvedConfigPath = $labJson
        Write-Check "Config file" PASS "config\lab.json"
    } elseif (Test-Path $labExample) {
        $resolvedConfigPath = $labExample
        Write-Check "Config file" WARN "Using config\lab.example.json (default)" `
            -Fix "Run:  Copy-Item .\config\lab.example.json .\config\lab.json  then edit as desired."
    } else {
        Write-Check "Config file" FAIL "No config file found in .\config\" `
            -Fix "Run:  Copy-Item .\config\lab.example.json .\config\lab.json"
    }
}

# Read ui_port from config so the port check is accurate
$uiPort = 8765
if ($resolvedConfigPath -and (Test-Path $resolvedConfigPath)) {
    try {
        $cfg = Get-Content -Raw $resolvedConfigPath | ConvertFrom-Json
        if ($cfg.lab.ui_port) { $uiPort = [int]$cfg.lab.ui_port }
    } catch {}
}

# Port availability
$portChecks = @(
    @{ Port = 443;     Label = "Port 443  (dashboard HTTPS)"    }
    @{ Port = 9200;    Label = "Port 9200 (Wazuh indexer API)"  }
    @{ Port = 1514;    Label = "Port 1514 (agent events)"       }
    @{ Port = 1515;    Label = "Port 1515 (agent enrollment)"   }
    @{ Port = 55000;   Label = "Port 55000 (Wazuh REST API)"    }
    @{ Port = $uiPort; Label = "Port $uiPort (generator UI)"    }
)
foreach ($p in $portChecks) {
    if (Test-PortFree $p.Port) {
        Write-Check $p.Label PASS "Free"
    } else {
        Write-Check $p.Label WARN "In use — may conflict" `
            -Fix "Find and stop the process using port $($p.Port), or this may already be a running lab instance."
    }
}

# ═══ SECTION 6 — Previous Run State ══════════════════════════════════════════
Write-Section "Previous Run State"

$vendorPath = Join-Path $RepoRoot "vendor\wazuh-docker"
if (Test-Path $vendorPath) {
    Write-Check "wazuh-docker vendor" INFO "Already cloned — setup-core will update to configured tag"
} else {
    Write-Check "wazuh-docker vendor" INFO "Not cloned yet — will be cloned on first run"
}

$certMarker = Join-Path $RepoRoot "vendor\wazuh-docker\single-node\config\wazuh_indexer_ssl_certs\wazuh.manager.pem"
if (Test-Path $certMarker) {
    Write-Check "TLS certificates" INFO "Already generated"
} else {
    Write-Check "TLS certificates" INFO "Will be generated on first run (adds ~1-2 min)"
}

$generatedCompose = Join-Path $RepoRoot "generated\lab-compose.yml"
if (Test-Path $generatedCompose) {
    Write-Check "Generated overlay compose" INFO "Present from a previous run"
} else {
    Write-Check "Generated overlay compose" INFO "Will be created by renderer"
}

# ═══ Summary ══════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host ("  " + [string]([char]0x2550) * 58) -ForegroundColor DarkGray
Write-Host ""
Write-Host -NoNewline "  Results:  "
Write-Host -NoNewline "$($Script:Passes) passed  " -ForegroundColor Green

if ($Script:Warns -gt 0) {
    Write-Host -NoNewline "$($Script:Warns) warning(s)  " -ForegroundColor Yellow
} else {
    Write-Host -NoNewline "0 warnings  " -ForegroundColor DarkGray
}

if ($Script:Fails -gt 0) {
    Write-Host "$($Script:Fails) failed" -ForegroundColor Red
} else {
    Write-Host "0 failed" -ForegroundColor DarkGray
}
Write-Host ""

if ($Script:Fails -gt 0) {
    Write-Host "  Fix all items marked [FAIL] before starting the lab." -ForegroundColor Red
    Write-Host ""
    exit 1
}

if ($CheckOnly) {
    if ($Script:Warns -gt 0) {
        Write-Host "  Prerequisite check complete — review warnings above." -ForegroundColor Yellow
    } else {
        Write-Host "  All prerequisites satisfied." -ForegroundColor Green
    }
    Write-Host ""
    exit 0
}

if (-not $resolvedConfigPath) {
    Write-Host "  Cannot launch: no config file resolved." -ForegroundColor Red
    Write-Host ""
    exit 1
}

# ═══ Launch ═══════════════════════════════════════════════════════════════════
if ($Script:Warns -gt 0) {
    Write-Host "  Prerequisites met with warnings. Review the items above." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "  How should synthetic endpoints connect to Wazuh?" -ForegroundColor White
Write-Host ""
Write-Host "    [1]  Ghost mode       — one lightweight Python process, no extra Docker containers" -ForegroundColor Cyan
Write-Host "         (recommended for most machines: fast, low memory)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    [2]  Container mode   — one wazuh-agent Docker container per endpoint" -ForegroundColor White
Write-Host "         (original behaviour: more realistic, higher resource usage)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    [3]  Skip             — exit without starting" -ForegroundColor DarkGray
Write-Host ""

$modeChoice = ""
while ($modeChoice -notin @("1","2","3")) {
    try {
        $modeChoice = (Read-Host "  Enter 1, 2, or 3").Trim()
    } catch {
        $modeChoice = "3"
    }
    if ($modeChoice -notin @("1","2","3")) {
        Write-Host "  Please enter 1, 2, or 3." -ForegroundColor Yellow
    }
}

if ($modeChoice -eq "3") {
    Write-Host ""
    Write-Host "  Skipped. Run .\scripts\up.ps1 -ConfigPath $resolvedConfigPath when ready." -ForegroundColor DarkGray
    Write-Host ""
} else {
    $chosenMode = if ($modeChoice -eq "1") { "ghost" } else { "container" }
    $modeLabel  = if ($modeChoice -eq "1") { "Ghost mode (lightweight)" } else { "Container mode (full)" }

    Write-Host ""
    Write-Host "  Starting Wazuh lab in $modeLabel — this may take a few minutes on first run..." -ForegroundColor Cyan
    Write-Host ""

    try {
        & (Join-Path $RepoRoot "scripts\up.ps1") -ConfigPath $resolvedConfigPath -AgentMode $chosenMode
    } catch {
        Write-Host ""
        Write-Host "  [FAIL] Lab failed to start: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        exit 1
    }

    Write-Host ""
    Write-Host ("  " + [string]([char]0x2550) * 58) -ForegroundColor DarkGray
    Write-Host "  Dashboard : https://localhost" -ForegroundColor Green
    Write-Host "  Username  : admin" -ForegroundColor Green
    Write-Host "  Password  : SecretPassword" -ForegroundColor Green
    Write-Host "  Generator : http://localhost:$uiPort" -ForegroundColor Green
    Write-Host ("  " + [string]([char]0x2550) * 58) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Agents enroll 30-90 s after the manager is ready." -ForegroundColor DarkGray
    Write-Host "  Check Agent management → Summary in the dashboard." -ForegroundColor DarkGray
    Write-Host "  Run .\scripts\diagnose.ps1 to verify the full pipeline." -ForegroundColor DarkGray
    Write-Host ""
}
