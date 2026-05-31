Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Inject Docker Desktop CLI into PATH on Windows when it is not already there.
$_dockerDesktopBin = "C:\Program Files\Docker\Docker\resources\bin"
if ((Test-Path $_dockerDesktopBin) -and ($env:PATH -notlike "*$_dockerDesktopBin*")) {
    $env:PATH = "$_dockerDesktopBin;$env:PATH"
}

# Inject the real Python 3 interpreter before the Windows Store alias stubs.
# The Store stubs (0-byte python.exe in WindowsApps) return exit code 9009 when
# no Store Python is installed, so we must ensure the real install comes first.
$_pythonCandidates = @(
    "$env:LOCALAPPDATA\Programs\Python\Python313",
    "$env:LOCALAPPDATA\Programs\Python\Python312",
    "$env:LOCALAPPDATA\Programs\Python\Python311",
    "C:\Python313", "C:\Python312", "C:\Python311"
)
foreach ($_pyDir in $_pythonCandidates) {
    if ((Test-Path "$_pyDir\python.exe") -and ($env:PATH -notlike "*$_pyDir*")) {
        $env:PATH = "$_pyDir;$_pyDir\Scripts;$env:PATH"
        break
    }
}

function Resolve-LabPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path $Path).Path
    }

    return (Resolve-Path (Join-Path $RepoRoot $Path)).Path
}

function Get-LabConfigObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    return Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
}

function Invoke-LabPython {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    if ($env:WAZUH_LAB_PYTHON) {
        & $env:WAZUH_LAB_PYTHON @Arguments
    }
    elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & (Get-Command python).Source @Arguments
    }
    elseif (Get-Command py -ErrorAction SilentlyContinue) {
        & (Get-Command py).Source -3 @Arguments
    }
    else {
        throw "Python 3.11 or newer is required. Set WAZUH_LAB_PYTHON if python is not on PATH."
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE."
    }
}

function Test-LabPortFree {
    param([int]$Port)
    try {
        $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
        return -not ($listeners | Where-Object { $_.Port -eq $Port })
    } catch {
        return $true
    }
}

# Returns a TCP port number in [10000, 60000] that:
#   - is recorded in generated/dashboard-port.txt across runs (so the URL stays stable), and
#   - is free, or already in use by an existing Wazuh dashboard container (which is fine - same lab).
# If the saved port is unusable, a new random free port is chosen and persisted.
function Get-WazuhDashboardPort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $portFile = Join-Path $RepoRoot "generated\dashboard-port.txt"
    $generatedDir = Split-Path -Parent $portFile
    if (-not (Test-Path $generatedDir)) {
        New-Item -ItemType Directory -Path $generatedDir -Force | Out-Null
    }

    $existing = 0
    if (Test-Path $portFile) {
        $raw = (Get-Content -Raw -Path $portFile -ErrorAction SilentlyContinue).Trim()
        if ($raw -match '^\d+$') {
            $candidate = [int]$raw
            if ($candidate -ge 10000 -and $candidate -le 65535) {
                $existing = $candidate
            }
        }
    }

    if ($existing -gt 0) {
        # If the port is free OR already bound by our own dashboard container, keep it.
        if (Test-LabPortFree -Port $existing) { return $existing }
        $bindingMatch = $false
        try {
            $dockerCheck = docker ps --filter "ancestor=wazuh/wazuh-dashboard" --format "{{.Ports}}" 2>$null
            if ($dockerCheck -and ($dockerCheck -match ":$existing->")) { $bindingMatch = $true }
        } catch {}
        if ($bindingMatch) { return $existing }
    }

    $rng = [System.Random]::new()
    for ($i = 0; $i -lt 200; $i++) {
        $candidate = 10000 + $rng.Next(0, 50001)  # 10000..60000
        if (Test-LabPortFree -Port $candidate) {
            $candidate | Out-File -FilePath $portFile -Encoding ASCII -NoNewline
            return $candidate
        }
    }
    throw "Could not find a free TCP port in [10000, 60000] for the Wazuh dashboard."
}

# Write/refresh vendor/wazuh-docker/single-node/docker-compose.override.yml so the
# dashboard service is exposed on the requested host port instead of 443.
function Write-WazuhDashboardOverride {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $singleNodeRoot = Join-Path $RepoRoot "vendor\wazuh-docker\single-node"
    if (-not (Test-Path $singleNodeRoot)) {
        # setup-core.ps1 hasn't run yet - nothing to override. up.ps1 will retry.
        return
    }
    $overridePath = Join-Path $singleNodeRoot "docker-compose.override.yml"
    $content = @"
# Auto-generated by Wazuh Home Lab - do not edit by hand.
# Remaps the dashboard host port from 443 to a free, non-privileged port.
services:
  wazuh.dashboard:
    ports:
      - "$Port`:5601"
"@
    Set-Content -Path $overridePath -Value $content -Encoding ASCII
}
