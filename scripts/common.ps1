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
