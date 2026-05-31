param(
    [string]$ConfigPath = ".\config\lab.example.json",
    [string]$CoreNetwork = "",
    [int]$DashboardPort = 0
)

. (Join-Path $PSScriptRoot "common.ps1")

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedConfigPath = Resolve-LabPath -RepoRoot $repoRoot -Path $ConfigPath

if ($DashboardPort -le 0) {
    # Called standalone - pick or reuse the persisted dashboard port.
    $DashboardPort = Get-WazuhDashboardPort -RepoRoot $repoRoot
}

$pyArgs = @(
    (Join-Path $repoRoot "app\render_lab.py"),
    "--config",
    $resolvedConfigPath,
    "--repo-root",
    $repoRoot,
    "--dashboard-port",
    "$DashboardPort"
)

if ($CoreNetwork) {
    $pyArgs += @("--core-network", $CoreNetwork)
}

Invoke-LabPython -Arguments $pyArgs
