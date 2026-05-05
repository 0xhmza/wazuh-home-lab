param(
    [string]$ConfigPath = ".\config\lab.example.json"
)

. (Join-Path $PSScriptRoot "common.ps1")

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedConfigPath = Resolve-LabPath -RepoRoot $repoRoot -Path $ConfigPath

Invoke-LabPython -Arguments @(
    (Join-Path $repoRoot "app\render_lab.py"),
    "--config",
    $resolvedConfigPath,
    "--repo-root",
    $repoRoot
)
