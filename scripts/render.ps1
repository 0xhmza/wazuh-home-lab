param(
    [string]$ConfigPath = ".\config\lab.example.json",
    [string]$CoreNetwork = ""
)

. (Join-Path $PSScriptRoot "common.ps1")

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedConfigPath = Resolve-LabPath -RepoRoot $repoRoot -Path $ConfigPath

$pyArgs = @(
    (Join-Path $repoRoot "app\render_lab.py"),
    "--config",
    $resolvedConfigPath,
    "--repo-root",
    $repoRoot
)

if ($CoreNetwork) {
    $pyArgs += @("--core-network", $CoreNetwork)
}

Invoke-LabPython -Arguments $pyArgs
