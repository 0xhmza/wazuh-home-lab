param(
    [string]$ConfigPath = ".\config\lab.example.json",
    [switch]$SkipCoreSetup,
    [switch]$SkipCertificateGeneration
)

. (Join-Path $PSScriptRoot "common.ps1")

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedConfigPath = Resolve-LabPath -RepoRoot $repoRoot -Path $ConfigPath
$config = Get-LabConfigObject -ConfigPath $resolvedConfigPath

if (-not $SkipCoreSetup) {
    & (Join-Path $PSScriptRoot "setup-core.ps1") -ConfigPath $resolvedConfigPath -SkipCertificateGeneration:$SkipCertificateGeneration
}

& (Join-Path $PSScriptRoot "render.ps1") -ConfigPath $resolvedConfigPath

$singleNodeRoot = Join-Path $repoRoot "vendor\wazuh-docker\single-node"
if (-not (Test-Path $singleNodeRoot)) {
    throw "The Wazuh core stack has not been prepared. Run scripts/setup-core.ps1 first."
}

Push-Location $singleNodeRoot
try {
    docker compose -p $config.lab.core_project_name up -d
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start the Wazuh core stack."
    }
}
finally {
    Pop-Location
}

$overlayCompose = Join-Path $repoRoot "generated\lab-compose.yml"
Push-Location $repoRoot
try {
    docker compose -f $overlayCompose -p $config.lab.lab_project_name up -d --build
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start the synthetic endpoint overlay."
    }
}
finally {
    Pop-Location
}

Write-Host "Wazuh dashboard: https://localhost"
Write-Host "Username: admin"
Write-Host "Password: SecretPassword"
Write-Host "Synthetic agents will enroll as the manager becomes ready."
