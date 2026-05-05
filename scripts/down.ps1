param(
    [string]$ConfigPath = ".\config\lab.example.json",
    [switch]$KeepCore
)

. (Join-Path $PSScriptRoot "common.ps1")

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedConfigPath = Resolve-LabPath -RepoRoot $repoRoot -Path $ConfigPath
$config = Get-LabConfigObject -ConfigPath $resolvedConfigPath

$overlayCompose = Join-Path $repoRoot "generated\lab-compose.yml"
if (Test-Path $overlayCompose) {
    Push-Location $repoRoot
    try {
        docker compose -f $overlayCompose -p $config.lab.lab_project_name down
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to stop the synthetic endpoint overlay."
        }
    }
    finally {
        Pop-Location
    }
}

if (-not $KeepCore) {
    $singleNodeRoot = Join-Path $repoRoot "vendor\wazuh-docker\single-node"
    if (Test-Path $singleNodeRoot) {
        Push-Location $singleNodeRoot
        try {
            docker compose -p $config.lab.core_project_name down
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to stop the Wazuh core stack."
            }
        }
        finally {
            Pop-Location
        }
    }
}

Write-Host "Requested stacks have been stopped."
