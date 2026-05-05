param(
    [string]$ConfigPath = ".\config\lab.example.json",
    [switch]$SkipCertificateGeneration
)

. (Join-Path $PSScriptRoot "common.ps1")

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedConfigPath = Resolve-LabPath -RepoRoot $repoRoot -Path $ConfigPath
$config = Get-LabConfigObject -ConfigPath $resolvedConfigPath

$wazuhVersion = [string]$config.wazuh.version
if (-not $wazuhVersion.StartsWith("v")) {
    $wazuhVersion = "v$wazuhVersion"
}

$vendorRoot = Join-Path $repoRoot "vendor"
$wazuhDockerRoot = Join-Path $vendorRoot "wazuh-docker"
$singleNodeRoot = Join-Path $wazuhDockerRoot "single-node"

if (-not (Test-Path $vendorRoot)) {
    New-Item -ItemType Directory -Path $vendorRoot | Out-Null
}

if (-not (Test-Path $wazuhDockerRoot)) {
    git clone --depth 1 --branch $wazuhVersion https://github.com/wazuh/wazuh-docker.git $wazuhDockerRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to clone wazuh/wazuh-docker."
    }
}
else {
    git -C $wazuhDockerRoot fetch --depth 1 origin "refs/tags/$wazuhVersion:refs/tags/$wazuhVersion"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to fetch Wazuh Docker tag $wazuhVersion."
    }

    git -C $wazuhDockerRoot checkout $wazuhVersion
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to checkout Wazuh Docker tag $wazuhVersion."
    }
}

$certificateMarker = Join-Path $singleNodeRoot "config\wazuh_indexer_ssl_certs\wazuh.manager.pem"
if (-not $SkipCertificateGeneration -and -not (Test-Path $certificateMarker)) {
    Push-Location $singleNodeRoot
    try {
        docker compose -f generate-indexer-certs.yml run --rm generator
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to generate Wazuh certificates."
        }
    }
    finally {
        Pop-Location
    }
}

Write-Host "Wazuh core stack is prepared in $singleNodeRoot"
