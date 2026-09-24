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
    git -C $wazuhDockerRoot fetch --depth 1 origin "refs/tags/${wazuhVersion}:refs/tags/${wazuhVersion}"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to fetch Wazuh Docker tag $wazuhVersion."
    }

    git -C $wazuhDockerRoot checkout $wazuhVersion
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to checkout Wazuh Docker tag $wazuhVersion."
    }
}

# ── Patch the manager's authd config so a re-enrolling agent name replaces the
# existing record IMMEDIATELY. The stock wazuh-docker config keeps authd's
# default force policy (only replace an agent after it has been disconnected
# ~1h), which leaves every synthetic endpoint stuck "Disconnected" whenever the
# generator / ghost-sender container restarts and re-enrolls — and silently
# drops all of their events. A `git checkout` of the pinned tag reverts this
# file, so we re-apply the patch on every setup-core run (idempotent).
$managerConf = Join-Path $singleNodeRoot "config\wazuh_cluster\wazuh_manager.conf"
if (Test-Path $managerConf) {
    $confText = Get-Content -Path $managerConf -Raw
    if ($confText -notmatch '(?s)<auth>.*<force>') {
        $forceBlock = @"
    <!-- Lab override: re-enrolling an existing agent name (e.g. after the
         generator / ghost-sender container restarts) must replace the old
         record immediately, instead of waiting for the stock ~1h disconnect
         window. Without this every endpoint stays "Disconnected" across
         restarts and all of its events are dropped. -->
    <force>
      <enabled>yes</enabled>
      <key_mismatch>no</key_mismatch>
      <disconnected_time enabled="no">0</disconnected_time>
      <after_registration_time>0</after_registration_time>
    </force>
  </auth>
"@
        $confText = $confText -replace '(?s)(\r?\n)\s*</auth>', "`$1$forceBlock"
        Set-Content -Path $managerConf -Value $confText -Encoding UTF8 -NoNewline
        Write-Host "Patched authd force-replace policy into wazuh_manager.conf" -ForegroundColor Green
    }
    else {
        Write-Host "authd force-replace policy already present in wazuh_manager.conf" -ForegroundColor DarkGray
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
