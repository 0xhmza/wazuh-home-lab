param(
    [string]$ConfigPath = ".\config\lab.example.json",
    [int]$ManagerApiPort = 55000,
    [string]$ManagerApiUser = "wazuh-wui",
    [string]$ManagerApiPassword = "MyS3cr37P450r.*-"
)

. (Join-Path $PSScriptRoot "common.ps1")

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedConfigPath = Resolve-LabPath -RepoRoot $repoRoot -Path $ConfigPath
$config = Get-LabConfigObject -ConfigPath $resolvedConfigPath

# -- output helpers -----------------------------------------------------------
# Note: previous versions used raw ANSI escape codes. Those render as garbage
# in Windows PowerShell 5.1 (which doesn't expand VT sequences by default), so
# we now use Write-Host -ForegroundColor for cross-version compatibility.

function Write-Header($text) {
    Write-Host ""
    Write-Host "-- $text --" -ForegroundColor Cyan
}

function Write-Pass($label, $detail = "") {
    Write-Host -NoNewline "  [OK]   " -ForegroundColor Green
    Write-Host -NoNewline $label
    if ($detail) { Write-Host "  $detail" -ForegroundColor DarkGray } else { Write-Host "" }
}

function Write-Warn($label, $detail = "") {
    Write-Host -NoNewline "  [WARN] " -ForegroundColor Yellow
    Write-Host -NoNewline $label
    if ($detail) { Write-Host "  $detail" -ForegroundColor DarkGray } else { Write-Host "" }
}

function Write-Fail($label, $detail = "") {
    Write-Host -NoNewline "  [FAIL] " -ForegroundColor Red
    Write-Host -NoNewline $label
    if ($detail) { Write-Host "  $detail" -ForegroundColor DarkGray } else { Write-Host "" }
}

# -- PS 5.1 vs PS 7 cert-validation shim --------------------------------------
# Invoke-RestMethod's -SkipCertificateCheck flag is PS 7+ only. On 5.1 we
# install a process-wide trust-all callback before calling Invoke-RestMethod.
$Script:IsPwsh7 = ($PSVersionTable.PSVersion.Major -ge 6)
if (-not $Script:IsPwsh7) {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor `
            [System.Net.SecurityProtocolType]::Tls12
    } catch {}
    try {
        # Idempotent - last writer wins; safe to call repeatedly.
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback =
            { param($s, $c, $ch, $e) $true }
    } catch {}
}

function Invoke-LabRest {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [hashtable]$Headers = @{},
        [int]$TimeoutSec = 8
    )
    if ($Script:IsPwsh7) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers `
            -SkipCertificateCheck -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers `
        -TimeoutSec $TimeoutSec -ErrorAction Stop
}

# -- 1. Manager container running? --------------------------------------------
Write-Header "Wazuh core stack"
$managerContainer = (docker ps --filter "ancestor=wazuh/wazuh-manager:$($config.wazuh.version)" --format "{{.Names}}" 2>$null | Select-Object -First 1)
if (-not $managerContainer) {
    $managerContainer = (docker ps --filter "name=wazuh.manager" --format "{{.Names}}" 2>$null | Select-Object -First 1)
}
if ($managerContainer) {
    Write-Pass "wazuh-manager container is running" $managerContainer
}
else {
    Write-Fail "No wazuh-manager container found" "Run scripts/up.ps1 first"
    exit 1
}

$indexerContainer = (docker ps --filter "ancestor=wazuh/wazuh-indexer:$($config.wazuh.version)" --format "{{.Names}}" 2>$null | Select-Object -First 1)
if ($indexerContainer) { Write-Pass "wazuh-indexer container is running" $indexerContainer } else { Write-Warn "wazuh-indexer not found" }

$dashboardContainer = (docker ps --filter "ancestor=wazuh/wazuh-dashboard:$($config.wazuh.version)" --format "{{.Names}}" 2>$null | Select-Object -First 1)
if ($dashboardContainer) {
    # Surface the actual published host port for the dashboard so the user can
    # navigate to the right URL - it is randomized at launch time (>= 10000).
    $dashPort = ""
    $portFile = Join-Path $repoRoot "generated\dashboard-port.txt"
    if (Test-Path $portFile) {
        $raw = (Get-Content -Raw -Path $portFile -ErrorAction SilentlyContinue).Trim()
        if ($raw -match '^\d+$') { $dashPort = $raw }
    }
    if (-not $dashPort) {
        try {
            $portRaw = docker port $dashboardContainer 5601/tcp 2>$null | Select-Object -First 1
            if ($portRaw -match ':(\d+)\s*$') { $dashPort = $Matches[1] }
        } catch {}
    }
    if ($dashPort) {
        Write-Pass "wazuh-dashboard container is running" "$dashboardContainer  ->  https://localhost:$dashPort"
    } else {
        Write-Pass "wazuh-dashboard container is running" $dashboardContainer
    }
} else {
    Write-Warn "wazuh-dashboard not found"
}

# -- 2. Network name + agent network attachment -------------------------------
Write-Header "Network connectivity"
$detectedNetwork = ""
$networkLine = (docker inspect $managerContainer --format "{{range `$k, `$v := .NetworkSettings.Networks}}{{`$k}}{{println}}{{end}}" 2>$null) -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1
if ($networkLine) { $detectedNetwork = $networkLine.Trim() }

if ($detectedNetwork) {
    Write-Pass "Manager network" $detectedNetwork
}
else {
    Write-Fail "Could not detect manager network"
}

$agentContainers = docker ps --filter "name=agent-" --format "{{.Names}}" 2>$null
$agentArr = @()
if ($agentContainers) { $agentArr = @($agentContainers -split "`r?`n" | Where-Object { $_ }) }

$agentMode = "container"
if ($config.lab.PSObject.Properties.Match('agent_mode').Count -gt 0 -and $config.lab.agent_mode) {
    $agentMode = $config.lab.agent_mode
}

if ($agentMode -eq "ghost") {
    Write-Pass "Ghost-sender mode enabled" "No per-endpoint agent containers expected"
    # Verify the generator container is up; ghost sender runs inside it.
}
elseif ($agentArr.Count -gt 0) {
    Write-Pass "Lab agent containers running" "$($agentArr.Count) container(s)"

    $sample = $agentArr | Select-Object -First 1
    $sampleNetwork = (docker inspect $sample --format "{{range `$k, `$v := .NetworkSettings.Networks}}{{`$k}}{{println}}{{end}}" 2>$null) -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1
    if ($sampleNetwork -and $detectedNetwork -and $sampleNetwork.Trim() -eq $detectedNetwork) {
        Write-Pass "Agent and manager share the same network" $detectedNetwork
    }
    elseif ($sampleNetwork) {
        Write-Fail "Agent network does not match manager network" "agent=$($sampleNetwork.Trim()) manager=$detectedNetwork"
    }
}
else {
    Write-Fail "No agent containers running" "Lab overlay never started, or could not attach to the manager network. Re-run scripts/up.ps1"
}

$generator = (docker ps --filter "name=lab-generator" --format "{{.Names}}" 2>$null | Select-Object -First 1)
if ($generator) { Write-Pass "lab-generator running" $generator } else { Write-Fail "lab-generator not running" }

# -- 3. Manager API: how many agents has it actually accepted? ----------------
Write-Header "Manager API (port $ManagerApiPort)"
try {
    $authHeader = "Basic " + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${ManagerApiUser}:${ManagerApiPassword}"))
    $tokenResp = Invoke-LabRest -Method Post -Uri "https://localhost:$ManagerApiPort/security/user/authenticate" `
        -Headers @{ Authorization = $authHeader } -TimeoutSec 8
    $token = $tokenResp.data.token
    Write-Pass "Authenticated to Wazuh manager API"

    $agents = Invoke-LabRest -Method Get -Uri "https://localhost:$ManagerApiPort/agents?limit=500" `
        -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 8

    $list = @($agents.data.affected_items)
    $active = @($list | Where-Object { $_.status -eq "active" }).Count
    $disconnected = @($list | Where-Object { $_.status -eq "disconnected" }).Count
    $never = @($list | Where-Object { $_.status -eq "never_connected" }).Count
    $total = $list.Count

    $synthActive = [Math]::Max(0, $active - 1)
    if ($synthActive -gt 0) { Write-Pass "Active synthetic agents (excluding manager 000)" "$synthActive" }
    else { Write-Fail "No active synthetic agents have enrolled yet" "Total enrolled rows: $total - give them 60-90s, then re-run." }

    if ($disconnected -gt 0) { Write-Warn "Disconnected agents" "$disconnected" }
    if ($never -gt 0) { Write-Warn "Never-connected agents" "$never (registered but never beaconed back)" }
}
catch {
    Write-Fail "Manager API call failed" $_.Exception.Message
}

# -- 4. Are logs being written to the shared volume? --------------------------
Write-Header "Generator output"
$trainingDataRoot = Join-Path $repoRoot "generated\training-data"
if (Test-Path $trainingDataRoot) {
    $logFiles = Get-ChildItem -Path $trainingDataRoot -Recurse -Filter "*.log" -ErrorAction SilentlyContinue
    if ($logFiles.Count -gt 0) {
        $totalBytes = ($logFiles | Measure-Object -Property Length -Sum).Sum
        $totalKb = [math]::Round($totalBytes / 1024, 1)
        Write-Pass "Generator log files exist" "$($logFiles.Count) file(s), $totalKb KB total"

        $newest = $logFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $age = [int]((Get-Date) - $newest.LastWriteTime).TotalSeconds
        if ($age -lt 30) { Write-Pass "Most-recent log line was written" "${age}s ago" }
        elseif ($age -lt 120) { Write-Warn "Most-recent log line was written ${age}s ago" "Generator may be paused - check the UI" }
        else { Write-Fail "No log lines written in the last $age seconds" "Generator container may have died - docker logs lab-generator" }
    }
    else {
        Write-Fail "No .log files under $trainingDataRoot" "Generator probably never wrote any output"
    }
}
else {
    Write-Fail "Training-data directory missing" $trainingDataRoot
}

# -- 5. Ingestion: is the manager actually generating alerts? -----------------
Write-Header "Manager alert ingestion"
$env:MSYS_NO_PATHCONV = "1"
try {
    $alertCountStr = docker exec $managerContainer sh -c "wc -l < //var/ossec/logs/alerts/alerts.log 2>/dev/null" 2>$null
    if ($LASTEXITCODE -eq 0 -and $alertCountStr) {
        $alertCount = [int]($alertCountStr.ToString().Trim())
        if ($alertCount -gt 0) { Write-Pass "Total alert lines on manager" "$alertCount" }
        else { Write-Fail "No alerts in alerts.log yet" "Logs may not be reaching the manager - give it 60-90s." }
    }
    else {
        Write-Warn "Could not read alerts.log" "Manager may still be initialising."
    }

    $topRules = docker exec $managerContainer sh -c "grep -ohE 'Rule: [0-9]+ \(level [0-9]+\) -> .*' //var/ossec/logs/alerts/alerts.log 2>/dev/null | sort | uniq -c | sort -rn | head -5" 2>$null
    if ($topRules) {
        Write-Host "  Top fired rules:" -ForegroundColor DarkGray
        ($topRules -split "`r?`n") | Where-Object { $_ } | ForEach-Object {
            Write-Host "    $_" -ForegroundColor DarkGray
        }
    }
}
catch {
    Write-Warn "Manager alert tail failed" $_.Exception.Message
}
finally {
    Remove-Item Env:\MSYS_NO_PATHCONV -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Run again after 60-90 seconds for a fair view of agent enrollment." -ForegroundColor DarkGray
