param(
    [string]$ConfigPath = ".\config\lab.example.json",
    [switch]$SkipCoreSetup,
    [switch]$SkipCertificateGeneration,
    [switch]$NoWaitForManager,
    # Override lab.agent_mode without editing the config file.
    # Valid values: "ghost" | "container"
    [ValidateSet("ghost","container","")]
    [string]$AgentMode = ""
)

. (Join-Path $PSScriptRoot "common.ps1")

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$resolvedConfigPath = Resolve-LabPath -RepoRoot $repoRoot -Path $ConfigPath
$config = Get-LabConfigObject -ConfigPath $resolvedConfigPath

# When an agent mode is requested at launch time, patch the config in memory
# and write a temp file so render_lab.py picks up the override.
$_tempConfigPath = $null
if ($AgentMode -ne "") {
    if (-not $config.lab.PSObject.Properties.Match('agent_mode').Count) {
        $config.lab | Add-Member -MemberType NoteProperty -Name 'agent_mode' -Value $AgentMode -Force
    } else {
        $config.lab.agent_mode = $AgentMode
    }
    $_tempConfigPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "lab-runtime-override-$PID.json")
    $config | ConvertTo-Json -Depth 20 | Set-Content -Path $_tempConfigPath -Encoding UTF8
    $resolvedConfigPath = $_tempConfigPath
}

if (-not $SkipCoreSetup) {
    & (Join-Path $PSScriptRoot "setup-core.ps1") -ConfigPath $resolvedConfigPath -SkipCertificateGeneration:$SkipCertificateGeneration
}

# Pick a free, non-privileged dashboard port (>= 10000) and remap the dashboard
# service via a generated docker-compose.override.yml so it isn't bound to 443.
$dashboardPort = Get-WazuhDashboardPort -RepoRoot $repoRoot
Write-WazuhDashboardOverride -RepoRoot $repoRoot -Port $dashboardPort
Write-Host "Wazuh dashboard will be exposed on host port $dashboardPort (https://localhost:$dashboardPort)." -ForegroundColor Cyan

# Start the core stack first (so we can query the running manager for its network)
$singleNodeRoot = Join-Path $repoRoot "vendor\wazuh-docker\single-node"
if (Test-Path $singleNodeRoot) {
    Push-Location $singleNodeRoot
    try {
        Write-Host "Starting Wazuh core stack (project: $($config.lab.core_project_name))..." -ForegroundColor Cyan
        docker compose -p $config.lab.core_project_name up -d
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to start the Wazuh core stack."
        }
    }
    finally {
        Pop-Location
    }
}
else {
    Write-Host "vendor/wazuh-docker not found. Assuming an external Wazuh stack is already running." -ForegroundColor Yellow
}

# ── Auto-detect the network the wazuh-manager container is actually attached to.
# Works whether the user started the stack via our setup-core.ps1, or manually
# from a different directory (which is why default project names diverge).
$detectedNetwork = ""
$managerContainer = (docker ps --filter "ancestor=wazuh/wazuh-manager:$($config.wazuh.version)" --format "{{.Names}}" 2>$null | Select-Object -First 1)
if (-not $managerContainer) {
    # Fallback: any container whose image is wazuh/wazuh-manager regardless of tag, or whose name contains wazuh.manager
    $managerContainer = (docker ps --format "{{.Names}}|{{.Image}}" 2>$null) `
        -split "`r?`n" `
        | Where-Object { $_ -match "wazuh/wazuh-manager|wazuh\.manager" } `
        | ForEach-Object { ($_ -split "\|")[0] } `
        | Select-Object -First 1
}
if ($managerContainer) {
    $networkLine = (docker inspect $managerContainer --format "{{range `$k, `$v := .NetworkSettings.Networks}}{{`$k}}{{println}}{{end}}" 2>$null) -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1
    if ($networkLine) {
        $detectedNetwork = $networkLine.Trim()
        Write-Host "Detected Wazuh core network: $detectedNetwork (manager: $managerContainer)" -ForegroundColor Green
    }
}
if (-not $detectedNetwork) {
    Write-Host "Could not detect the Wazuh manager network - falling back to derived name." -ForegroundColor Yellow
}

# ── Render the lab overlay using the detected (or derived) network name.
& (Join-Path $PSScriptRoot "render.ps1") -ConfigPath $resolvedConfigPath -CoreNetwork $detectedNetwork -DashboardPort $dashboardPort

# ── Optionally wait for the manager registration port (1515) to be reachable
# from our host, so the agent containers don't waste their initial enrollment
# attempts. Inside Docker the registration is on the manager host alias, but
# the host port mapping is a good readiness proxy.
if (-not $NoWaitForManager) {
    Write-Host "Waiting for the Wazuh manager registration port to be reachable..." -ForegroundColor Cyan
    $deadline = (Get-Date).AddSeconds(120)
    $managerReady = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect("127.0.0.1", 1515, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(2000, $false) -and $tcp.Connected) {
                $tcp.EndConnect($iar) | Out-Null
                $tcp.Close()
                $managerReady = $true
                break
            }
            $tcp.Close()
        }
        catch {}
        Start-Sleep -Seconds 2
    }
    if ($managerReady) {
        Write-Host "Wazuh manager is accepting connections on 1515." -ForegroundColor Green
    }
    else {
        Write-Host "Wazuh manager port 1515 still not reachable after 120s. Continuing anyway." -ForegroundColor Yellow
    }
}

# ── Pre-create every agent group on the manager. Wazuh's authd refuses
# enrollment for agents whose target group does not already exist
# ("ERROR: Invalid group: X. Unable to add agent"), so we MUST create them
# before any agent (ghost or container) tries to enroll.
#
# The previous version silently dropped stderr and the exit code, which hid
# transient failures while the manager's wazuh-db / authd processes were still
# booting. The result: zero groups created, every agent rejected, dashboard
# stays empty. We now retry with verification and fail loudly if anything is
# still missing at the end.
if ($managerContainer) {
    $allGroups = @{}
    foreach ($profile in $config.profiles) {
        foreach ($g in $profile.groups) {
            if ($g) { $allGroups[$g] = $true }
        }
    }
    $wantedGroups = @($allGroups.Keys | Sort-Object)
    if ($wantedGroups.Count -gt 0) {
        Write-Host "Pre-creating agent groups on the manager: $($wantedGroups -join ', ')" -ForegroundColor Cyan
        $env:MSYS_NO_PATHCONV = "1"
        try {
            $deadline = (Get-Date).AddSeconds(120)
            $existing = @()
            while ((Get-Date) -lt $deadline) {
                # List current groups; if the binary errors out the manager is
                # still booting, so just retry.
                $listOut = docker exec $managerContainer //var/ossec/bin/agent_groups -l 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $existing = @(($listOut -split "`r?`n") |
                        ForEach-Object {
                            if ($_ -match '^\s+([A-Za-z0-9._-]+)\s+\(\d+\)\s*$') { $Matches[1] }
                        })
                    $missing = @($wantedGroups | Where-Object { $_ -notin $existing })
                    if ($missing.Count -eq 0) { break }
                    foreach ($group in $missing) {
                        $createOut = docker exec $managerContainer //var/ossec/bin/agent_groups -a -g $group -q 2>&1
                        if ($LASTEXITCODE -ne 0 -and $createOut -notmatch 'already exists') {
                            Write-Host "  create '$group' returned non-zero - manager probably still warming up, retrying" -ForegroundColor DarkGray
                        }
                    }
                }
                Start-Sleep -Seconds 2
            }

            # Final verification.
            $listOut = docker exec $managerContainer //var/ossec/bin/agent_groups -l 2>&1
            $existing = @(($listOut -split "`r?`n") |
                ForEach-Object {
                    if ($_ -match '^\s+([A-Za-z0-9._-]+)\s+\(\d+\)\s*$') { $Matches[1] }
                })
            $missing = @($wantedGroups | Where-Object { $_ -notin $existing })
            if ($missing.Count -gt 0) {
                throw "Agent group(s) never created on the manager: $($missing -join ', '). Without these, every agent enrollment will be rejected with 'Invalid group'."
            }
            Write-Host "  Verified groups on manager: $($existing -join ', ')" -ForegroundColor Green
        }
        finally {
            Remove-Item Env:\MSYS_NO_PATHCONV -ErrorAction SilentlyContinue
        }
    }
}

# ── Start the lab overlay.
$overlayCompose = Join-Path $repoRoot "generated\lab-compose.yml"
Push-Location $repoRoot
try {
    Write-Host "Starting lab overlay (project: $($config.lab.lab_project_name))..." -ForegroundColor Cyan
    docker compose -f $overlayCompose -p $config.lab.lab_project_name up -d --build
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start the synthetic endpoint overlay."
    }
}
finally {
    Pop-Location
}

$uiPort = 8765
if ($config.lab.PSObject.Properties.Match('ui_port').Count -gt 0 -and $config.lab.ui_port) {
    $uiPort = [int]$config.lab.ui_port
}

Write-Host ""
Write-Host "Lab is up." -ForegroundColor Green
Write-Host "  Wazuh dashboard: https://localhost:$dashboardPort  (admin / SecretPassword)"
Write-Host "  Generator UI:    http://localhost:$uiPort"
Write-Host ""
Write-Host "Synthetic agents enroll over 30 to 90 seconds. Run scripts/diagnose.ps1 to verify the pipeline." -ForegroundColor DarkGray

# Clean up any temp config written for the -AgentMode override.
if ($_tempConfigPath -and (Test-Path $_tempConfigPath)) {
    Remove-Item $_tempConfigPath -ErrorAction SilentlyContinue
}
