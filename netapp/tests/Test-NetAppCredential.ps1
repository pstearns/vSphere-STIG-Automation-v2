<#
.SYNOPSIS
    Interactive test script to validate NetApp credential retrieval + SSH command execution.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$ClusterName
)

$ErrorActionPreference = 'Stop'

$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
$InputsPath  = Join-Path $OverlayRoot "netapp/conf/inputs.yml"
$CredFile    = Join-Path $OverlayRoot "conf/.creds.json.encrypted"

Write-Host "`n[*] Testing NetApp Credential Workflow for: $ClusterName" -ForegroundColor Cyan

# 1. Import required modules
Import-Module (Join-Path $OverlayRoot "modules/CredentialManagement.psm1") -Force
Import-Module powershell-yaml -Force -ErrorAction SilentlyContinue

# 2. Load inputs.yml
if (-not (Test-Path $InputsPath)) {
    Write-Error "inputs.yml not found at $InputsPath"
    return
}

$Inputs = Get-Content $InputsPath -Raw | ConvertFrom-Yaml

$Target = $Inputs.netapp_targets | Where-Object { 
    $_.fqdn -eq $ClusterName -or 
    $_.name -eq $ClusterName -or 
    ($_.fqdn -split '\.')[0] -eq $ClusterName 
} | Select-Object -First 1

if (-not $Target) {
    Write-Error "Cluster '$ClusterName' not found in netapp/conf/inputs.yml"
    return
}

Write-Host "[+] Found target in inputs.yml: $($Target.fqdn)" -ForegroundColor Green

# 3. Retrieve credentials from vault
$Creds = Get-NetAppCredential -FQDN $Target.fqdn -FilePath $CredFile

if (-not $Creds) {
    Write-Error "No credentials found in vault for $($Target.fqdn)"
    return
}

$Username = $Creds.AdminCred.UserName
$Password = $Creds.AdminCred.GetNetworkCredential().Password

Write-Host "[+] Credentials retrieved successfully for user: $Username" -ForegroundColor Green

# 4. Run a simple command against the NetApp cluster
$Command = "cluster identity show"

Write-Host "`n[*] Executing command on $($Target.fqdn): $Command" -ForegroundColor Yellow

try {
    # Using sshpass if available (common on these systems)
    $sshpass = Get-Command sshpass -ErrorAction SilentlyContinue

    if ($sshpass) {
        $result = sshpass -p $Password ssh -o StrictHostKeyChecking=no "$Username@$($Target.fqdn)" $Command 2>&1
    } else {
        Write-Warning "sshpass not found. Falling back to interactive ssh (you may be prompted for password)."
        $result = ssh "$Username@$($Target.fqdn)" $Command 2>&1
    }

    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n[✓] Command executed successfully!" -ForegroundColor Green
        Write-Host "----- Output -----"
        $result | Write-Host
        Write-Host "------------------"
    } else {
        Write-Warning "Command returned exit code $LASTEXITCODE"
        $result | Write-Host
    }
}
catch {
    Write-Error "Failed to execute SSH command: $_"
}