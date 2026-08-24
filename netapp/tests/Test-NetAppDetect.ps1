<#
.SYNOPSIS
    Diagnostic script to see how Cinc-Auditor detects the NetApp platform (with debug logging).
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$ClusterName,

    [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
)

$ErrorActionPreference = 'Stop'

Write-Host "`n[*] NetApp Platform Detection Test (Debug Mode)" -ForegroundColor Cyan
Write-Host "    Cluster: $ClusterName`n" -ForegroundColor Gray

$InputsPath = Join-Path $OverlayRoot "netapp/conf/inputs.yml"
$CredFile   = Join-Path $OverlayRoot "conf/.creds.json.encrypted"

Import-Module (Join-Path $OverlayRoot "modules/CredentialManagement.psm1") -Force
Import-Module powershell-yaml -Force -ErrorAction SilentlyContinue

# Load target
$Inputs = Get-Content $InputsPath -Raw | ConvertFrom-Yaml
$Target = $Inputs.netapp_targets | Where-Object {
    $_.fqdn -eq $ClusterName -or 
    $_.name -eq $ClusterName -or 
    ($_.fqdn -split '\.')[0] -eq $ClusterName
} | Select-Object -First 1

if (-not $Target) {
    Write-Error "Cluster '$ClusterName' not found in inputs.yml"
    return
}

$fqdn = $Target.fqdn
Write-Host "[+] Target found: $fqdn" -ForegroundColor Green

# Get credentials from Credential Manager
$Creds = Get-NetAppCredential -FQDN $fqdn -FilePath $CredFile
if (-not $Creds) {
    Write-Error "No credentials found for $fqdn"
    return
}

$username = $Creds.AdminCred.UserName
$password = $Creds.AdminCred.GetNetworkCredential().Password

Write-Host "[+] Credentials loaded from vault for user: $username`n" -ForegroundColor Green

# Base64 encode password (same pattern as ESXi)
$b64Pass = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($password))

# Build command with DEBUG logging enabled
$detectCmd = "CHEF_LOG_LEVEL=debug cinc-auditor detect -t ontap://$username@$fqdn --password `"`$(echo '$b64Pass' | base64 -d)`" --backend ssh --platform unix "

Write-Host "[*] Running cinc-auditor detect with DEBUG logging..." -ForegroundColor Yellow
Write-Host "    This may produce a lot of output.`n" -ForegroundColor DarkGray

try {
    $output = bash -c $detectCmd 2>&1

    Write-Host "`n=== Cinc-Auditor Detect Output (DEBUG) ===" -ForegroundColor Cyan
    $output | Write-Host
    Write-Host "==========================================`n" -ForegroundColor Cyan

} catch {
    Write-Error "Failed to run cinc-auditor detect: $_"
}