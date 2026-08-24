<#
.SYNOPSIS
    Test script to run the NetApp InSpec profile against a specific cluster.
    Retrieves credentials from the secure vault and executes InSpec.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "FQDN or short name of the NetApp cluster")]
    [string]$ClusterName,

    [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
)

$ErrorActionPreference = 'Stop'

Write-Host "`n[*] NetApp InSpec Test Runner" -ForegroundColor Cyan
Write-Host "    Cluster: $ClusterName" -ForegroundColor Gray

# Paths
$InputsPath        = Join-Path $OverlayRoot "netapp/conf/inputs.yml"
$InSpecProfilePath = Join-Path $OverlayRoot "netapp/inspec"
$CredFile          = Join-Path $OverlayRoot "conf/.creds.json.encrypted"

# 1. Import modules
Import-Module (Join-Path $OverlayRoot "modules/CredentialManagement.psm1") -Force
Import-Module powershell-yaml -Force -ErrorAction SilentlyContinue

# 2. Load target from inputs.yml
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

$fqdn = $Target.fqdn
Write-Host "[+] Target found: $fqdn" -ForegroundColor Green

# 3. Retrieve credentials
$Creds = Get-NetAppCredential -FQDN $fqdn -FilePath $CredFile
if (-not $Creds) {
    Write-Error "No credentials found in vault for $fqdn"
    return
}

$username = $Creds.AdminCred.UserName
$password = $Creds.AdminCred.GetNetworkCredential().Password
Write-Host "[+] Credentials loaded for user: $username" -ForegroundColor Green

# 4. Prepare output location
$DateStr   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportDir = Join-Path $OverlayRoot "reports/$DateStr/netapp"
if (-not (Test-Path $ReportDir)) { 
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null 
}

$JsonOutput = Join-Path $ReportDir "$($fqdn.Split('.')[0])_InSpec_$DateStr.json"
$CliOutput  = Join-Path $ReportDir "$($fqdn.Split('.')[0])_InSpec_$DateStr.txt"

Write-Host "`n[*] Running InSpec profile..." -ForegroundColor Yellow
Write-Host "    Profile : $InSpecProfilePath"
Write-Host "    Target  : ssh://$username@$fqdn"
Write-Host "    Output  : $JsonOutput`n"

# 5. Build and run InSpec command
$inspecCmd = "inspec exec $InSpecProfilePath -t ontap://$username@$fqdn --password='$password' --reporter cli json:$JsonOutput"

try {
    $result = bash -c $inspecCmd 2>&1

    # Save CLI output
    $result | Out-File -FilePath $CliOutput -Encoding UTF8

    Write-Host "`n[✓] InSpec execution completed." -ForegroundColor Green
    Write-Host "    JSON Results : $JsonOutput"
    Write-Host "    CLI Output   : $CliOutput`n"

    # === Quick Summary ===
    if (Test-Path $JsonOutput) {
        try {
            $inspecResult = Get-Content $JsonOutput | ConvertFrom-Json

            $controls = if ($inspecResult.controls) {
                $inspecResult.controls
            } elseif ($inspecResult.profiles -and $inspecResult.profiles[0].controls) {
                $inspecResult.profiles[0].controls
            } else {
                $null
            }

            if ($controls) {
                $passed  = ($controls | Where-Object { $_.status -eq 'passed' }).Count
                $failed  = ($controls | Where-Object { $_.status -eq 'failed' }).Count
                $skipped = ($controls | Where-Object { $_.status -eq 'skipped' }).Count

                Write-Host "[*] Quick Summary:" -ForegroundColor Cyan
                Write-Host "    Passed  : $passed"  -ForegroundColor Green
                Write-Host "    Failed  : $failed"  -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })
                Write-Host "    Skipped : $skipped" -ForegroundColor Yellow
                Write-Host "    Total   : $($controls.Count)`n"
            } else {
                Write-Host "[*] Could not parse control results from JSON." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[*] Failed to generate summary from JSON results." -ForegroundColor Yellow
        }
    }

} catch {
    Write-Error "InSpec execution failed: $_"
}