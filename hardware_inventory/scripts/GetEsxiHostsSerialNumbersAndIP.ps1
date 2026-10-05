param (
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$VaultPath = "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted",
    [string]$ModulePath = "/usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1"
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------
# 1. Environment & Module Initialization
# ---------------------------------------------------------
# Ignore untrusted SSL certificates on internal networks
if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

# Import centralized AES-256 Credential Manager
if (-not (Test-Path $ModulePath)) {
    throw "CredentialManagement module not found at: $ModulePath"
}
Import-Module $ModulePath -Force

# Ensure target directory exists
$OutputDirectory = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

# Clear any legacy reporting file to guarantee a fresh append cycle
if (Test-Path $OutputPath) {
    Remove-Item -Path $OutputPath -Force | Out-Null
}

# ---------------------------------------------------------
# 2. Target vCenter Inventory (Dynamic Vault Query)
# ---------------------------------------------------------
$vaultStore = Get-vCenterCredentialStore -FilePath $VaultPath
if (-not $vaultStore.vCenters -or $vaultStore.vCenters.Count -eq 0) {
    throw "No vCenter targets found in vault: $VaultPath"
}

# Dynamically populate $VC_list from credential store entries
$VC_list = @($vaultStore.vCenters | ForEach-Object {
    if ($_.FQDN) { $_.FQDN } else { $_ }
} | Sort-Object)

Write-Host "[INFO] Discovered $($VC_list.Count) vCenter target(s) inside secure vault." -ForegroundColor Cyan

# ---------------------------------------------------------
# 3. Interrogate vCenters & Gather Host Hardware Data
# ---------------------------------------------------------
$hasSuccess = $false

foreach ($VC in $VC_list) {
    # Determine Datacenter Location Tag by analyzing host prefix only
    if ($VC -match '^huar') {
        $datacenter = "Rowe"
    } elseif ($VC -match '^huag') {
        $datacenter = "GIB"
    } else {
        # Defaults to 'Friedman' for huaf or any other designated infrastructure nodes
        $datacenter = "Friedman"
    }

    # Retrieve decrypted PSCredential from AES-256 Vault
    $vcEntry = Get-vCenterCredential -FQDN $VC -FilePath $VaultPath
    if (-not $vcEntry -or -not $vcEntry.AdminCred) {
        Write-Warning "Skipping ${VC} - No credentials found in vault ($VaultPath)."
        continue
    }

    Write-Host "[INFO] Connecting to ${VC} ($datacenter)..." -ForegroundColor Cyan
    try {
        $connection = Connect-VIServer $VC -Credential $vcEntry.AdminCred -ErrorAction Stop
    } catch {
        Write-Warning "[WARN] Could not reach or connect to ${VC}: $($_.Exception.Message)"
        continue
    }

    $esxlist = Get-VMHost | Sort-Object Name
    foreach ($Esx in $esxlist) {
        # DNS resolution using cross-platform .NET
        $ip = ""
        try {
            $ipAddresses = [System.Net.Dns]::GetHostAddresses($Esx.Name)
            $ip = ($ipAddresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
        } catch {
            $ip = "Unknown"
        }

        # Safe ESXi hardware collection
        $vendor = $Esx.Manufacturer
        $model  = $Esx.Model
        $serial = "N/A"

        try {
            $esxcli   = Get-EsxCli -VMHost $Esx -V2
            $platform = $esxcli.hardware.platform.get.Invoke()
            if ($platform.SerialNumber) { $serial = $platform.SerialNumber }
            if ($platform.VendorName)   { $vendor = $platform.VendorName }
            if ($platform.ProductName)  { $model  = $platform.ProductName }
        } catch {
            # Leaves values at fallback / basic properties retrieved via SDK
        }

        $Report = [PSCustomObject]@{
            Hostname          = $Esx.Name
            IP                = $ip
            Manufacturer      = $vendor
            Model             = $model
            SerialNumber      = $serial
            Operating_System  = $Esx.Version
            Building_Location = $datacenter
            Memory_size_GB    = [math]::Round($Esx.MemoryTotalGB, 2)
        }

        $Report | Export-Csv -NoTypeInformation -UseCulture -Append -Path $OutputPath
        $hasSuccess = $true
    }

    Disconnect-VIServer $connection -Confirm:$false
}

if (-not $hasSuccess -and -not (Test-Path $OutputPath)) {
    throw "No inventory data collected from any configured vCenter target."
}

Write-Host "[SUCCESS] Inventory execution completed. Report located at: $OutputPath" -ForegroundColor Green