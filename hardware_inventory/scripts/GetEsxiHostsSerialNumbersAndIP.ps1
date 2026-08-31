param (
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$VaultPath = "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted",
    [string]$ModulePath = "/usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1"
)

$ErrorActionPreference = "Stop"

# 1. Ignore untrusted SSL certificates on internal networks
if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

# 2. Import centralized AES-256 Credential Manager
if (-not (Test-Path $ModulePath)) {
    throw "CredentialManagement module not found at: $ModulePath"
}
Import-Module $ModulePath -Force

# 3. Ensure target directory exists
$OutputDirectory = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$VC_list = @(
    "huarinfvc.niprpnp.army.mil",
    "huarvdivcsa.niprpnp.army.mil",
    "huar35tvc.swi.local",
    "huafinfvc.niprpnp.army.mil",
    "huafvdivcsa.niprpnp.army.mil",
    "huagvc.niprpnp.army.mil"
)

$hasSuccess = $false

foreach ($VC in $VC_list) {
    # Determine Datacenter Location Tag
    if (($VC -eq "huarinfvc.niprpnp.army.mil") -or ($VC -eq "huarvdivcsa.niprpnp.army.mil") -or ($VC -eq "huar35tvc.niprpnp.army.mil") -or ($VC -eq "huar35tvc.swi.local")) {
        $datacenter = "Rowe"
    } elseif ($VC -eq "huagvc.niprpnp.army.mil") {
        $datacenter = "GIB"
    } else {
        $datacenter = "Friedman"
    }

    # Retrieve decrypted PSCredential from AES-256 Vault
    $vcEntry = Get-vCenterCredential -FQDN $VC -FilePath $VaultPath
    if (-not $vcEntry -or -not $vcEntry.AdminCred) {
        Write-Warning "Skipping ${VC} - No credentials found in vault ($VaultPath)."
        continue
    }

    Write-Host "[INFO] Connecting to ${VC} ($datacenter)..."
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
        $serial = ""

        try {
            $esxcli   = Get-EsxCli -VMHost $Esx -V2
            $platform = $esxcli.hardware.platform.get.Invoke()
            if ($platform.SerialNumber) { $serial = $platform.SerialNumber }
            if ($platform.VendorName)   { $vendor = $platform.VendorName }
            if ($platform.ProductName)  { $model  = $platform.ProductName }
        } catch {
            $serial = "N/A"
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