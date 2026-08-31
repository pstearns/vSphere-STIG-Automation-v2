param (
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$VaultPath = "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted",
    [string]$ModulePath = "/usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1"
)

$ErrorActionPreference = "Stop"

# 1. Ignore untrusted SSL certificates
if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

# 2. Import centralized AES-256 Credential Manager
if (-not (Test-Path $ModulePath)) {
    throw "CredentialManagement module not found at: $ModulePath"
}
Import-Module $ModulePath -Force

$Manufacturer = "VMware"
$Model        = "Virtual Machine"

# 3. Ensure target directory exists
$OutputDirectory = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$VC_list = @(
    "huarinfvc.niprpnp.army.mil",
    "huarvdivcsa.niprpnp.army.mil",
    "huafinfvc.niprpnp.army.mil",
    "huafvdivcsa.niprpnp.army.mil",
    "huagvc.niprpnp.army.mil"
)

$hasSuccess = $false

foreach ($VC in $VC_list) {
    # Determine Datacenter Location Tag
    if (($VC -eq "huarinfvc.niprpnp.army.mil") -or ($VC -eq "huarvdivcsa.niprpnp.army.mil")) {
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

    $vmlist = Get-VM | Where-Object {
        !$_.Name.Contains("vCLS") -and 
        !$_.Name.Contains("replica") -and 
        !$_.Name.Contains("cp-template")
    } | Sort-Object Name

    foreach ($vm in $vmlist) {
        $ip = ""
        try {
            $ipAddresses = [System.Net.Dns]::GetHostAddresses($vm.Name)
            $ip = ($ipAddresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
        } catch {
            $ip = "Unknown"
        }

        $Adapter = $vm | Get-NetworkAdapter | Select-Object -First 1
        $VMIP    = if ($vm.Guest.IPAddress) { $vm.Guest.IPAddress[0] } else { "" }
        $vCenter = $vm.Uid.Substring($vm.Uid.IndexOf('@')+1).Split(":")[0]

        $Report = [PSCustomObject]@{
            vCenter           = $vCenter
            Name              = $vm.Name
            VMIP              = $VMIP
            IP                = $ip
            MAC_Address       = if ($Adapter) { $Adapter.MacAddress } else { "N/A" }
            Manufacturer      = $Manufacturer
            Model             = $Model
            SN                = (Get-View $vm.Id).Config.Uuid
            Operating_System  = $vm.Guest.OSFullName
            Building_Location = $datacenter
            Memory_size_GB    = [math]::Round($vm.MemoryGB, 2)
            vCPU_Count        = $vm.NumCpu
        }

        $Report | Export-Csv -NoTypeInformation -UseCulture -Append -Path $OutputPath
        $hasSuccess = $true
    }

    Disconnect-VIServer $connection -Confirm:$false
}

if (-not $hasSuccess -and -not (Test-Path $OutputPath)) {
    throw "No inventory data collected from any configured vCenter target."
}