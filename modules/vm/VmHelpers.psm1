<#
.SYNOPSIS
    Retrieves Virtual Machine IP, MAC, and DNS names via PowerCLI.
.DESCRIPTION
    Authenticates to the vCenter API to pull the Guest OS network details for a specific VM.
#>
function Get-VmNetworkInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$vCenter,
        [Parameter(Mandatory=$true)][string]$AdminUser,
        [Parameter(Mandatory=$true)][string]$AdminPass,
        [Parameter(Mandatory=$true)][string]$VmName
    )

    Write-StigLog -Message "Querying vCenter for VM Networking Info: $VmName" -Severity INFO -Source "NetInfo"
    
    try {
        # Connect-VIServer natively re-uses active sessions if one already exists
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
        Connect-VIServer -Server $vCenter -User $AdminUser -Password $AdminPass -Force -ErrorAction Stop | Out-Null
        
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        
        $vm_IP = $vm.Guest.IPAddress | Select-Object -First 1
        $vmDNSName = $vm.Guest.HostName
        $networkadapter = $vm | Get-NetworkAdapter -ErrorAction SilentlyContinue | Select-Object -First 1
        
        Write-StigLog -Message "Successfully retrieved networking info for $VmName" -Severity SUCCESS -Source "NetInfo"
        
        return [PSCustomObject]@{
            IPAddress  = if ($vm_IP) { $vm_IP } else { "" }
            MACAddress = if ($networkadapter) { $networkadapter.MacAddress } else { "" }
            DNSName    = if ($vmDNSName) { $vmDNSName } else { "" }
        }
    }
    catch {
        Write-StigLog -Message "Failed to retrieve VM networking info for $VmName. Error: $($_.Exception.Message)" -Severity WARN -Source "NetInfo"
    }

    return [PSCustomObject]@{ IPAddress = ""; MACAddress = ""; DNSName = "" }
}

Export-ModuleMember -Function Get-VmNetworkInfo