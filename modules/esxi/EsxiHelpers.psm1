<#
.SYNOPSIS
    Retrieves ESXi IP and MAC addresses via PowerCLI.
.DESCRIPTION
    Authenticates to the vCenter API to pull the vmk0 interface details for a specific ESXi host.
#>
function Get-EsxiNetworkInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$vCenter,
        [Parameter(Mandatory=$true)][string]$AdminUser,
        [Parameter(Mandatory=$true)][string]$AdminPass,
        [Parameter(Mandatory=$true)][string]$EsxiHost
    )

    Write-StigLog -Message "Querying vCenter for ESXi Networking Info: $EsxiHost" -Severity INFO -Source "NetInfo"
    
    try {
        # Connect-VIServer natively re-uses active sessions if one already exists
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
        Connect-VIServer -Server $vCenter -User $AdminUser -Password $AdminPass -Force -ErrorAction Stop | Out-Null
        
        $vmhost = Get-VMHost -Name $EsxiHost -ErrorAction Stop
        $adapter = $vmhost | Get-VMHostNetworkAdapter | Where-Object { $_.Name -eq "vmk0" }
        
        if ($adapter) {
            Write-StigLog -Message "Successfully retrieved networking info for $EsxiHost" -Severity SUCCESS -Source "NetInfo"
            return [PSCustomObject]@{
                IPAddress  = $adapter.IP
                MACAddress = $adapter.Mac
            }
        }
    }
    catch {
        Write-StigLog -Message "Failed to retrieve ESXi networking info for $EsxiHost. Error: $($_.Exception.Message)" -Severity WARN -Source "NetInfo"
    }

    return [PSCustomObject]@{ IPAddress = ""; MACAddress = "" }
}

<#
.SYNOPSIS
    Enables or disables SSH and Lockdown Mode on an ESXi Host via PowerCLI.
#>
function Set-EsxiAccessState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$vCenter,
        [Parameter(Mandatory=$true)][string]$AdminUser,
        [Parameter(Mandatory=$true)][string]$AdminPass,
        [Parameter(Mandatory=$true)][string]$EsxiHost,
        [Parameter(Mandatory=$true)][bool]$Enabled
    )

    $StateStr = if ($Enabled) { "Enabling" } else { "Disabling" }
    Write-StigLog -Message "$StateStr SSH and modifying Lockdown Mode on ESXi: $EsxiHost" -Severity INFO -Source "SSHControl"
    
    try {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
        Connect-VIServer -Server $vCenter -User $AdminUser -Password $AdminPass -Force -ErrorAction Stop | Out-Null
        
        $vmhost = Get-VMHost -Name $EsxiHost -ErrorAction Stop
        $vmhostv = $vmhost | Get-View 
        $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
        
        if ($Enabled) {
            if ($vmhostv.config.LockdownMode -ne 'lockdownDisabled') { $lockdown.ChangeLockdownMode('lockdownDisabled') }
            $vmhost | Get-VMHostService | Where-Object { $_.Key -eq "TSM-SSH"} | Start-VMHostService -Confirm:$false | Out-Null
            Write-StigLog -Message "Access opened successfully on $EsxiHost" -Severity SUCCESS -Source "SSHControl"
        } 
        else {
            if ($vmhostv.config.LockdownMode -ne 'lockdownNormal') { $lockdown.ChangeLockdownMode('lockdownNormal') }
            $vmhost | Get-VMHostService | Where-Object { $_.Key -eq "TSM-SSH"} | Stop-VMHostService -Confirm:$false | Out-Null
            Write-StigLog -Message "Access secured successfully on $EsxiHost" -Severity SUCCESS -Source "SSHControl"
        }
    }
    catch {
        Write-StigLog -Message "Failed to alter access state on $EsxiHost. Error: $($_.Exception.Message)" -Severity ERROR -Source "SSHControl"
    }
}

Export-ModuleMember -Function Get-EsxiNetworkInfo, Set-EsxiAccessState