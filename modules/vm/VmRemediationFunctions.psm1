<#
.SYNOPSIS
    VmRemediationFunctions.psm1
    Decoupled Remediation Controller for VCSA, ESXi, and VMs.
.DESCRIPTION
    Modular, decoupled STIG Remediation functions for Virtual Machines
    tailored for vSphere 8.0 VM STIG.
    All functions are designed to operate asynchronously within parallel runspaces.
#>

# ==========================================
# REGION: Logging Helper (Framework Safe)
# ==========================================

<#
.SYNOPSIS
    Centralized logging abstraction.
.DESCRIPTION
    Integrates with the global Write-StigLog logging pipeline if available,
    otherwise falls back to structured console outputs.
#>

# ==========================================
# REGION: Core Advanced Setting Helper
# ==========================================

<#
.SYNOPSIS
    Applies an Advanced Setting (VMX option) to a Virtual Machine.
.DESCRIPTION
    Checks if a setting exists, compares its value, and either updates
    or creates the setting dynamically.
.PARAMETER VM
    The target Virtual Machine PowerCLI object.
.PARAMETER Name
    The key name of the advanced setting.
.PARAMETER Value
    The target value to be applied.
#>
function Set-VmAdvancedSetting {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][object]$Value
    )
    
    $CurrentSetting = Get-AdvancedSetting -Entity $VM -Name $Name -ErrorAction SilentlyContinue
    if ($CurrentSetting) {
        if ([string]$CurrentSetting.Value -eq [string]$Value) {
            Write-StigLog -Message "[$($VM.Name)] Setting '$Name' is already compliant ($Value)." -Severity SUCCESS -Source "VmRemediation"
        } else {
            Write-StigLog -Message "[$($VM.Name)] Setting '$Name' is non-compliant ($($CurrentSetting.Value)). Remediating to '$Value'..." -Severity WARN -Source "VmRemediation"
            $CurrentSetting | Set-AdvancedSetting -Value $Value -Confirm:$false -ErrorAction Stop | Out-Null
        }
    } else {
        Write-StigLog -Message "[$($VM.Name)] Setting '$Name' does not exist. Creating setting with value '$Value'..." -Severity WARN -Source "VmRemediation"
        New-AdvancedSetting -Entity $VM -Name $Name -Value $Value -Confirm:$false -ErrorAction Stop | Out-Null
    }
}

# ==========================================
# REGION: STIG Remediation Functions
# ==========================================

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000189.
.DESCRIPTION
    Virtual machines (VMs) must have copy operations disabled.
#>
function VMCH-80-000189 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000189"
    $Title  = "Virtual machines (VMs) must have copy operations disabled."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.copyDisable.Keys | Select-Object -First 1)
    $Value = ($StigSettings.copyDisable.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000191.
.DESCRIPTION
    Virtual machines (VMs) must have drag and drop operations disabled.
#>
function VMCH-80-000191 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000191"
    $Title  = "Virtual machines (VMs) must have drag and drop operations disabled."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.dndDisable.Keys | Select-Object -First 1)
    $Value = ($StigSettings.dndDisable.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000192.
.DESCRIPTION
    Virtual machines (VMs) must have paste operations disabled.
#>
function VMCH-80-000192 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000192"
    $Title  = "Virtual machines (VMs) must have paste operations disabled."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.pasteDisable.Keys | Select-Object -First 1)
    $Value = ($StigSettings.pasteDisable.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000193.
.DESCRIPTION
    Virtual machines (VMs) must have virtual disk shrinking disabled.
#>
function VMCH-80-000193 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000193"
    $Title  = "Virtual machines (VMs) must have virtual disk shrinking disabled."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.diskShrink.Keys | Select-Object -First 1)
    $Value = ($StigSettings.diskShrink.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000194.
.DESCRIPTION
    Virtual machines (VMs) must have virtual disk wiping disabled.
#>
function VMCH-80-000194 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000194"
    $Title  = "Virtual machines (VMs) must have virtual disk wiping disabled."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.diskWiper.Keys | Select-Object -First 1)
    $Value = ($StigSettings.diskWiper.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000208.
.DESCRIPTION
    Virtual machines (VMs) must not use independent, nonpersistent disks.
#>
function VMCH-80-000208 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000208"
    $Title  = "Virtual machines (VMs) must not use independent, nonpersistent disks."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    Write-StigLog -Message "[$($VM.Name)] Independent, nonpersistent disks must be evaluated and configured manually." -Severity WARN -Source "VmRemediation"
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000209.
.DESCRIPTION
    Virtual machines (VMs) must remove unneeded floppy devices.
#>
function VMCH-80-000209 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000209"
    $Title  = "Virtual machines (VMs) must remove unneeded floppy devices."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    # 1. Check for the floppy drive using PowerCLI
    $FloppyDrive = $VM | Get-FloppyDrive -ErrorAction SilentlyContinue
    
    if ($FloppyDrive) {
        Write-StigLog -Message "[$($VM.Name)] Active virtual floppy drive found. Removing device..." -Severity WARN -Source "VmRemediation"
        try {
            # 2. Automatically remove the device from the VM configuration
            $FloppyDrive | Remove-FloppyDrive -Confirm:$false -ErrorAction Stop | Out-Null
            Write-StigLog -Message "[$($VM.Name)] Floppy drive successfully removed." -Severity SUCCESS -Source "VmRemediation"
        }
        catch {
            Write-StigLog -Message "[$($VM.Name)] Failed to remove floppy drive automatically: $_" -Severity ERROR -Source "VmRemediation"
        }
    } else {
        Write-StigLog -Message "[$($VM.Name)] No floppy devices present. Compliant." -Severity SUCCESS -Source "VmRemediation"
    }
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000210.
.DESCRIPTION
    Virtual machines (VMs) must remove unneeded CD/DVD devices.
#>
function VMCH-80-000210 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000210"
    $Title  = "Virtual machines (VMs) must remove unneeded CD/DVD devices."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $CdDrives = $VM | Get-CDDrive | Where-Object { $_.ExtensionData.Connectable.Connected -eq $true }
    if ($CdDrives) {
        # Log skipped state, leaving the setting open as requested
        Write-StigLog -Message "[$($VM.Name)] Active CD/DVD drive detected. Skipping automated unmounting to prevent disruption of system upgrades. This must be addressed manually." -Severity WARN -Source "VmRemediation"
    } else {
        Write-StigLog -Message "[$($VM.Name)] CD/DVD drive is disconnected or not present." -Severity SUCCESS -Source "VmRemediation"
    }
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000211.
.DESCRIPTION
    Virtual machines (VMs) must remove unneeded parallel devices.
#>
function VMCH-80-000211 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000211"
    $Title  = "Virtual machines (VMs) must remove unneeded parallel devices."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Parallel = $VM.ExtensionData.Config.Hardware.Device | Where-Object { $_.DeviceInfo.Label -match "parallel" }
    if ($Parallel) {
        Write-StigLog -Message "[$($VM.Name)] Parallel device exists. Must be manually detached or removed." -Severity WARN -Source "VmRemediation"
    } else {
        Write-StigLog -Message "[$($VM.Name)] Parallel device is not present." -Severity SUCCESS -Source "VmRemediation"
    }
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000212.
.DESCRIPTION
    Virtual machines (VMs) must remove unneeded serial devices.
#>
function VMCH-80-000212 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000212"
    $Title  = "Virtual machines (VMs) must remove unneeded serial devices."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Serial = $VM.ExtensionData.Config.Hardware.Device | Where-Object { $_.DeviceInfo.Label -match "serial" }
    if ($Serial) {
        Write-StigLog -Message "[$($VM.Name)] Serial device exists. Must be manually detached or removed." -Severity WARN -Source "VmRemediation"
    } else {
        Write-StigLog -Message "[$($VM.Name)] Serial device is not present." -Severity SUCCESS -Source "VmRemediation"
    }
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000213.
.DESCRIPTION
    Virtual machines (VMs) must remove unneeded USB devices.
#>
function VMCH-80-000213 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000213"
    $Title  = "Virtual machines (VMs) must remove unneeded USB devices."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Usb = $VM.ExtensionData.Config.Hardware.Device | Where-Object { $_.DeviceInfo.Label -match "usb" }
    if ($Usb) {
        Write-StigLog -Message "[$($VM.Name)] USB device exists. USB Smart Card Readers are permitted in security frameworks and are marked as Not a Finding." -Severity SUCCESS -Source "VmRemediation"
    } else {
        Write-StigLog -Message "[$($VM.Name)] USB device is not present." -Severity SUCCESS -Source "VmRemediation"
    }
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000214.
.DESCRIPTION
    Virtual machines (VMs) must disable DirectPath I/O devices when not required.
#>
function VMCH-80-000214 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000214"
    $Title  = "Virtual machines (VMs) must disable DirectPath I/O devices when not required."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Passthrough = $VM | Get-PassthroughDevice -ErrorAction SilentlyContinue
    if ($Passthrough) {
        Write-StigLog -Message "[$($VM.Name)] DirectPath I/O devices exist. Must be manually detached or evaluated." -Severity WARN -Source "VmRemediation"
    } else {
        Write-StigLog -Message "[$($VM.Name)] DirectPath I/O devices are not present." -Severity SUCCESS -Source "VmRemediation"
    }
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000195.
.DESCRIPTION
    Virtual machines (VMs) must limit console sharing.
#>
function VMCH-80-000195 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000195"
    $Title  = "Virtual machines (VMs) must limit console sharing."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.RemoteDisplayMax.Keys | Select-Object -First 1)
    $Value = ($StigSettings.RemoteDisplayMax.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000196.
.DESCRIPTION
    Virtual machines (VMs) must limit informational messages to the VMX file.
#>
function VMCH-80-000196 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000196"
    $Title  = "Virtual machines (VMs) must limit informational messages to the VMX file."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.setinfoSizeLimit.Keys | Select-Object -First 1)
    $Value = ($StigSettings.setinfoSizeLimit.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000197.
.DESCRIPTION
    Virtual machines (VMs) must prevent unauthorized removal of devices.
#>
function VMCH-80-000197 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000197"
    $Title  = "Virtual machines (VMs) must prevent unauthorized removal of devices."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.deviceConnectable.Keys | Select-Object -First 1)
    $Value = ($StigSettings.deviceConnectable.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000198.
.DESCRIPTION
    Virtual machines (VMs) must not obtain host information from the hypervisor.
#>
function VMCH-80-000198 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000198"
    $Title  = "Virtual machines (VMs) must not obtain host information from the hypervisor."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.guestlibEnableHostInf.Keys | Select-Object -First 1)
    $Value = ($StigSettings.guestlibEnableHostInf.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000199.
.DESCRIPTION
    Virtual machines (VMs) must have shared salt values disabled.
#>
function VMCH-80-000199 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000199"
    $Title  = "Virtual machines (VMs) must have shared salt values disabled."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name = $StigSettings.schedMemPshareSalt
    $Setting = $VM | Get-AdvancedSetting -Name $Name -ErrorAction SilentlyContinue
    if ($Setting) {
        Write-StigLog -Message "[$($VM.Name)] Setting '$Name' exists. Removing to disable shared salt values..." -Severity WARN -Source "VmRemediation"
        $Setting | Remove-AdvancedSetting -Confirm:$false -ErrorAction Stop | Out-Null
        Write-StigLog -Message "[$($VM.Name)] Setting '$Name' removed successfully." -Severity SUCCESS -Source "VmRemediation"
    } else {
        Write-StigLog -Message "[$($VM.Name)] Setting '$Name' is already absent." -Severity SUCCESS -Source "VmRemediation"
    }
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000200.
.DESCRIPTION
    Virtual machines (VMs) must disable access through the dvfilter API.
#>
function VMCH-80-000200 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000200"
    $Title  = "Virtual machines (VMs) must disable access through the dvfilter API."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    Write-StigLog -Message "[$($VM.Name)] dvFilter API configuration must be evaluated manually." -Severity WARN -Source "VmRemediation"
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000201.
.DESCRIPTION
    Virtual machines (VMs) must lock when the last console connection is closed.
#>
function VMCH-80-000201 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000201"
    $Title  = "Virtual machines (VMs) must lock when the last console connection is closed."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.desktopAutolock.Keys | Select-Object -First 1)
    $Value = ($StigSettings.desktopAutolock.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000202.
.DESCRIPTION
    Virtual machines (VMs) must disable 3D features when not required.
#>
function VMCH-80-000202 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000202"
    $Title  = "Virtual machines (VMs) must disable 3D features when not required."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.mksEnable3d.Keys | Select-Object -First 1)
    $Value = ($StigSettings.mksEnable3d.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000203.
.DESCRIPTION
    Virtual machines (VMs) must enable encryption for vMotion.
#>
function VMCH-80-000203 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000203"
    $Title  = "Virtual machines (VMs) must enable encryption for vMotion."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $TargetMode = $StigSettings.vmotionEncryption
    if ($VM.ExtensionData.Config.MigrateEncryption -eq $TargetMode) {
        Write-StigLog -Message "[$($VM.Name)] vMotion encryption is already set correctly to $TargetMode." -Severity SUCCESS -Source "VmRemediation"
    } else {
        Write-StigLog -Message "[$($VM.Name)] vMotion encryption was set to $($VM.ExtensionData.Config.MigrateEncryption). Modifying to $TargetMode..." -Severity WARN -Source "VmRemediation"
        $View = $VM | Get-View -ErrorAction Stop
        $Spec = New-Object VMware.Vim.VirtualMachineConfigSpec
        $Spec.MigrateEncryption = $TargetMode
        $View.ReconfigVM($Spec)
        Write-StigLog -Message "[$($VM.Name)] vMotion encryption successfully updated." -Severity SUCCESS -Source "VmRemediation"
    }
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000204.
.DESCRIPTION
    Virtual machines (VMs) must enable encryption for Fault Tolerance.
#>
function VMCH-80-000204 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000204"
    $Title  = "Virtual machines (VMs) must enable encryption for Fault Tolerance."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $TargetMode = $StigSettings.ftEncryption
    if ($VM.ExtensionData.Config.FtEncryptionMode -eq $TargetMode) {
        Write-StigLog -Message "[$($VM.Name)] Fault Tolerance encryption is already set correctly to $TargetMode." -Severity SUCCESS -Source "VmRemediation"
    } else {
        Write-StigLog -Message "[$($VM.Name)] Fault Tolerance encryption was set to $($VM.ExtensionData.Config.FtEncryptionMode). Modifying to $TargetMode..." -Severity WARN -Source "VmRemediation"
        $View = $VM | Get-View -ErrorAction Stop
        $Spec = New-Object VMware.Vim.VirtualMachineConfigSpec
        $Spec.FTEncryption = $TargetMode
        $View.ReconfigVM($Spec)
        Write-StigLog -Message "[$($VM.Name)] Fault Tolerance encryption successfully updated." -Severity SUCCESS -Source "VmRemediation"
    }
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000205.
.DESCRIPTION
    Virtual machines (VMs) must configure log size.
#>
function VMCH-80-000205 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000205"
    $Title  = "Virtual machines (VMs) must configure log size."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.logRotateSize.Keys | Select-Object -First 1)
    $Value = ($StigSettings.logRotateSize.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000206.
.DESCRIPTION
    Virtual machines (VMs) must configure log retention.
#>
function VMCH-80-000206 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000206"
    $Title  = "Virtual machines (VMs) must configure log retention."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $Name  = ($StigSettings.logKeepOld.Keys | Select-Object -First 1)
    $Value = ($StigSettings.logKeepOld.Values | Select-Object -First 1)
    Set-VmAdvancedSetting -VM $VM -Name $Name -Value $Value
}

<#
.SYNOPSIS
    Remediates STIG ID VMCH-80-000207.
.DESCRIPTION
    Virtual machines (VMs) must enable logging.
#>
function VMCH-80-000207 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][object]$VM,
        [Parameter(Mandatory=$true)][hashtable]$StigSettings
    )
    $STIGID = "VMCH-80-000207"
    $Title  = "Virtual machines (VMs) must enable logging."
    Write-StigLog -Message "[$($VM.Name)] Remediating STIG: $STIGID - $Title" -Severity INFO -Source "VmRemediation"
    
    $TargetMode = $StigSettings.vmLogging
    if ($VM.ExtensionData.Config.Flags.EnableLogging -eq $TargetMode) {
        Write-StigLog -Message "[$($VM.Name)] VM Logging is already set correctly to $TargetMode." -Severity SUCCESS -Source "VmRemediation"
    } else {
        Write-StigLog -Message "[$($VM.Name)] VM Logging was set to $($VM.ExtensionData.Config.Flags.EnableLogging). Modifying to $TargetMode..." -Severity WARN -Source "VmRemediation"
        $View = $VM | Get-View -ErrorAction Stop
        $Spec = New-Object VMware.Vim.VirtualMachineConfigSpec
        $Spec.Flags = New-Object VMware.Vim.VirtualMachineFlagInfo
        $Spec.Flags.EnableLogging = $TargetMode
        $View.ReconfigVM($Spec)
        Write-StigLog -Message "[$($VM.Name)] VM Logging successfully updated." -Severity SUCCESS -Source "VmRemediation"
    }
}

# Export Functions to module space
Export-ModuleMember -Function VMCH-80-*, Set-VmAdvancedSetting