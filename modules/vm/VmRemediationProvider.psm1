# =========================================================================
# PROVIDER: VmRemediationProvider.psm1
# DESCRIPTION: Manages VM compliance remediation using PowerCLI SDK.
# =========================================================================

function Get-AssetProviderConfig {
    param([string]$OverlayRoot)
    
    $VsphereBasePath = "/usr/share/stigs/vsphere/8.0"
    $ApiProfilePath = Get-ChildItem -Path $VsphereBasePath -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -eq "vm" -and $_.Parent.Name -match "vmware-vsphere-8.0-.*"
    } | Select-Object -ExpandProperty FullName -First 1

    if (-not $ApiProfilePath) {
        $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | 
            Sort-Object Name -Descending | 
            Select-Object -ExpandProperty Name -First 1
        
        if ($LatestStigRelease) {
            $ApiProfilePath = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/vm"
        }
    }

    if (-not $ApiProfilePath -or -not (Test-Path $ApiProfilePath)) {
        $ApiProfilePath = Join-Path $OverlayRoot "sourceDir/vsphere/inspec/vmware-vsphere-8.0-vm-baseline"
    }

    return [PSCustomObject]@{
        AnswersXml   = Join-Path $OverlayRoot "conf/vm/answers.xml"
        InputsYml    = Join-Path $OverlayRoot "conf/vm/inputs.yml"
        InspecAPI    = $ApiProfilePath
        FuncsModule  = Join-Path $OverlayRoot "modules/vm/VmRemediationFunctions.psm1"
    }
}

function Get-AssetObject {
    param([string]$Name)
    return Get-VM -Name $Name -ErrorAction SilentlyContinue
}

function Invoke-AssetRemediation {
    param(
        [object]$AssetObject,
        [array]$FixList,
        [object]$Config,
        [object]$Creds
    )
    
    $SuccessFixes = [System.Collections.Generic.List[string]]::new()

    if (Test-Path $Config.FuncsModule) {
        Import-Module $Config.FuncsModule -Force -DisableNameChecking -WarningAction SilentlyContinue
    } else {
        Write-Warning "VM Remediation functions module missing at: $($Config.FuncsModule)"
        return @()
    }

    $DefaultVmSettings = [ordered]@{
        copyDisable           = @{"isolation.tools.copy.disable"           = $true}        #VMCH-80-000189
        dndDisable            = @{"isolation.tools.dnd.disable"            = $true}        #VMCH-80-000191
        pasteDisable          = @{"isolation.tools.paste.disable"          = $true}        #VMCH-80-000192
        diskShrink            = @{"isolation.tools.diskShrink.disable"     = $true}        #VMCH-80-000193
        diskWiper             = @{"isolation.tools.diskWiper.disable"      = $true}        #VMCH-80-000194
        RemoteDisplayMax       = @{"RemoteDisplay.maxConnections"           = "1"}          #VMCH-80-000195
        setinfoSizeLimit       = @{"tools.setinfo.sizeLimit"                = "1048576"}    #VMCH-80-000196
        deviceConnectable      = @{"isolation.device.connectable.disable"   = $true}        #VMCH-80-000197
        guestlibEnableHostInf  = @{"tools.guestlib.enableHostInfo"          = $false }      #VMCH-80-000198
        desktopAutolock        = @{"tools.guest.desktop.autolock"           = $true}        #VMCH-80-000201
        mksEnable3d            = @{"mks.enable3d"                           = $false}       #VMCH-80-000202
        logRotateSize          = @{"log.rotateSize"                         = "2048000"}    #VMCH-80-000205
        logKeepOld             = @{"log.keepOld"                            = "10"}         #VMCH-80-000206
        schedMemPshareSalt     = "sched.mem.pshare.salt"                                    #VMCH-80-000199
        vmotionEncryption      = "opportunistic"                                            #VMCH-80-000203
        ftEncryption           = "ftEncryptionOpportunistic"                                #VMCH-80-000204
        vmLogging              = $true                                                      #VMCH-80-000207
    }

    foreach ($StigID in $FixList) {
        try {
            Write-Host " [VM] Executing fix $StigID on $($AssetObject.Name)"
            & $StigID -vm $AssetObject -stigsettings $DefaultVmSettings
            $SuccessFixes.Add($StigID)
        }
        catch {
            # Corrected: Write-Warning logs the event without interrupting execution flow
            Write-Warning "Failed to apply VM fix $StigID on $($AssetObject.Name). Error: $_"
        }
    }

    return $SuccessFixes.ToArray()
}

function Get-AssetVerificationArgs {
    param($Job, $Config, $DeltaJson)
    
    $InputArgString = ""
    if (Test-Path $Config.InputsYml) {
        $InputArgString = "--input-file '$($Config.InputsYml)'"
    }
    
    $Controls = $Job.FixedRules -join " "
    return "exec '$($Config.InspecAPI)' -t vmware:// --input vmName='$($Job.VcenterObjName)' --reporter json:'$DeltaJson' $InputArgString --controls $Controls"
}