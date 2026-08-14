<#
.SYNOPSIS
    Worker module for Virtual Machine STIG Audits with Custom API Overlay.
#>
function Invoke-VmAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$TargetList,
        
        [string]$OverlayRoot = $(if (Test-Path "/usr/share/stigs/orchestration_overlay") { "/usr/share/stigs/orchestration_overlay" } else { (Resolve-Path "$PSScriptRoot/../..").Path })
    )

    Write-Host "[*] Initiating Parallel VM Audits for $($TargetList.Count) targets..." -ForegroundColor Cyan

    $TargetList | ForEach-Object -Parallel {
        $Target = $_
        $OverlayRoot = $using:OverlayRoot
        
        $GlobalFuncs = (Get-Content (Join-Path $OverlayRoot "modules/globalFunctions.psm1") -Raw) -replace "(?m)^Export-ModuleMember.*`$", ""
        Invoke-Expression $GlobalFuncs
        
        $VmHelpers = (Get-Content (Join-Path $OverlayRoot "modules/vm/VmHelpers.psm1") -Raw) -replace "(?m)^Export-ModuleMember.*`$", ""
        Invoke-Expression $VmHelpers

        Write-Host " -> [$($Target.Name)] Executing VM API Audit via vCenter..." -ForegroundColor DarkGray
        
        $RawJsonDir = "/tmp/stig_staging/$($Target.Name)"
        if (-not (Test-Path $RawJsonDir)) { New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null }

        $InputsFile = Join-Path $OverlayRoot "conf/vm/inputs.yml"
        
        # Call the Helper for Asset Data
        $NetInfo = Get-VmNetworkInfo -vCenter $Target.vCenter -AdminUser $Target.AdminUser -AdminPass $Target.AdminPass -VmName $Target.Name

        $VsphereBasePath   = "/usr/share/stigs/vsphere/8.0"
        $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory | Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | Sort-Object Name -Descending | Select-Object -ExpandProperty Name -First 1
        
        $ApiProfilePath = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/vm"
        $RawOut         = Join-Path $RawJsonDir "$($Target.Name)_Virtual_Machine_raw.json"

        # Define Custom Profile Paths
        $CustomApiProfilePath = Join-Path $OverlayRoot "custom_profiles/vm/inspec/api"
        $CustomApiRawOut      = Join-Path $RawJsonDir "$($Target.Name)_VM_CUSTOM_API_raw.json"

        $b64AdminPass = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Target.AdminPass))
        $InputArg = if (Test-Path $InputsFile) { "--input-file '$InputsFile'" } else { "" }
        
        # -------------------------------------------------------------
        # Phase 1: Base API Audit
        # -------------------------------------------------------------
        $Cmd = "VISERVER='$($Target.vCenter)' VISERVER_USERNAME='$($Target.AdminUser)' VISERVER_PASSWORD=`"`$(echo '$b64AdminPass' | base64 -d)`" cinc-auditor exec '$ApiProfilePath' -t vmware:// $InputArg --input vmName=`"$($Target.Name)`" --reporter json:'$RawOut'"
        $BashOutput = bash -c $Cmd 2>&1

        # -------------------------------------------------------------
        # Phase 2: Custom API Overlay Execution
        # -------------------------------------------------------------
        if (Test-Path (Join-Path $CustomApiProfilePath "inspec.yml")) {
            Write-Host " -> [$($Target.Name)] Executing Custom VM API Overlay..." -ForegroundColor DarkCyan
            $CustomApiCmd = "VISERVER='$($Target.vCenter)' VISERVER_USERNAME='$($Target.AdminUser)' VISERVER_PASSWORD=`"`$(echo '$b64AdminPass' | base64 -d)`" cinc-auditor exec '$CustomApiProfilePath' -t vmware:// $InputArg --input vmName=`"$($Target.Name)`" --reporter json:'$CustomApiRawOut'"
            $CustomBashOutput = bash -c $CustomApiCmd 2>&1
        }

        # -------------------------------------------------------------
        # Phase 3: Format Pipeline Output
        # -------------------------------------------------------------
        if (Test-Path $RawOut) {
            [PSCustomObject]@{ 
                TargetName        = $Target.Name
                TargetType        = "VM" 
                DisaComponent     = "Virtual_Machine" 
                RawJsonFile       = $RawOut 
                CustomApiJsonFile = if (Test-Path $CustomApiRawOut) { $CustomApiRawOut } else { $null }
                CustomSshJsonFile = $null
                vCenterShortName  = $Target.vCenterShortName
                DateStr           = $Target.DateStr
                IPAddress         = $NetInfo.IPAddress 
                MACAddress        = $NetInfo.MACAddress
                DNSName           = $NetInfo.DNSName
            }
        } else {
            Write-StigLog -Message "Scan failed to produce JSON for $($Target.Name). Cinc-Auditor Error: $BashOutput" -Severity ERROR -Source "VmWorker"
        }
    } -ThrottleLimit 15
}
Export-ModuleMember -Function Invoke-VmAudit