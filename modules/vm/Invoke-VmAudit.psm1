<#
.SYNOPSIS
    Worker module for Virtual Machine STIG Audits.
.DESCRIPTION
    Executes native vSphere API (vmware://) InSpec transports for VMs.
    Outputs a PSCustomObject containing the raw JSON path for downstream formatting.
.PARAMETER Target
    A PSCustomObject containing VM target metadata (Name, vCenter FQDN, AdminUser, etc.).
.PARAMETER OverlayRoot
    The base directory for the orchestration overlay.
#>

function Invoke-VmAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject]$Target,
        
        [string]$OverlayRoot = $(if (Test-Path "/usr/share/stigs/orchestration_overlay") { "/usr/share/stigs/orchestration_overlay" } else { (Resolve-Path "$PSScriptRoot/../..").Path })
    )

    process {
        Write-Host "[*] Initiating VM Worker for target: $($Target.Name)" -ForegroundColor Cyan
        
        $RawJsonDir = Join-Path $OverlayRoot "reports/raw_json"
        $InputsFile = Join-Path $OverlayRoot "conf/vm/inputs.yml"
        
        if (-not (Test-Path $RawJsonDir)) { New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null }

        $VsphereBasePath   = "/usr/share/stigs/vsphere/8.0"
        $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory | 
                             Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | 
                             Sort-Object Name -Descending | Select-Object -ExpandProperty Name -First 1

        $ApiProfilePath = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/vm"
        $RawOut         = Join-Path $RawJsonDir "$($Target.Name)_Virtual_Machine_raw.json"

        # Base64 encode the password to prevent bash command injection and URI formatting errors
        $b64AdminPass = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Target.AdminPass))

        Write-Verbose " -> Executing VM API Audit via vCenter"
        # Prepend VISERVER_PASSWORD specifically for this bash command execution
        $Cmd = "VISERVER_PASSWORD=`"`$(echo '$b64AdminPass' | base64 -d)`" cinc-auditor exec $ApiProfilePath -t vmware://$($Target.AdminUser)@$($Target.vCenter) --input-file $InputsFile --input vm_name=$($Target.Name) --reporter json:$RawOut"
        
        Invoke-Expression "& bash -c `"$Cmd`"" | Out-Null

        if (Test-Path $RawOut) {
            Write-Output ([PSCustomObject]@{ TargetName = $Target.Name; TargetType = "VM"; DisaComponent = "Virtual_Machine"; RawJsonFile = $RawOut })
        } else {
            Write-Error "Failed to generate JSON report for VM $($Target.Name)"
        }
    }
}
Export-ModuleMember -Function Invoke-VmAudit