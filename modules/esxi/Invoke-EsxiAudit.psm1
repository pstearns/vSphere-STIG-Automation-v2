<#
.SYNOPSIS
    Worker module for ESXi STIG Audits.
.DESCRIPTION
    Executes both PowerCLI (API) and SSH (OS-level) InSpec transports against an ESXi host.
    Outputs a PSCustomObject containing both raw JSON paths for downstream pipeline merging.
.PARAMETER Target
    A PSCustomObject containing ESXi target metadata (Name, vCenter FQDN, AdminUser, RootPass, etc.).
.PARAMETER OverlayRoot
    The base directory for the orchestration overlay. Defaults to /usr/share/stigs/orchestration_overlay.
#>

function Invoke-EsxiAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject]$Target,
        
        [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
    )

    process {
        Write-Host "[*] Initiating ESXi Worker (API + SSH) for target: $($Target.Name)" -ForegroundColor Cyan
        
        # --- Environment Initialization ---
        
        $RawJsonDir = Join-Path $OverlayRoot "reports/raw_json"
        $InputsFile = Join-Path $OverlayRoot "conf/esxi/inputs.yml"
        
        if (-not (Test-Path $RawJsonDir)) { New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null }

        # --- Dynamic Path Resolution for Base OVA Profiles ---
        # Note: Grabbing the native InSpec profiles from the OVA base directory
        $VsphereBasePath   = "/usr/share/stigs/vsphere/8.0"
        $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory | 
                             Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | 
                             Sort-Object Name -Descending | Select-Object -ExpandProperty Name -First 1

        $ApiProfilePath = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec"
        
        # If you have custom SSH overlays, define the path here. 
        # (Assuming native SSH profile for now based on your tree)
        $SshProfilePath = Join-Path $VsphereBasePath "$LatestStigRelease/customization/ESXi/vmware-esxi-8.0-stig-inspec/esxi-ssh" 

        # --- Execution Definitions ---
        
        $ApiRawOut = Join-Path $RawJsonDir "$($Target.Name)_ESXi_API_raw.json"
        $SshRawOut = Join-Path $RawJsonDir "$($Target.Name)_ESXi_SSH_raw.json"

        # 1. API Execution (PowerCLI via vCenter)
        Write-Verbose " -> Executing ESXi API Audit via vCenter"
        $ApiCmd = "cinc-auditor exec $ApiProfilePath -t vmware://$($Target.AdminUser):$($Target.AdminPass)@$($Target.vCenter) --input-file $InputsFile --reporter json:$ApiRawOut"
        Invoke-Expression "& bash -c `"$ApiCmd`"" | Out-Null

        # 2. SSH Execution (Direct to ESXi Host)
        Write-Verbose " -> Executing ESXi SSH Audit directly on host"
        # *Ensure SSH is temporarily enabled on the ESXi host prior to this step*
        $SshCmd = "cinc-auditor exec $SshProfilePath -t ssh://root@$($Target.Name) --password '$($Target.RootPass)' --input-file $InputsFile --reporter json:$SshRawOut"
        Invoke-Expression "& bash -c `"$SshCmd`"" | Out-Null

        # --- Output Stream ---
        
        if ((Test-Path $ApiRawOut) -and (Test-Path $SshRawOut)) {
            Write-Output ([PSCustomObject]@{
                TargetName    = $Target.Name
                TargetType    = "ESXi"
                DisaComponent = "ESXi"
                ApiJsonFile   = $ApiRawOut
                SshJsonFile   = $SshRawOut
            })
        } else {
            Write-Error "Failed to generate one or more JSON reports for ESXi host $($Target.Name)"
        }
    }
}

Export-ModuleMember -Function Invoke-EsxiAudit