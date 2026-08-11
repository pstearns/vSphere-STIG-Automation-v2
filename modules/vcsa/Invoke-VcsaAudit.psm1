<#
.SYNOPSIS
    Worker module for VCSA STIG Audits (10 Components).
.DESCRIPTION
    Executes PowerCLI and SSH InSpec transports in parallel to reduce overall audit 
    run times. Outputs a collection of custom objects detailing the raw JSON paths 
    and target metadata for pipeline formatting.
.PARAMETER Target
    A PSCustomObject containing vCenter target metadata (FQDN, AdminUser, RootPass, etc.).
.PARAMETER OverlayRoot
    The base directory for the orchestration overlay. Defaults to /usr/share/stigs/orchestration_overlay.
#>

function Invoke-VcsaAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject]$Target,
        
        [string]$OverlayRoot = $(if (Test-Path "/usr/share/stigs/orchestration_overlay") { "/usr/share/stigs/orchestration_overlay" } else { (Resolve-Path "$PSScriptRoot/../..").Path })
    )

    process {
        Write-Host "[*] Initiating parallel VCSA audit for target: $($Target.FQDN)" -ForegroundColor Cyan
        
        $RawJsonDir           = Join-Path $OverlayRoot "reports/raw_json"
        $InspecProfileBaseDir = Join-Path $OverlayRoot "custom/vcsa"
        $InputsFile           = Join-Path $OverlayRoot "conf/VCSA/inputs.yml"

        if (-not (Test-Path $RawJsonDir)) { New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null }

        $VcsaComponents = @(
            @{ Component = "vCenter"; Transport = "vmware"; ProfileFolder = "vcenter" },
            @{ Component = "VCSA_EAM"; Transport = "ssh"; ProfileFolder = "eam" },
            @{ Component = "VCSA_Envoy"; Transport = "ssh"; ProfileFolder = "envoy" },
            @{ Component = "VCSA_Lookup_Svc"; Transport = "ssh"; ProfileFolder = "lookup" },
            @{ Component = "VCSA_Perfcharts"; Transport = "ssh"; ProfileFolder = "perfcharts" },
            @{ Component = "VCSA_Photon_OS"; Transport = "ssh"; ProfileFolder = "photon" },
            @{ Component = "VCSA_PostgreSQL"; Transport = "ssh"; ProfileFolder = "postgresql" },
            @{ Component = "VCSA_STS"; Transport = "ssh"; ProfileFolder = "sts" },
            @{ Component = "VCSA_UI"; Transport = "ssh"; ProfileFolder = "ui" },
            @{ Component = "VCSA_VAMI"; Transport = "ssh"; ProfileFolder = "vami" }
        )

        $b64AdminPass = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Target.AdminPass))
        $b64RootPass  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Target.RootPass))

        $Results = $VcsaComponents | ForEach-Object -Parallel {
            $App                  = $_
            $Target               = $using:Target
            $InspecProfileBaseDir = $using:InspecProfileBaseDir
            $InputsFile           = $using:InputsFile
            $RawJsonDir           = $using:RawJsonDir
            $PassAdmin            = $using:b64AdminPass
            $PassRoot             = $using:b64RootPass

            $ProfilePath = Join-Path $InspecProfileBaseDir $App.ProfileFolder
            $RawOut      = Join-Path $RawJsonDir "$($Target.FQDN)_$($App.Component)_raw.json"

            if ($App.Transport -eq "vmware") {
                $Cmd = "VISERVER_PASSWORD=`"`$(echo '$PassAdmin' | base64 -d)`" cinc-auditor exec $ProfilePath -t vmware://$($Target.AdminUser)@$($Target.FQDN) --input-file $InputsFile --reporter json:$RawOut"
            } else {
                $Cmd = "cinc-auditor exec $ProfilePath -t ssh://root@$($Target.FQDN) --password `"`$(echo '$PassRoot' | base64 -d)`" --input-file $InputsFile --reporter json:$RawOut"
            }

            Invoke-Expression "& bash -c `"$Cmd`"" | Out-Null

            if (Test-Path $RawOut) {
                [PSCustomObject]@{ TargetName = $Target.FQDN; TargetType = "VCSA"; DisaComponent = $App.Component; RawJsonFile = $RawOut }
            } else {
                Write-Error "Failed to generate JSON report for $($App.Component) on $($Target.FQDN)"
            }
        } -ThrottleLimit 10 
        
        $Results | Write-Output
    }
}
Export-ModuleMember -Function Invoke-VcsaAudit