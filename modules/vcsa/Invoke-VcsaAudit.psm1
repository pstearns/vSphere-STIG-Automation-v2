<#
.SYNOPSIS
    Worker module for VCSA STIG Audits (10 Components).
.DESCRIPTION
    Executes PowerCLI and SSH InSpec transports. Implements a 3-Phase approach 
    to toggle SSH securely so the vCenter API audit passes its STIG checks, 
    while the 9 VCSA services execute in parallel.
#>
function Invoke-VcsaAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject]$Target,
        
        [string]$OverlayRoot = $(if (Test-Path "/usr/share/stigs/orchestration_overlay") { "/usr/share/stigs/orchestration_overlay" } else { (Resolve-Path "$PSScriptRoot/../..").Path })
    )

    process {
        Write-Host "[*] Initiating VCSA audit for target: $($Target.FQDN)" -ForegroundColor Cyan
        
        $RawJsonDir = $Target.ReportDir
        if (-not (Test-Path $RawJsonDir)) { New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null }

        $NetInfo = Get-VCSANetworkInfo -FQDN $Target.FQDN -Username $Target.AdminUser -Password $Target.AdminPass

        $VsphereBasePath   = "/usr/share/stigs/vsphere/8.0"
        $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory | Sort-Object Name -Descending | Select-Object -ExpandProperty Name -First 1
        $VsphereProfileBaseDir = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline"
        $VcsaProfileBaseDir    = Join-Path $VsphereBasePath "$LatestStigRelease/vcsa/inspec/vmware-vcsa-8.0-stig-baseline"
        
        $InputsFile = Join-Path $OverlayRoot "conf/vcsa/inputs.yml"
        if (-not (Test-Path $InputsFile)) { Throw "CRITICAL: Custom inputs.yml not found." }

        $VcsaComponents = @(
            @{ Component = "vCenter";         Transport = "vmware"; ProfileFolder = "vcenter" },
            @{ Component = "VCSA_EAM";        Transport = "ssh";    ProfileFolder = "eam" },
            @{ Component = "VCSA_Envoy";      Transport = "ssh";    ProfileFolder = "envoy" },
            @{ Component = "VCSA_Lookup_Svc"; Transport = "ssh";    ProfileFolder = "lookup" },
            @{ Component = "VCSA_Perfcharts"; Transport = "ssh";    ProfileFolder = "perfcharts" },
            @{ Component = "VCSA_Photon_OS";  Transport = "ssh";    ProfileFolder = "photon" },
            @{ Component = "VCSA_PostgreSQL"; Transport = "ssh";    ProfileFolder = "postgresql" },
            @{ Component = "VCSA_STS";        Transport = "ssh";    ProfileFolder = "sts" },
            @{ Component = "VCSA_UI";         Transport = "ssh";    ProfileFolder = "ui" },
            @{ Component = "VCSA_VAMI";       Transport = "ssh";    ProfileFolder = "vami" }
        )

        $b64AdminPass = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Target.AdminPass))
        $b64RootPass  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Target.RootPass))

        $ApiComponent  = $VcsaComponents | Where-Object { $_.Transport -eq "vmware" }
        $SshComponents = $VcsaComponents | Where-Object { $_.Transport -eq "ssh" }
        $AllResults    = @()

        Write-Host "[*] Disabling SSH & Running vCenter API Audit..." -ForegroundColor Cyan
        Set-VCSASshState -FQDN $Target.FQDN -Username $Target.AdminUser -Password $Target.AdminPass -Enabled $false

        $RawOut      = Join-Path $RawJsonDir "$($Target.FQDN)_$($ApiComponent.Component)_raw.json"
        $ProfilePath = Join-Path $VsphereProfileBaseDir $ApiComponent.ProfileFolder
        $Cmd = "VISERVER='$($Target.FQDN)' VISERVER_USERNAME='$($Target.AdminUser)' VISERVER_PASSWORD=`"`$(echo '$b64AdminPass' | base64 -d)`" cinc-auditor exec $ProfilePath -t vmware:// --input-file $InputsFile --reporter json:$RawOut"
        
        bash -c $Cmd | Out-Null

        if (Test-Path $RawOut) {
            $AllResults += [PSCustomObject]@{ 
                TargetName       = $Target.FQDN; 
                TargetType       = "VCSA"; 
                DisaComponent    = $ApiComponent.Component; 
                RawJsonFile      = $RawOut;
                vCenterShortName = $Target.vCenterShortName;
                DateStr          = $Target.DateStr;
                IPAddress        = $NetInfo.IPAddress;
                MACAddress       = $NetInfo.MACAddress
            }
        }

        Write-Host "[*] Enabling SSH & Running 9 VCSA Services in parallel..." -ForegroundColor Cyan
        Set-VCSASshState -FQDN $Target.FQDN -Username $Target.AdminUser -Password $Target.AdminPass -Enabled $true

        $PreFlightSuccess = Set-VCSABashShell -FQDN $Target.FQDN -RootPassword $Target.RootPass
        if (-not $PreFlightSuccess) {
            Throw "CRITICAL: Pre-flight shell verification failed for $($Target.FQDN)."
        }

        $SshResults = $SshComponents | ForEach-Object -Parallel {
            $App                = $_
            $Target             = $using:Target
            $NetInfo            = $using:NetInfo
            $VcsaProfileBaseDir = $using:VcsaProfileBaseDir
            $InputsFile         = $using:InputsFile
            $RawJsonDir         = $using:RawJsonDir
            $PassRoot           = $using:b64RootPass

            $RawOut      = Join-Path $RawJsonDir "$($Target.FQDN)_$($App.Component)_raw.json"
            $ProfilePath = Join-Path $VcsaProfileBaseDir $App.ProfileFolder
            
            $Cmd = "cinc-auditor exec $ProfilePath -t ssh://root@$($Target.FQDN) --password `"`$(echo '$PassRoot' | base64 -d)`" --input-file $InputsFile --reporter json:$RawOut"
            bash -c $Cmd | Out-Null

            if (Test-Path $RawOut) {
                [PSCustomObject]@{ 
                    TargetName       = $Target.FQDN; 
                    TargetType       = "VCSA"; 
                    DisaComponent    = $App.Component; 
                    RawJsonFile      = $RawOut;
                    vCenterShortName = $Target.vCenterShortName;
                    DateStr          = $Target.DateStr;
                    IPAddress        = $NetInfo.IPAddress;
                    MACAddress       = $NetInfo.MACAddress
                }
            } else {
                Write-Error "Failed to generate JSON report for $($App.Component) on $($Target.FQDN)"
            }
        } -ThrottleLimit 10 
        
        $AllResults += $SshResults

        Write-Host "[*] Audits Complete. Securing appliance (Disabling SSH)..." -ForegroundColor Cyan
        Set-VCSASshState -FQDN $Target.FQDN -Username $Target.AdminUser -Password $Target.AdminPass -Enabled $false

        # Output to formatting pipeline
        $AllResults | Write-Output
    }
}

Export-ModuleMember -Function Invoke-VcsaAudit