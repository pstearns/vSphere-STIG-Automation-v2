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
        
        $RawJsonDir = "/tmp/stig_staging/$($Target.FQDN)"
        if (-not (Test-Path $RawJsonDir)) { New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null }

        # Configure PowerCLI persistently in User scope so InSpec's spawned subprocesses inherit the bypass
        try {
            Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope User | Out-Null
        } catch {
            Write-Warning "Could not configure PowerCLI certificate validation bypass: $_"
        }

        # Helper functions use the API (Invoke-RestMethod) directly
        $NetInfo = Get-VCSANetworkInfo -FQDN $Target.FQDN -Username $Target.AdminUser -Password $Target.AdminPass

        $VsphereBasePath   = "/usr/share/stigs/vsphere/8.0"
        $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory | Sort-Object Name -Descending | Select-Object -ExpandProperty Name -First 1
        $VsphereProfileBaseDir = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline"
        $VcsaProfileBaseDir    = Join-Path $VsphereBasePath "$LatestStigRelease/vcsa/inspec/vmware-vcsa-8.0-stig-baseline"
        
        $InputsFile = Join-Path $OverlayRoot "conf/vcsa/inputs.yml"
        if (-not (Test-Path $InputsFile)) { Throw "CRITICAL: Custom inputs.yml not found." }

        # --- Define Custom Profile Paths ---
        $CustomApiProfilePath = Join-Path $OverlayRoot "custom_profiles/vcsa/inspec/api"
        $CustomSshProfilePath = Join-Path $OverlayRoot "custom_profiles/vcsa/inspec/ssh"
        
        $CustomApiRawOut = Join-Path $RawJsonDir "$($Target.FQDN)_VCSA_CUSTOM_API_raw.json"
        $CustomSshRawOut = Join-Path $RawJsonDir "$($Target.FQDN)_VCSA_CUSTOM_SSH_raw.json"

        $VcsaComponents = @(
            @{ Component = "vCenter";        Transport = "vmware"; ProfileFolder = "vcenter" },
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

        $ApiComponent  = $VcsaComponents | Where-Object { $_.Transport -eq "vmware" }
        $SshComponents = $VcsaComponents | Where-Object { $_.Transport -eq "ssh" }
        $AllResults    = @()

        # -------------------------------------------------------------
        # PHASE 1: API (PowerCLI) Executions
        # -------------------------------------------------------------
        try {
            Write-Host "[*] Disabling SSH & Running vCenter API Audit..." -ForegroundColor Cyan
            Set-VCSASshState -FQDN $Target.FQDN -Username $Target.AdminUser -Password $Target.AdminPass -Enabled $false

            $RawOut      = Join-Path $RawJsonDir "$($Target.FQDN)_$($ApiComponent.Component)_raw.json"
            $ProfilePath = Join-Path $VsphereProfileBaseDir $ApiComponent.ProfileFolder
            
            # FIXED: Set environment variables directly in PowerShell Process (No escaping or Base64 required)
            $env:VISERVER          = $Target.FQDN
            $env:VISERVER_USERNAME = $Target.AdminUser
            $env:VISERVER_PASSWORD = $Target.AdminPass
            
            # FIXED: Force ANSI color stripping so the VMware train parser does not break in PowerShell 7.2.1+
            $env:NO_COLOR          = "true"

            # FIXED: Invoke cinc-auditor directly (PowerShell handles native parameter passing literally and securely)
            cinc-auditor exec $ProfilePath -t vmware:// --insecure --input-file $InputsFile --reporter json:$RawOut | Out-Null

            if (Test-Path (Join-Path $CustomApiProfilePath "inspec.yml")) {
                Write-Host " -> [$($Target.FQDN)] Executing Custom VCSA API Overlay..." -ForegroundColor DarkCyan
                cinc-auditor exec $CustomApiProfilePath -t vmware:// --insecure --input-file $InputsFile --reporter json:$CustomApiRawOut 2>&1 | Out-Null
            }

            # Cleanup process-level API environment variables
            Remove-Item env:VISERVER -ErrorAction SilentlyContinue
            Remove-Item env:VISERVER_USERNAME -ErrorAction SilentlyContinue
            Remove-Item env:VISERVER_PASSWORD -ErrorAction SilentlyContinue
            Remove-Item env:NO_COLOR -ErrorAction SilentlyContinue

            if (Test-Path $RawOut) {
                $AllResults += [PSCustomObject]@{ 
                    TargetName       = $Target.FQDN; 
                    TargetType       = "VCSA"; 
                    DisaComponent    = $ApiComponent.Component; 
                    RawJsonFile      = $RawOut;
                    CustomApiJsonFile= if (Test-Path $CustomApiRawOut) { $CustomApiRawOut } else { $null };
                    CustomSshJsonFile= $null;
                    vCenterShortName = $Target.vCenterShortName;
                    DateStr          = $Target.DateStr;
                    IPAddress        = $NetInfo.IPAddress;
                    MACAddress       = $NetInfo.MACAddress
                }
            } else {
                Write-Warning "Failed to generate JSON report for $($ApiComponent.Component) on $($Target.FQDN)"
            }
        } catch {
            Write-Warning "Exception caught during Phase 1 (vCenter API) execution: $_"
        }

        # -------------------------------------------------------------
        # PHASE 2: SSH Executions
        # -------------------------------------------------------------
        try {
            Write-Host "[*] Enabling SSH & Running VCSA Services..." -ForegroundColor Cyan
            Set-VCSASshState -FQDN $Target.FQDN -Username $Target.AdminUser -Password $Target.AdminPass -Enabled $true

            $PreFlightSuccess = Set-VCSABashShell -FQDN $Target.FQDN -RootPassword $Target.RootPass
            if (-not $PreFlightSuccess) {
                Throw "CRITICAL: Pre-flight shell verification failed for $($Target.FQDN)."
            }

            if (Test-Path (Join-Path $CustomSshProfilePath "inspec.yml")) {
                Write-Host " -> [$($Target.FQDN)] Executing Custom VCSA SSH Overlay..." -ForegroundColor DarkCyan
                # FIXED: Direct native parameter execution
                cinc-auditor exec $CustomSshProfilePath -t ssh://root@$($Target.FQDN) --password $Target.RootPass --insecure --input-file $InputsFile --reporter json:$CustomSshRawOut 2>&1 | Out-Null
            }

            $SshResults = $SshComponents | ForEach-Object -Parallel {
                $App                = $_
                $Target             = $using:Target
                $NetInfo            = $using:NetInfo
                $VcsaProfileBaseDir = $using:VcsaProfileBaseDir
                $InputsFile         = $using:InputsFile
                $RawJsonDir         = $using:RawJsonDir

                $RawOut      = Join-Path $RawJsonDir "$($Target.FQDN)_$($App.Component)_raw.json"
                $ProfilePath = Join-Path $VcsaProfileBaseDir $App.ProfileFolder
                
                # FIXED: Direct native execution prevents password variable expansion issues in parallel blocks
                cinc-auditor exec $ProfilePath -t ssh://root@$($Target.FQDN) --password $Target.RootPass --input-file $InputsFile --reporter json:$RawOut | Out-Null

                if (Test-Path $RawOut) {
                    [PSCustomObject]@{ 
                        TargetName       = $Target.FQDN; 
                        TargetType       = "VCSA"; 
                        DisaComponent    = $App.Component; 
                        RawJsonFile      = $RawOut;
                        CustomApiJsonFile= $null;
                        CustomSshJsonFile= if (Test-Path $using:CustomSshRawOut) { $using:CustomSshRawOut } else { $null };
                        vCenterShortName = $Target.vCenterShortName;
                        DateStr          = $Target.DateStr;
                        IPAddress        = $NetInfo.IPAddress;
                        MACAddress       = $NetInfo.MACAddress
                    }
                } else {
                    Write-Warning "Failed to generate JSON report for $($App.Component) on $($Target.FQDN)"
                }
            } -ThrottleLimit 10 
            
            if ($SshResults) {
                $AllResults += $SshResults
            }
        } catch {
            Write-Warning "Exception caught during Phase 2 (SSH Services) execution: $_"
        }

        # -------------------------------------------------------------
        # CLEANUP: Secure Target
        # -------------------------------------------------------------
        try {
            Write-Host "[*] Audits Complete. Securing appliance (Disabling SSH)..." -ForegroundColor Cyan
            Set-VCSASshState -FQDN $Target.FQDN -Username $Target.AdminUser -Password $Target.AdminPass -Enabled $false
        } catch {
            Write-Warning "Could not secure target (disable SSH): $_"
        }

        $AllResults | Write-Output
    }
}

Export-ModuleMember -Function Invoke-VcsaAudit