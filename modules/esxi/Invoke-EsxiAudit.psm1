<#
.SYNOPSIS
    Worker module for ESXi STIG Audits.
.DESCRIPTION
    Executes both PowerCLI (API) and SSH (OS-level) InSpec transports against ESXi hosts.
    Processes targets in parallel, implementing a phase-based approach to toggle 
    Lockdown Mode and SSH securely per host.
#>
function Invoke-EsxiAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$TargetList,
        
        [string]$OverlayRoot = $(if (Test-Path "/usr/share/stigs/orchestration_overlay") { "/usr/share/stigs/orchestration_overlay" } else { (Resolve-Path "$PSScriptRoot/../..").Path })
    )

    Write-Host "[*] Initiating parallel ESXi audits for $($TargetList.Count) targets..." -ForegroundColor Cyan

    $TargetList | ForEach-Object -Parallel {
        $Target = $_
        $OverlayRoot = $using:OverlayRoot

        $GlobalFuncs = (Get-Content (Join-Path $OverlayRoot "modules/globalFunctions.psm1") -Raw) -replace "(?m)^Export-ModuleMember.*`$", ""
        Invoke-Expression $GlobalFuncs

        $EsxiHelpers = (Get-Content (Join-Path $OverlayRoot "modules/esxi/EsxiHelpers.psm1") -Raw) -replace "(?m)^Export-ModuleMember.*`$", ""
        Invoke-Expression $EsxiHelpers

        Write-Host " -> [$($Target.Name)] Executing ESXi Audit phases..." -ForegroundColor DarkGray
        
        # Directory structure initialization
        $RawJsonDir = "/tmp/stig_staging/$($Target.Name)"
        if (-not (Test-Path $RawJsonDir)) { New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null }

        $InputsFile = Join-Path $OverlayRoot "conf/esxi/inputs.yml"
        
        # Retrieve asset metadata via helper module
        $NetInfo = Get-EsxiNetworkInfo -vCenter $Target.vCenter -AdminUser $Target.AdminUser -AdminPass $Target.AdminPass -EsxiHost $Target.Name

        # Dynamic profile path resolution
        $VsphereBasePath   = "/usr/share/stigs/vsphere/8.0"
        $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory | Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | Sort-Object Name -Descending | Select-Object -ExpandProperty Name -First 1
        
        $ApiProfilePath = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/esxi"
        
        # --- Define Custom Profile Paths ---
        $CustomApiProfilePath = Join-Path $OverlayRoot "custom_profiles/esxi/inspec/api"
        $CustomSshProfilePath = Join-Path $OverlayRoot "custom_profiles/esxi/inspec/ssh"
        
        $BaseCustomization = Join-Path $VsphereBasePath "$LatestStigRelease/customization"
        $SshProfileMatch   = Get-ChildItem -Path $BaseCustomization -Recurse -Directory -Filter "esxi-ssh" -ErrorAction SilentlyContinue | Select-Object -First 1
        $SshProfilePath    = if ($SshProfileMatch) { $SshProfileMatch.FullName } else { $null }

        # --- Define Output Paths Upfront (Fixes Variable Scope) ---
        $ApiRawOut       = Join-Path $RawJsonDir "$($Target.Name)_ESXi_API_raw.json"
        $SshRawOut       = Join-Path $RawJsonDir "$($Target.Name)_ESXi_SSH_raw.json"
        $CustomApiRawOut = Join-Path $RawJsonDir "$($Target.Name)_ESXi_CUSTOM_API_raw.json"
        $CustomSshRawOut = Join-Path $RawJsonDir "$($Target.Name)_ESXi_CUSTOM_SSH_raw.json"

        # Base64 encode credentials to prevent command injection
        $b64RootPass  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Target.RootPass))
        $InputArg = if (Test-Path $InputsFile) { "--input-file '$InputsFile'" } else { "" }

        $HasBaseSsh   = ($null -ne $SshProfilePath -and (Test-Path $SshProfilePath))
        $HasCustomSsh = (Test-Path (Join-Path $CustomSshProfilePath "inspec.yml"))

        # -------------------------------------------------------------
        # PHASE 1: SSH Executions (Open Access -> Audit -> Close Access)
        # -------------------------------------------------------------
        if ($HasBaseSsh -or $HasCustomSsh) {
            # Open SSH access and disable lockdown
            Set-EsxiAccessState -vCenter $Target.vCenter -AdminUser $Target.AdminUser -AdminPass $Target.AdminPass -EsxiHost $Target.Name -Enabled $true

            try {
                if ($HasBaseSsh) {
                    $SshCmd = "cinc-auditor exec '$SshProfilePath' -t ssh://root@$($Target.Name) --password `"`$(echo '$b64RootPass' | base64 -d)`" $InputArg --reporter json:'$SshRawOut'"
                    $SshBashOutput = bash -c $SshCmd 2>&1
                    if (-not (Test-Path $SshRawOut)) { 
                        Write-StigLog -Message "SSH Audit failed to produce JSON for $($Target.Name). Output: $SshBashOutput" -Severity WARN -Source "EsxiWorker" 
                    }
                }

                if ($HasCustomSsh) {
                    Write-Host " -> [$($Target.Name)] Executing Custom ESXi SSH Overlay..." -ForegroundColor DarkCyan
                    
                    $CustomSshCmd = "cinc-auditor exec '$CustomSshProfilePath' -t ssh://root@$($Target.Name) --password `"`$(echo '$b64RootPass' | base64 -d)`" $InputArg --reporter json:'$CustomSshRawOut'"
                    $CustomSshBashOutput = bash -c $CustomSshCmd 2>&1
                    
                    if (-not (Test-Path $CustomSshRawOut)) {
                        Write-Host "    [DEBUG] Custom SSH Run Failed!" -ForegroundColor Red
                        Write-Host "    [DEBUG] RAW OUTPUT START:" -ForegroundColor Red
                        Write-Host $CustomSshBashOutput -ForegroundColor Gray
                        Write-Host "    [DEBUG] RAW OUTPUT END" -ForegroundColor Red
                    }
                }
            } finally {
                # Ensure the host is ALWAYS locked down before API audits run
                Set-EsxiAccessState -vCenter $Target.vCenter -AdminUser $Target.AdminUser -AdminPass $Target.AdminPass -EsxiHost $Target.Name -Enabled $false
            }
        } else {
            Write-StigLog -Message "No SSH Profiles found (Base or Custom). Skipped SSH phases for $($Target.Name)." -Severity WARN -Source "EsxiWorker"
        }

        # -------------------------------------------------------------
        # PHASE 2: API (PowerCLI) Executions against Secured Host
        # -------------------------------------------------------------
        Write-Host " -> [$($Target.Name)] Executing API Audits..." -ForegroundColor DarkGray
        
        # Securely build the process environment (avoids Bash string injection and fixes SSL)
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "bash"
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.RedirectStandardError = $true
        
        # Inject credentials directly as process environment variables
        $ProcessInfo.EnvironmentVariables["VISERVER"]          = $Target.vCenter
        $ProcessInfo.EnvironmentVariables["VISERVER_USERNAME"] = $Target.AdminUser
        $ProcessInfo.EnvironmentVariables["VISERVER_PASSWORD"] = $Target.AdminPass
        $ProcessInfo.EnvironmentVariables["VISERVER_INSECURE"] = "true" # Forces cinc-auditor to bypass strict SSL checks

        # Execute Base API
        $ProcessInfo.Arguments = "-c `"cinc-auditor exec '$ApiProfilePath' -t vmware:// $InputArg --input vmhostName='$($Target.Name)' --reporter json:'$ApiRawOut'`""
        $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
        $ApiBashOutput = $Process.StandardOutput.ReadToEnd() + $Process.StandardError.ReadToEnd()
        $Process.WaitForExit()

        if (-not (Test-Path $ApiRawOut)) { 
            Write-StigLog -Message "API Audit failed to produce JSON for $($Target.Name). Output: $ApiBashOutput" -Severity WARN -Source "EsxiWorker" 
        }

        # Execute Custom API
        if (Test-Path (Join-Path $CustomApiProfilePath "inspec.yml")) {
            Write-Host " -> [$($Target.Name)] Executing Custom ESXi API Overlay..." -ForegroundColor DarkCyan
            
            $ProcessInfo.Arguments = "-c `"cinc-auditor exec '$CustomApiProfilePath' -t vmware:// $InputArg --input vmhostName='$($Target.Name)' --reporter json:'$CustomApiRawOut'`""
            $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
            $CustomApiBashOutput = $Process.StandardOutput.ReadToEnd() + $Process.StandardError.ReadToEnd()
            $Process.WaitForExit()
            
            if (-not (Test-Path $CustomApiRawOut)) {
                Write-Host "    [DEBUG] Custom API Run Failed!" -ForegroundColor Red
                Write-Host "    [DEBUG] RAW API OUTPUT START:" -ForegroundColor Red
                Write-Host $CustomApiBashOutput -ForegroundColor Gray
                Write-Host "    [DEBUG] RAW API OUTPUT END" -ForegroundColor Red
            }
        }

        # -------------------------------------------------------------
        # OUTPUT: Format Pipeline Submission
        # -------------------------------------------------------------

        if ((Test-Path $ApiRawOut) -or (Test-Path $SshRawOut) -or (Test-Path $CustomApiRawOut) -or (Test-Path $CustomSshRawOut)) {
            [PSCustomObject]@{ 
                TargetName        = $Target.Name
                TargetType        = "ESXi" 
                DisaComponent     = "ESXi" 
                
                # Check real existence before passing down pipeline
                ApiJsonFile       = if (Test-Path $ApiRawOut) { $ApiRawOut } else { $null }
                SshJsonFile       = if (Test-Path $SshRawOut) { $SshRawOut } else { $null }
                CustomApiJsonFile = if (Test-Path $CustomApiRawOut) { $CustomApiRawOut } else { $null }
                CustomSshJsonFile = if (Test-Path $CustomSshRawOut) { $CustomSshRawOut } else { $null }
                
                vCenterShortName  = $Target.vCenterShortName
                DateStr           = $Target.DateStr
                IPAddress         = $NetInfo.IPAddress
                MACAddress        = $NetInfo.MACAddress
            }
        } else {
            Write-StigLog -Message "All InSpec profiles failed for $($Target.Name). Check inputs.yml syntax and profile paths." -Severity ERROR -Source "EsxiWorker"
        }
    } -ThrottleLimit 10
}

Export-ModuleMember -Function Invoke-EsxiAudit