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

    # Ensure PowerCLI persistently ignores untrusted certificates for all threads and subprocesses
    try {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope User | Out-Null
    } catch {
        Write-Warning "Could not configure PowerCLI certificate validation bypass: $_"
    }

    # UPGRADE 1: Read the helper files ONCE in parent scope to prevent concurrent disk access lockups inside parallel threads
    $GlobalFuncsPath = Join-Path $OverlayRoot "modules/globalFunctions.psm1"
    $EsxiHelpersPath = Join-Path $OverlayRoot "modules/esxi/EsxiHelpers.psm1"

    $GlobalFuncsContent = if (Test-Path $GlobalFuncsPath) { (Get-Content $GlobalFuncsPath -Raw) -replace "(?ms)Export-ModuleMember.*", "" } else { $null }
    $EsxiHelpersContent = if (Test-Path $EsxiHelpersPath) { (Get-Content $EsxiHelpersPath -Raw) -replace "(?ms)Export-ModuleMember.*", "" } else { $null }

    $TargetList | ForEach-Object -Parallel {
        # FIXED: Suppress parallel PowerCLI RecentServerList write conflicts
        $WarningPreference = 'SilentlyContinue'

        $Target = $_
        $OverlayRoot = $using:OverlayRoot

        # --- AUTO-FAIL OFFLINE HOSTS ---
        if ($Target.IsOffline) {
            Write-Host " [!] Target $($Target.Name) is offline ($($Target.ConnectionState)). Writing FAILURE record and continuing." -ForegroundColor Red

            $RawJsonDir = "/tmp/stig_staging/$($Target.Name)"
            if (-not (Test-Path $RawJsonDir)) {
                New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null
            }

            $FailedMetaPath = Join-Path $RawJsonDir "$($Target.Name)_ESXi_OFFLINE.json"
            @{
                status  = "failed"
                reason  = "Host ConnectionState was $($Target.ConnectionState)"
                host    = $Target.Name
                vCenter = $Target.vCenter
            } | ConvertTo-Json | Out-File -FilePath $FailedMetaPath -Force

            # Emit a pipeline object so Format-StigChecklist / summary still see the host
            [PSCustomObject]@{
                TargetName        = $Target.Name
                TargetType        = "ESXi"
                DisaComponent     = "ESXi"
                ApiJsonFile       = $null
                SshJsonFile       = $null
                CustomApiJsonFile = $null
                CustomSshJsonFile = $null
                vCenterShortName  = $Target.vCenterShortName
                DateStr           = $Target.DateStr
                IPAddress         = ""
                MACAddress        = ""
                IsOffline         = $true
                ConnectionState   = $Target.ConnectionState
            }
            return
        }

        # UPGRADE 1 (Cont.): Load helpers in thread context using pre-read memory streams (No I/O collision)
        if ($using:GlobalFuncsContent) { Invoke-Expression $using:GlobalFuncsContent }
        if ($using:EsxiHelpersContent) { Invoke-Expression $using:EsxiHelpersContent }

        Write-Host " -> [$($Target.Name)] Executing ESXi Audit phases..." -ForegroundColor DarkGray
        
        # Directory structure initialization
        $RawJsonDir = "/tmp/stig_staging/$($Target.Name)"
        if (-not (Test-Path $RawJsonDir)) { New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null }

        $InputsFile = Join-Path $OverlayRoot "conf/esxi/inputs.yml"
        
        # FIXED: Retrieve asset metadata via helper module (Safeguarded against random timeouts and disconnections)
        $NetInfo = $null
        try {
            $NetInfo = Get-EsxiNetworkInfo -vCenter $Target.vCenter -AdminUser $Target.AdminUser -AdminPass $Target.AdminPass -EsxiHost $Target.Name -ErrorAction Stop
        } catch {
            Write-Warning " -> [$($Target.Name)] Failed to retrieve network metadata: $_. Proceeding with fallback blank details."
            $NetInfo = [PSCustomObject]@{
                IPAddress  = ""
                MACAddress = ""
            }
        }

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

        # --- Define Output Paths Upfront ---
        $ApiRawOut       = Join-Path $RawJsonDir "$($Target.Name)_ESXi_API_raw.json"
        $SshRawOut       = Join-Path $RawJsonDir "$($Target.Name)_ESXi_SSH_raw.json"
        $CustomApiRawOut = Join-Path $RawJsonDir "$($Target.Name)_ESXi_CUSTOM_API_raw.json"
        $CustomSshRawOut = Join-Path $RawJsonDir "$($Target.Name)_ESXi_CUSTOM_SSH_raw.json"

        $InputArg = if (Test-Path $InputsFile) { "--input-file", $InputsFile } else { @() }

        $HasBaseSsh   = ($null -ne $SshProfilePath -and (Test-Path $SshProfilePath))
        $HasCustomSsh = (Test-Path (Join-Path $CustomSshProfilePath "inspec.yml"))

        # -------------------------------------------------------------
        # PHASE 1: SSH Executions (Open Access -> Audit -> Close Access)
        # -------------------------------------------------------------
        if ($HasBaseSsh -or $HasCustomSsh) {
            # Open SSH access and disable lockdown via PowerCLI (required to allow connection testing)
            Set-EsxiAccessState -vCenter $Target.vCenter -AdminUser $Target.AdminUser -AdminPass $Target.AdminPass -EsxiHost $Target.Name -Enabled $true

            try {
                # --- SSH ROOT LOGIN GUARD ---
                # Test connectivity and confirm 'PermitRootLogin' is active before running InSpec
                Write-Host " -> [$($Target.Name)] Testing Root SSH login availability..." -ForegroundColor DarkGray
                $SshLoginSuccess = $false
                
                if (Get-Command sshpass -ErrorAction SilentlyContinue) {
                    # Configure non-interactive SSH test args: 3s connect timeout, 1 password prompt max, bypass host key validation, bypass keys
                    $SshTestArgs = @("-p", $Target.RootPass, "ssh", "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no", "root@$($Target.Name)", "exit")
                    
                    $SshProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $SshProcessInfo.FileName = "sshpass"
                    $SshProcessInfo.UseShellExecute = $false
                    $SshProcessInfo.RedirectStandardOutput = $true
                    $SshProcessInfo.RedirectStandardError = $true
                    foreach ($arg in $SshTestArgs) { $SshProcessInfo.ArgumentList.Add($arg) }
                    
                    try {
                        $SshProcess = [System.Diagnostics.Process]::Start($SshProcessInfo)
                        # We give the entire process up to 5 seconds to run (covers network and auth latency)
                        if ($SshProcess.WaitForExit(5000)) {
                            if ($SshProcess.ExitCode -eq 0) {
                                $SshLoginSuccess = $true
                            } else {
                                Write-Warning " -> [$($Target.Name)] Pre-check failed (Exit Code: $($SshProcess.ExitCode)). Root login disabled or credential invalid."
                            }
                        } else {
                            $SshProcess.Kill()
                            Write-Warning " -> [$($Target.Name)] SSH login test timed out."
                        }
                    } catch {
                        Write-Warning " -> [$($Target.Name)] Error launching SSH verification process: $_"
                    }
                } else {
                    # Fallback if sshpass is missing
                    Write-Warning " -> [$($Target.Name)] sshpass missing; bypassing guard pre-check (runs may hang if SSH is misconfigured)."
                    $SshLoginSuccess = $true
                }

                # Only proceed to execute InSpec if the SSH Login Guard succeeded
                if ($SshLoginSuccess) {
                    if ($HasBaseSsh) {
                        # UPGRADE 2: Added --no-create-lockfile to bypass parallel contention on shared profile directories
                        $SshArgs = @("exec", $SshProfilePath, "-t", "ssh://root@$($Target.Name)", "--password", $Target.RootPass, "--reporter", "json:$SshRawOut", "--no-create-lockfile")
                        if ($InputArg) { $SshArgs += $InputArg }

                        & cinc-auditor $SshArgs 2>&1 | Out-Null
                        if (-not (Test-Path $SshRawOut)) { 
                            Write-StigLog -Message "SSH Audit failed to produce JSON for $($Target.Name)." -Severity WARN -Source "EsxiWorker" 
                        }
                    }

                    if ($HasCustomSsh) {
                        Write-Host " -> [$($Target.Name)] Executing Custom ESXi SSH Overlay..." -ForegroundColor DarkCyan
                        
                        # UPGRADE 2: Added --no-create-lockfile here as well
                        $CustomSshArgs = @("exec", $CustomSshProfilePath, "-t", "ssh://root@$($Target.Name)", "--password", $Target.RootPass, "--reporter", "json:$CustomSshRawOut", "--no-create-lockfile")
                        if ($InputArg) { $CustomSshArgs += $InputArg }

                        $CustomSshOutput = & cinc-auditor $CustomSshArgs 2>&1
                        
                        if (-not (Test-Path $CustomSshRawOut)) {
                            Write-Host "    [DEBUG] Custom SSH Run Failed!" -ForegroundColor Red
                            Write-Host "    [DEBUG] RAW OUTPUT START:" -ForegroundColor Red
                            Write-Host $CustomSshOutput -ForegroundColor Gray
                            Write-Host "    [DEBUG] RAW OUTPUT END" -ForegroundColor Red
                        }
                    }
                } else {
                    Write-StigLog -Message "SSH Root Login disabled or unreachable on $($Target.Name). Bypassing InSpec SSH profile." -Severity WARN -Source "EsxiWorker"
                    Write-Host " [!] [$($Target.Name)] Root SSH login failed pre-check. Skipping Phase 1 SSH Audits." -ForegroundColor Yellow
                }
            } finally {
                # Ensure the host is ALWAYS locked down before API audits run, even if pre-check fails
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
        $ProcessInfo.FileName = "cinc-auditor" # FIXED: Direct execution of cinc-auditor natively (no bash -c required)
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.RedirectStandardError = $true
        
        # Inject credentials directly as process environment variables
        $ProcessInfo.EnvironmentVariables["VISERVER"]          = $Target.vCenter
        $ProcessInfo.EnvironmentVariables["VISERVER_USERNAME"] = $Target.AdminUser
        $ProcessInfo.EnvironmentVariables["VISERVER_PASSWORD"] = $Target.AdminPass
        $ProcessInfo.EnvironmentVariables["VISERVER_INSECURE"] = "true" 
        $ProcessInfo.EnvironmentVariables["NO_COLOR"]          = "true"
        $ProcessInfo.EnvironmentVariables["HOME"]              = "/root"

        # Execute Base API Natively (Passing arguments directly via ArgumentList)
        # UPGRADE 2: Added --no-create-lockfile to protect the base API run
        $ApiArgs = @("exec", $ApiProfilePath, "-t", "vmware://", "--input", "vmhostName=$($Target.Name)", "--reporter", "json:$ApiRawOut", "--no-create-lockfile")
        if (Test-Path $InputsFile) { $ApiArgs += @("--input-file", $InputsFile) }
        
        $ProcessInfo.ArgumentList.Clear()
        foreach ($arg in $ApiArgs) { $ProcessInfo.ArgumentList.Add($arg) }

        $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
        $ApiOutput = $Process.StandardOutput.ReadToEnd() + $Process.StandardError.ReadToEnd()
        $Process.WaitForExit()

        if (-not (Test-Path $ApiRawOut)) { 
            Write-StigLog -Message "API Audit failed to produce JSON for $($Target.Name). Output: $ApiOutput" -Severity WARN -Source "EsxiWorker" 
        }

        # Execute Custom API Natively
        if (Test-Path (Join-Path $CustomApiProfilePath "inspec.yml")) {
            Write-Host " -> [$($Target.Name)] Executing Custom ESXi API Overlay..." -ForegroundColor DarkCyan
            
            # UPGRADE 3: Dedicated ProcessStartInfo for Custom API to avoid parallel argument/state corruption
            $CustomProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $CustomProcessInfo.FileName = "cinc-auditor"
            $CustomProcessInfo.UseShellExecute = $false
            $CustomProcessInfo.RedirectStandardOutput = $true
            $CustomProcessInfo.RedirectStandardError = $true
            
            $CustomProcessInfo.EnvironmentVariables["VISERVER"]          = $Target.vCenter
            $CustomProcessInfo.EnvironmentVariables["VISERVER_USERNAME"] = $Target.AdminUser
            $CustomProcessInfo.EnvironmentVariables["VISERVER_PASSWORD"] = $Target.AdminPass
            $CustomProcessInfo.EnvironmentVariables["VISERVER_INSECURE"] = "true" 
            $CustomProcessInfo.EnvironmentVariables["NO_COLOR"]          = "true"
            $CustomProcessInfo.EnvironmentVariables["HOME"]              = "/root"

            # UPGRADE 2: Added --no-create-lockfile to protect custom API folder
            $CustomApiArgs = @("exec", $CustomApiProfilePath, "-t", "vmware://", "--input", "vmhostName=$($Target.Name)", "--reporter", "json:$CustomApiRawOut", "--no-create-lockfile")
            if (Test-Path $InputsFile) { $CustomApiArgs += @("--input-file", $InputsFile) }
            
            foreach ($arg in $CustomApiArgs) { $CustomProcessInfo.ArgumentList.Add($arg) }

            $CustomProcess = [System.Diagnostics.Process]::Start($CustomProcessInfo)
            $CustomApiOutput = $CustomProcess.StandardOutput.ReadToEnd() + $CustomProcess.StandardError.ReadToEnd()
            $CustomProcess.WaitForExit()
            
            if (-not (Test-Path $CustomApiRawOut)) {
                Write-Host "    [DEBUG] Custom API Run Failed!" -ForegroundColor Red
                Write-Host "    [DEBUG] RAW API OUTPUT START:" -ForegroundColor Red
                Write-Host $CustomApiOutput -ForegroundColor Gray
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