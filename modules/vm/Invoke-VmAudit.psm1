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

    # Ensure PowerCLI persistently ignores untrusted certificates for all threads and subprocesses
    try {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope User | Out-Null
    } catch {
        Write-Warning "Could not configure PowerCLI certificate validation bypass: $_"
    }

    $TargetList | ForEach-Object -Parallel {
        $Target = $_
        $OverlayRoot = $using:OverlayRoot
        
        # FIXED: Robust Multiline regex to completely chop the Export-ModuleMember statements
        $GlobalFuncs = (Get-Content (Join-Path $OverlayRoot "modules/globalFunctions.psm1") -Raw) -replace "(?ms)Export-ModuleMember.*", ""
        Invoke-Expression $GlobalFuncs
        
        # FIXED: Robust Multiline regex applied here as well
        $VmHelpers = (Get-Content (Join-Path $OverlayRoot "modules/vm/VmHelpers.psm1") -Raw) -replace "(?ms)Export-ModuleMember.*", ""
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

        # -------------------------------------------------------------
        # Phase 1: Base API Audit Natively (No shell escaping issues)
        # -------------------------------------------------------------
        # Securely build the process environment (avoids Bash string injection and fixes SSL)
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "cinc-auditor" # FIXED: Direct execution of cinc-auditor natively
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.RedirectStandardError = $true
        
        # Inject credentials directly as process environment variables
        $ProcessInfo.EnvironmentVariables["VISERVER"]          = $Target.vCenter
        $ProcessInfo.EnvironmentVariables["VISERVER_USERNAME"] = $Target.AdminUser
        $ProcessInfo.EnvironmentVariables["VISERVER_PASSWORD"] = $Target.AdminPass
        $ProcessInfo.EnvironmentVariables["VISERVER_INSECURE"] = "true" 
        $ProcessInfo.EnvironmentVariables["NO_COLOR"]          = "true" # FIXED: Prevents ANSI stream corruption
        $ProcessInfo.EnvironmentVariables["HOME"]              = "/root" # FIXED: Resolves user gems in cron

        # Execute Base API Natively (Passing arguments directly via ArgumentList)
        $ApiArgs = @("exec", $ApiProfilePath, "-t", "vmware://", "--input", "vmName=$($Target.Name)", "--reporter", "json:$RawOut")
        if (Test-Path $InputsFile) { $ApiArgs += @("--input-file", $InputsFile) }
        
        $ProcessInfo.ArgumentList.Clear()
        foreach ($arg in $ApiArgs) { $ProcessInfo.ArgumentList.Add($arg) }

        $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
        $ApiOutput = $Process.StandardOutput.ReadToEnd() + $Process.StandardError.ReadToEnd()
        $Process.WaitForExit()

        # -------------------------------------------------------------
        # Phase 2: Custom API Overlay Execution Natively
        # -------------------------------------------------------------
        if (Test-Path (Join-Path $CustomApiProfilePath "inspec.yml")) {
            Write-Host " -> [$($Target.Name)] Executing Custom VM API Overlay..." -ForegroundColor DarkCyan
            
            $CustomApiArgs = @("exec", $CustomApiProfilePath, "-t", "vmware://", "--input", "vmName=$($Target.Name)", "--reporter", "json:$CustomApiRawOut")
            if (Test-Path $InputsFile) { $CustomApiArgs += @("--input-file", $InputsFile) }
            
            $ProcessInfo.ArgumentList.Clear()
            foreach ($arg in $CustomApiArgs) { $ProcessInfo.ArgumentList.Add($arg) }

            $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
            $CustomApiOutput = $Process.StandardOutput.ReadToEnd() + $Process.StandardError.ReadToEnd()
            $Process.WaitForExit()
            
            if (-not (Test-Path $CustomApiRawOut)) {
                Write-Host "    [DEBUG] Custom API Run Failed!" -ForegroundColor Red
                Write-Host "    [DEBUG] RAW API OUTPUT START:" -ForegroundColor Red
                Write-Host $CustomApiOutput -ForegroundColor Gray
                Write-Host "    [DEBUG] RAW API OUTPUT END" -ForegroundColor Red
            }
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
            Write-StigLog -Message "Scan failed to produce JSON for $($Target.Name). Cinc-Auditor Error: $ApiOutput" -Severity ERROR -Source "VmWorker"
        }
    } -ThrottleLimit 15
}

Export-ModuleMember -Function Invoke-VmAudit