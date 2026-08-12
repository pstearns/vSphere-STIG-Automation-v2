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
        $RawJsonDir = $Target.ReportDir
        if (-not (Test-Path $RawJsonDir)) { New-Item -ItemType Directory -Path $RawJsonDir -Force | Out-Null }

        $InputsFile = Join-Path $OverlayRoot "conf/esxi/inputs.yml"
        
        # Retrieve asset metadata via helper module
        $NetInfo = Get-EsxiNetworkInfo -vCenter $Target.vCenter -AdminUser $Target.AdminUser -AdminPass $Target.AdminPass -EsxiHost $Target.Name

        # Dynamic profile path resolution
        $VsphereBasePath   = "/usr/share/stigs/vsphere/8.0"
        $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory | Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | Sort-Object Name -Descending | Select-Object -ExpandProperty Name -First 1
        
        $ApiProfilePath = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/esxi"
        
        $BaseCustomization = Join-Path $VsphereBasePath "$LatestStigRelease/customization"
        $SshProfileMatch   = Get-ChildItem -Path $BaseCustomization -Recurse -Directory -Filter "esxi-ssh" -ErrorAction SilentlyContinue | Select-Object -First 1
        $SshProfilePath    = if ($SshProfileMatch) { $SshProfileMatch.FullName } else { $null }

        $ApiRawOut = Join-Path $RawJsonDir "$($Target.Name)_ESXi_API_raw.json"
        $SshRawOut = Join-Path $RawJsonDir "$($Target.Name)_ESXi_SSH_raw.json"

        # Base64 encode credentials to prevent command injection
        $b64AdminPass = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Target.AdminPass))
        $b64RootPass  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Target.RootPass))

        $InputArg = if (Test-Path $InputsFile) { "--input-file '$InputsFile'" } else { "" }

        $ApiCmd = "VISERVER='$($Target.vCenter)' VISERVER_USERNAME='$($Target.AdminUser)' VISERVER_PASSWORD=`"`$(echo '$b64AdminPass' | base64 -d)`" cinc-auditor exec '$ApiProfilePath' -t vmware:// $InputArg --input vmhostName=`"$($Target.Name)`" --reporter json:'$ApiRawOut'"
        
        $ApiBashOutput = bash -c $ApiCmd 2>&1
        
        if (-not (Test-Path $ApiRawOut)) { 
            Write-StigLog -Message "API Audit failed to produce JSON for $($Target.Name). Output: $ApiBashOutput" -Severity WARN -Source "EsxiWorker" 
        }

        if ($SshProfilePath -and (Test-Path $SshProfilePath)) {
            Set-EsxiAccessState -vCenter $Target.vCenter -AdminUser $Target.AdminUser -AdminPass $Target.AdminPass -EsxiHost $Target.Name -Enabled $true

            $SshCmd = "cinc-auditor exec '$SshProfilePath' -t ssh://root@$($Target.Name) --password `"`$(echo '$b64RootPass' | base64 -d)`" $InputArg --reporter json:'$SshRawOut'"
            $SshBashOutput = bash -c $SshCmd 2>&1
            
            if (-not (Test-Path $SshRawOut)) { 
                Write-StigLog -Message "SSH Audit failed to produce JSON for $($Target.Name). Output: $SshBashOutput" -Severity WARN -Source "EsxiWorker" 
            }

            Set-EsxiAccessState -vCenter $Target.vCenter -AdminUser $Target.AdminUser -AdminPass $Target.AdminPass -EsxiHost $Target.Name -Enabled $false
        } else {
            Write-StigLog -Message "SSH Profile not found. Skipped SSH phases for $($Target.Name)." -Severity WARN -Source "EsxiWorker"
        }

        if ((Test-Path $ApiRawOut) -or (Test-Path $SshRawOut)) {
            [PSCustomObject]@{ 
                TargetName       = $Target.Name
                TargetType       = "ESXi" 
                DisaComponent    = "ESXi" 
                ApiJsonFile      = if (Test-Path $ApiRawOut) { $ApiRawOut } else { $null }
                SshJsonFile      = if (Test-Path $SshRawOut) { $SshRawOut } else { $null }
                vCenterShortName = $Target.vCenterShortName
                DateStr          = $Target.DateStr
                IPAddress        = $NetInfo.IPAddress
                MACAddress       = $NetInfo.MACAddress
            }
        } else {
            Write-StigLog -Message "All InSpec profiles failed for $($Target.Name). Check inputs.yml syntax and profile paths." -Severity ERROR -Source "EsxiWorker"
        }
    } -ThrottleLimit 10
}

Export-ModuleMember -Function Invoke-EsxiAudit