# =========================================================================
# MODULE: Invoke-NetAppAudit.psm1
# DESCRIPTION: NetApp ONTAP STIG Audit Worker.
#              Loads targets from inputs.yml, retrieves credentials via
#              CredentialManagement.psm1, and executes InSpec profile.
# =========================================================================

if (Test-Path "/usr/share/stigs/orchestration_overlay") {
    $Script:OverlayRoot = "/usr/share/stigs/orchestration_overlay"
} else {
    $Script:OverlayRoot = (Resolve-Path "$PSScriptRoot/..").Path
}

Import-Module (Join-Path $Script:OverlayRoot "modules/CredentialManagement.psm1") -Global -Force -ErrorAction Stop
Import-Module (Join-Path $Script:OverlayRoot "modules/globalFunctions.psm1") -Global -Force -ErrorAction Stop

<#
.SYNOPSIS
    Loads enabled NetApp targets from netapp/conf/inputs.yml.
    Also returns the NetApp-specific Collection ID if defined.
#>
function Get-NetAppTargets {
    [CmdletBinding()]
    param ([string]$OverlayRoot = $Script:OverlayRoot)

    $InputsPath = Join-Path $OverlayRoot "netapp/conf/inputs.yml"
    if (-not (Test-Path $InputsPath)) {
        Write-StigLog -Message "NetApp inputs.yml not found at $InputsPath" -Severity ERROR -Source "NetAppAudit"
        return @{ Targets = @(); CollectionId = $null }
    }

    try {
        $Inputs = Get-Content $InputsPath -Raw | ConvertFrom-Yaml -ErrorAction Stop
    } catch {
        Write-StigLog -Message "Failed to parse NetApp inputs.yml: $($_.Exception.Message)" -Severity ERROR -Source "NetAppAudit"
        return @{ Targets = @(); CollectionId = $null }
    }

    $EnabledTargets = $Inputs.netapp_targets | Where-Object {
        ($_.enabled -eq $true) -or ($_.enabled -eq "true")
    }

    # Read NetApp-specific Collection ID override (defaults to 16 if not present)
    $CollectionId = if ($Inputs.collection_id) { [string]$Inputs.collection_id } else { "16" }

    Write-StigLog -Message "Loaded $($EnabledTargets.Count) enabled NetApp target(s) | CollectionId: $CollectionId" -Severity INFO -Source "NetAppAudit"

    return [PSCustomObject]@{
        Targets      = $EnabledTargets
        CollectionId = $CollectionId
    }
}

<#
.SYNOPSIS
    Internal helper to retrieve NetApp credentials (avoids name collision).
#>
function Get-NetAppTargetCredential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$FQDN,
        [string]$FilePath = (Join-Path $Script:OverlayRoot "conf/.creds.json.encrypted")
    )

    try {
        $Creds = Get-NetAppCredential -FQDN $FQDN -FilePath $FilePath -ErrorAction Stop

        if ($null -eq $Creds) {
            Write-StigLog -Message "No credentials found in vault for $FQDN" -Severity WARN -Source "NetAppAudit"
            return $null
        }

        return [PSCustomObject]@{
            AdminUser = $Creds.AdminCred.UserName
            AdminPass = $Creds.AdminCred.GetNetworkCredential().Password
        }
    }
    catch {
        Write-StigLog -Message "Failed to retrieve credentials for $FQDN : $($_.Exception.Message)" -Severity ERROR -Source "NetAppAudit"
        return $null
    }
}

<#
.SYNOPSIS
    Main NetApp audit function. Executes InSpec against enabled targets using the ontap:// transport.
#>
function Invoke-NetAppAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)][array]$TargetList,
        [string]$OverlayRoot = $Script:OverlayRoot
    )

    Write-StigLog -Message "Starting NetApp InSpec Audit..." -Severity INFO -Source "NetAppAudit"

    if (-not $TargetList) {
        $TargetList = Get-NetAppTargets -OverlayRoot $OverlayRoot
    }

    if (-not $TargetList.Targets -or $TargetList.Targets.Count -eq 0) {
        Write-StigLog -Message "No enabled NetApp targets found." -Severity WARN -Source "NetAppAudit"
        return
    }

    $DateStr = Get-Date -Format "yyyyMMdd"
    $results = @()

    foreach ($target in $TargetList.Targets) {
        $fqdn = $target.fqdn
        if ([string]::IsNullOrWhiteSpace($fqdn)) { continue }

        Write-StigLog -Message "Processing NetApp target: $fqdn" -Severity INFO -Source "NetAppAudit"

        # Get credentials
        $creds = Get-NetAppTargetCredential -FQDN $fqdn
        if (-not $creds) {
            Write-StigLog -Message "Skipping $fqdn - no credentials available in vault." -Severity WARN -Source "NetAppAudit"
            continue
        }

        $username = $creds.AdminUser
        $password = $creds.AdminPass

        # Report directory structure (matches VMware pattern)
        $shortName = $fqdn.Split('.')[0]
        $ReportDir = Join-Path $OverlayRoot "reports/$DateStr/$shortName/NetApp"
        if (-not (Test-Path $ReportDir)) {
            New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $JsonOutput = Join-Path $ReportDir "$shortName`_NetApp_$timestamp.json"

        # Build InSpec command using ontap:// transport (your custom Train gem)
        $InSpecProfilePath = Join-Path $OverlayRoot "netapp/inspec"

        Write-StigLog -Message "Executing InSpec profile against $fqdn using ontap:// transport..." -Severity INFO -Source "NetAppAudit"

        try {
            # Using argument array for clean execution on Photon OS / Linux PowerShell
            $argList = @(
                "exec",
                $InSpecProfilePath,
                "--target", "ontap://$username@$fqdn",
                "--password", $password,
                "--reporter", "cli",
                "json:$JsonOutput"
            )

            $result = & inspec $argList 2>&1

            if (Test-Path $JsonOutput) {
                Write-StigLog -Message "InSpec scan completed successfully for $fqdn. Report: $JsonOutput" -Severity SUCCESS -Source "NetAppAudit"

                $results += [PSCustomObject]@{
                    TargetName     = $fqdn
                    TargetType     = "NetApp"
                    DisaComponent  = "NetApp ONTAP"
                    ShortName      = $shortName
                    DateStr        = $DateStr
                    RawJsonFile    = $JsonOutput          # InSpec HDF/JSON output
                    ReportDir      = $ReportDir
                    Status         = "Completed"
                }
            } else {
                Write-StigLog -Message "InSpec finished but no JSON report was created for $fqdn. Output: $result" -Severity WARN -Source "NetAppAudit"
            }
        }
        catch {
            Write-StigLog -Message "InSpec execution failed for ${fqdn}: $_" -Severity ERROR -Source "NetAppAudit"
        }
    }

    Write-StigLog -Message "NetApp Audit cycle completed." -Severity INFO -Source "NetAppAudit"

    return $results
}

Export-ModuleMember -Function Invoke-NetAppAudit, Get-NetAppTargets