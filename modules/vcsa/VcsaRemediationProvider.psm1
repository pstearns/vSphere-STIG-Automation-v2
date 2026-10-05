# =========================================================================
# PROVIDER: VcsaRemediationProvider.psm1
# DESCRIPTION: Bridges the master orchestrator to VCSA STIG profiles.
#              Wraps the official Broadcom VCSA 8.0 Hardening Playbook.
#              State-safe: Dynamically opens and closes SSH ONCE per run.
#              Aligned: Resolves dynamic sub-profiles and transport URIs.
# =========================================================================

$ProviderDir = Split-Path $MyInvocation.MyCommand.Path -Parent

# 1. Optimized Direct Import (Bypasses slow disk crawling)
$HelpersPath = Join-Path $ProviderDir "VcsaHelpers.psm1"
if (Test-Path $HelpersPath) { 
    Import-Module $HelpersPath -Force -DisableNameChecking
}

# 2. Module-Scoped Cache
$script:CachedLatestRelease = $null

function Get-AssetProviderConfig {
    param([string]$OverlayRoot)

    $VcsaConfDir = Join-Path $OverlayRoot "conf/vcsa"
    $InputsYml   = Join-Path $VcsaConfDir "inputs.yml"

    $VsphereBasePath = "/usr/share/stigs/vsphere/8.0"

    # Dynamically find the active SRG/STIG release directory
    $LatestRelease = Get-ChildItem -Path $VsphereBasePath -Directory -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | 
        Sort-Object Name -Descending | 
        Select-Object -ExpandProperty Name -First 1

    $PlaybookDir = if ($LatestRelease) {
        Join-Path $VsphereBasePath "$LatestRelease/vcsa/ansible/vmware-vcsa-8.0-stig-ansible-hardening"
    } else {
        "/usr/share/stigs/vsphere/8.0/v2r4-srg/vcsa/ansible/vmware-vcsa-8.0-stig-ansible-hardening"
    }

    return [PSCustomObject]@{
        AnswersXml   = Join-Path $VcsaConfDir "answers.xml"
        VariablesYml = $InputsYml
        InputsYml    = $InputsYml
        PlaybookDir  = $PlaybookDir
        InspecAPI    = $VsphereBasePath
    }
}

function Get-AssetObject {
    param([string]$Name)
    return [PSCustomObject]@{ Name = $Name }
}

# --- LIFECYCLE HOOKS (Triggered once per vCenter) ---

function Initialize-AssetProvider {
    param(
        [object]$AssetObject, 
        [object]$Config,
        [object]$Creds
    )
    $VCSA_IP = if ($AssetObject -is [string]) { $AssetObject } else { $AssetObject.Name }

    $AdminUser = $Creds.AdminCred.UserName
    $AdminPass = $Creds.AdminCred.GetNetworkCredential().Password
    $RootPass  = $Creds.RootCred.GetNetworkCredential().Password

    # Programmatically enable SSH via REST API over port 443 ONCE
    Set-VCSASshState -FQDN $VCSA_IP -Username $AdminUser -Password $AdminPass -Enabled $true

    # Pre-Flight: Enforce /bin/bash shell via custom VcsaHelpers function ONCE
    Write-StigLog "[$VCSA_IP] Triggering pre-flight shell validation..." -Severity INFO -Source "VcsaProvider"
    $ShellOK = Set-VCSABashShell -FQDN $VCSA_IP -RootPassword $RootPass
    if (-not $ShellOK) {
        Write-StigLog "[$VCSA_IP] Warning: Root shell check returned non-success state. Continuing playbook launch." -Severity WARN -Source "VcsaProvider"
    }
}

function Finalize-AssetProvider {
    param(
        [object]$AssetObject, 
        [object]$Config,
        [object]$Creds
    )
    $VCSA_IP = if ($AssetObject -is [string]) { $AssetObject } else { $AssetObject.Name }

    $AdminUser = $Creds.AdminCred.UserName
    $AdminPass = $Creds.AdminCred.GetNetworkCredential().Password

    # State Restoration: Safely disable SSH over REST API ONCE to return VCSA to hardened state
    try {
        Set-VCSASshState -FQDN $VCSA_IP -Username $AdminUser -Password $AdminPass -Enabled $false
        Write-StigLog "[$VCSA_IP] SSH service successfully disabled. Appliance restored to hardened state." -Severity SUCCESS -Source "VcsaProvider"
    }
    catch {
        Write-StigLog "[$VCSA_IP] Warning: Failed to re-disable SSH service via REST API: $_" -Severity WARN -Source "VcsaProvider"
    }
}

# --- REMEDIATION DISPATCH (Triggered per Checklist file) ---

function Invoke-AssetRemediation {
    param(
        [object]$AssetObject,
        [array]$FixList,
        [object]$Config,
        [object]$Creds
    )

    $SuccessFixes = [System.Collections.Generic.List[string]]::new()
    $VCSA_IP      = if ($Creds.FQDN) { $Creds.FQDN } elseif ($AssetObject -is [string]) { $AssetObject } else { $AssetObject.Name }
    $RootUser     = "root"
    $RootPass     = $Creds.RootCred.GetNetworkCredential().Password

    # 1. Execution: Map open findings directly to Broadcom Playbook Tags
    $TagsString = $FixList -join ","
    Write-StigLog "[$VCSA_IP] Launching Broadcom VCSA Playbook with tags: $TagsString" -Severity INFO -Source "VcsaProvider"

    try {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "ansible-playbook"
        $ProcessInfo.WorkingDirectory = $Config.PlaybookDir

        $ProcessInfo.Arguments = "-i $VCSA_IP, -u $RootUser playbook.yml --extra-vars `"@$($Config.VariablesYml)`" -e `"ansible_ssh_pass=$RootPass`" -e `"photon_version=4`" --tags $TagsString -v"
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.RedirectStandardError = $true

        $RolesPaths = @(
            "$($Config.PlaybookDir)/roles",
            "/usr/share/stigs/photon/4.0/v2r3-srg/ansible"
        )
        $ProcessInfo.EnvironmentVariables["ANSIBLE_ROLES_PATH"] = ($RolesPaths -join ":")
        $ProcessInfo.EnvironmentVariables["ANSIBLE_HOST_KEY_CHECKING"] = "False"

        $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
        $FullOutput = [System.Text.StringBuilder]::new()

        while (-not $Process.HasExited) {
            $Line = $Process.StandardOutput.ReadLine()
            if ($null -ne $Line) {
                [void]$FullOutput.AppendLine($Line)
                if ($Line -match "PLAY \[|changed:|fatal:|failed:") {
                    $CleanLine = $Line -replace '\*+$', '' -replace '\s+', ' '
                    if ($Line -match "changed:") {
                        Write-StigLog "  [REMEDIATING] $CleanLine" -Severity SUCCESS -Source "VcsaProvider"
                    } elseif ($Line -match "fatal:|failed:") {
                        Write-StigLog "  [FAILURE] $CleanLine" -Severity ERROR -Source "VcsaProvider"
                    } else {
                        Write-StigLog "  [Ansible] $CleanLine" -Severity INFO -Source "VcsaProvider"
                    }
                }
            }
            Start-Sleep -Milliseconds 20
        }

        $Remaining = $Process.StandardOutput.ReadToEnd()
        if (-not [string]::IsNullOrWhiteSpace($Remaining)) {
            [void]$FullOutput.Append($Remaining)
        }
        $ErrorOutput = $Process.StandardError.ReadToEnd()
        $Output = $FullOutput.ToString()
        $Process.Dispose()

        if ($Process.ExitCode -eq 0 -and $Output -notmatch "Could not match supplied host pattern") {
            Write-StigLog "[$VCSA_IP] Broadcom VCSA hardening playbook completed." -Severity SUCCESS -Source "VcsaProvider"
        } else {
            Write-StigLog "[$VCSA_IP] Playbook returned non-zero exit code ($($Process.ExitCode)). Launching InSpec to verify actual state..." -Severity WARN -Source "VcsaProvider"
        }
    }
    catch {
        Write-StigLog "[$VCSA_IP] Non-fatal playbook launch issue: $_. Proceeding to verify actual state..." -Severity WARN -Source "VcsaProvider"
    }

    # Queue all rules for verification so delta scan records ground-truth state
    foreach ($Rule in $FixList) { $SuccessFixes.Add($Rule) }

    return $SuccessFixes.ToArray()
}

# --- VERIFICATION DISPATCH ---

function Get-AssetVerificationArgs {
    param($Job, $Config, $DeltaJson)

    $VsphereBasePath = $Config.InspecAPI

    if ($null -eq $script:CachedLatestRelease) {
        $LatestRelease = Get-ChildItem -Path $VsphereBasePath -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | 
            Sort-Object Name -Descending | 
            Select-Object -ExpandProperty Name -First 1

        if (-not $LatestRelease) {
            $LatestRelease = Get-ChildItem -Path $VsphereBasePath -Directory | Sort-Object Name -Descending | Select-Object -ExpandProperty Name -First 1
        }
        $script:CachedLatestRelease = $LatestRelease
    }

    $VsphereProfileBaseDir = Join-Path $VsphereBasePath "$script:CachedLatestRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline"
    $VcsaProfileBaseDir    = Join-Path $VsphereBasePath "$script:CachedLatestRelease/vcsa/inspec/vmware-vcsa-8.0-stig-baseline"

    $SubProfile = "photon"
    $Transport = "ssh"
    $BaseAPIPath = $VcsaProfileBaseDir
    $Matched = $false

    if ($Job.File) {
        $FileName = Split-Path $Job.File -Leaf
        if ($FileName -match "PostgreSQL|Postgres")     { $SubProfile = "postgresql";  $Transport = "ssh";    $Matched = $true }
        elseif ($FileName -match "STS")                 { $SubProfile = "sts";         $Transport = "ssh";    $Matched = $true }
        elseif ($FileName -match "EAM")                 { $SubProfile = "eam";         $Transport = "ssh";    $Matched = $true }
        elseif ($FileName -match "Envoy")               { $SubProfile = "envoy";       $Transport = "ssh";    $Matched = $true }
        elseif ($FileName -match "Lookup")              { $SubProfile = "lookup";      $Transport = "ssh";    $Matched = $true }
        elseif ($FileName -match "Perfcharts")          { $SubProfile = "perfcharts";  $Transport = "ssh";    $Matched = $true }
        elseif ($FileName -match "UI")                  { $SubProfile = "ui";          $Transport = "ssh";    $Matched = $true }
        elseif ($FileName -match "VAMI")                { $SubProfile = "vami";        $Transport = "ssh";    $Matched = $true }
        elseif ($FileName -match "Photon")              { $SubProfile = "photon";      $Transport = "ssh";    $Matched = $true }
        elseif ($FileName -match "vCenter|vSphere") { 
            $SubProfile = "vcenter"
            $Transport = "vmware" 
            $BaseAPIPath = $VsphereProfileBaseDir
            $Matched = $true
        }
    }

    if (-not $Matched) {
        $RulesArray = @($Job.FixedRules)
        $FirstRule = if ($RulesArray.Count -gt 0) { $RulesArray[0] } else { "" }

        if ($FirstRule -match "^PHTN")                     { $SubProfile = "photon";     $Transport = "ssh" }
        elseif ($FirstRule -match "^VCPG")                 { $SubProfile = "postgresql"; $Transport = "ssh" }
        elseif ($FirstRule -match "^VCST")                 { $SubProfile = "sts";        $Transport = "ssh" } 
        elseif ($FirstRule -match "^VEAM|^VCAM|^VCEAM")    { $SubProfile = "eam";        $Transport = "ssh" }
        elseif ($FirstRule -match "^VENV")                 { $SubProfile = "envoy";      $Transport = "ssh" }
        elseif ($FirstRule -match "^VLKP|^VCLU")           { $SubProfile = "lookup";     $Transport = "ssh" }
        elseif ($FirstRule -match "^VPRF")                 { $SubProfile = "perfcharts"; $Transport = "ssh" }
        elseif ($FirstRule -match "^VCUI")                 { $SubProfile = "ui";         $Transport = "ssh" }
        elseif ($FirstRule -match "^VVAM|^VAMI|^VMWI")     { $SubProfile = "vami";       $Transport = "ssh" }
        elseif ($FirstRule -match "^VCSA") { 
            $SubProfile = "vcenter"
            $Transport = "vmware" 
            $BaseAPIPath = $VsphereProfileBaseDir
        }
    }

    $ResolvedAPIPath = Join-Path $BaseAPIPath $SubProfile
    $TargetHost = if ($Job.vCenterFQDN) { $Job.vCenterFQDN } else { $Job.VcenterObjName }

    # Build clean argument token array (NO string joining)
    $ArgParts = [System.Collections.Generic.List[string]]::new()
    $ArgParts.Add("exec")
    $ArgParts.Add($ResolvedAPIPath)

    if ($Transport -eq "ssh") {
        $ArgParts.Add("-t")
        $ArgParts.Add("ssh://root@$TargetHost")
        $ArgParts.Add("--password")
        $ArgParts.Add($env:VCSA_ROOT_PASSWORD)
    } else {
        $ArgParts.Add("-t")
        $ArgParts.Add("vmware://")
    }

    $ArgParts.Add("--insecure")

    if (Test-Path $Config.InputsYml) {
        $ArgParts.Add("--input-file")
        $ArgParts.Add($Config.InputsYml)
    }

    # Add targeted controls for delta verification
    if ($Job.FixedRules -and $Job.FixedRules.Count -gt 0) {
        $ArgParts.Add("--controls")
        foreach ($Rule in $Job.FixedRules) {
            $ArgParts.Add($Rule)
        }
    }

    $ArgParts.Add("--reporter")
    $ArgParts.Add("json:$DeltaJson")

    # Return pure token array
    return ,$ArgParts.ToArray()
}

Export-ModuleMember -Function Get-AssetProviderConfig, Get-AssetObject, Invoke-AssetRemediation, Get-AssetVerificationArgs, Initialize-AssetProvider, Finalize-AssetProvider