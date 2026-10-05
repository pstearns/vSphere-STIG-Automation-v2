# =========================================================================
# PROVIDER: EsxiRemediationProvider.psm1
# DESCRIPTION: Bridges the master orchestrator to your ESXi-specific tools.
# =========================================================================

$ProviderDir = Split-Path $MyInvocation.MyCommand.Path -Parent

$HelpersPath = Get-ChildItem -Path $ProviderDir -File | Where-Object { $_.Name.ToLower() -eq "esxihelpers.psm1" } | Select-Object -ExpandProperty FullName -First 1
$FuncsPath    = Get-ChildItem -Path $ProviderDir -File | Where-Object { $_.Name.ToLower() -eq "esxiremediationfunctions.psm1" } | Select-Object -ExpandProperty FullName -First 1

if ($HelpersPath) { Import-Module $HelpersPath -Force -DisableNameChecking }
if ($FuncsPath)    { Import-Module $FuncsPath -Force -DisableNameChecking }

function Convert-ObjectToHashtable {
    param($InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $hash = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $InputObject.Keys) {
            $hash[$key] = Convert-ObjectToHashtable $InputObject[$key]
        }
        return $hash
    } elseif ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $hash = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($prop in $InputObject.PSObject.Properties) {
            $hash[$prop.Name] = Convert-ObjectToHashtable $prop.Value
        }
        return $hash
    } elseif ($InputObject -is [System.Collections.IList] -or $InputObject -is [System.Array]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) {
            [void]$list.Add((Convert-ObjectToHashtable $item))
        }
        return $list.ToArray()
    } else {
        return $InputObject
    }
}

function Get-AssetProviderConfig {
    param([string]$OverlayRoot)
    
    $ConfFolder = Join-Path $OverlayRoot "conf"
    $EsxiConfDir = Join-Path $ConfFolder "ESXi"
    if (Test-Path $ConfFolder) {
        $MatchedConf = Get-ChildItem -Path $ConfFolder -Directory | Where-Object { $_.Name.ToLower() -eq "esxi" } | Select-Object -First 1
        if ($MatchedConf) { $EsxiConfDir = $MatchedConf.FullName }
    }

    $InputsYml = Join-Path $EsxiConfDir "inputs.yml"
    if (Test-Path $EsxiConfDir) {
        $MatchedInputs = Get-ChildItem -Path $EsxiConfDir -File | Where-Object { $_.Name.ToLower() -match "inputs\.ya?ml" } | Select-Object -First 1
        if ($MatchedInputs) { $InputsYml = $MatchedInputs.FullName }
    }

    $VsphereBasePath = "/usr/share/stigs/vsphere/8.0"
    $ApiProfilePath = Get-ChildItem -Path $VsphereBasePath -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -eq "esxi" -and $_.Parent.Name -match "vmware-vsphere-8.0-.*"
    } | Select-Object -ExpandProperty FullName -First 1

    if (-not $ApiProfilePath) {
        $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | 
            Sort-Object Name -Descending | 
            Select-Object -ExpandProperty Name -First 1
        
        if ($LatestStigRelease) {
            $ApiProfilePath = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/esxi"
        }
    }

    if (-not $ApiProfilePath -or -not (Test-Path $ApiProfilePath)) {
        $ApiProfilePath = Join-Path $OverlayRoot "sourceDir/vsphere/inspec/vmware-esxi-8.0-api"
    }

    return [PSCustomObject]@{
        AnswersXml   = Join-Path $EsxiConfDir "answers.xml"
        VariablesYml = $InputsYml
        InputsYml    = $InputsYml
        InspecSSH    = Join-Path $OverlayRoot "sourceDir/vsphere/inspec/vmware-esxi-8.0-ssh"
        InspecAPI    = $ApiProfilePath
        Playbook     = Join-Path $EsxiConfDir "ansible/playbook.yml"
    }
}

function Get-AssetObject {
    param([string]$Name)
    return Get-VMHost -Name $Name -ErrorAction SilentlyContinue
}

function Invoke-AssetRemediation {
    param(
        [object]$AssetObject,
        [array]$FixList,
        [object]$Config,
        [object]$Creds
    )
    # --- GUARD AGAINST DISCONNECTED / UNRESPONSIVE HOSTS
    if ($AssetObject.ConnectionState -ne "Connected") {
        Write-Warning "Host [$($AssetObject.Name)] is not connected (State: $($AssetObject.ConnectionState)). Aborting remediation."
        return @()
    }

    $SuccessFixes = [System.Collections.Generic.List[string]]::new()
    
    if (-not (Test-Path $Config.VariablesYml)) {
        Write-Warning "ESXi configuration file not found at: $($Config.VariablesYml)"
        return @()
    }

    $RawVariables = Get-Content -Path $Config.VariablesYml -Raw | ConvertFrom-Yaml
    $Variables = Convert-ObjectToHashtable -InputObject $RawVariables

    $SSHFixes = $FixList | Where-Object { $_ -match "SSH" -or $_ -eq "ESXI-80-000094" }
    $APIFixes = $FixList | Where-Object { $_ -notin $SSHFixes }

    # 1. PowerCLI API Remediations
    foreach ($Rule in $APIFixes) {
        try {
            & $Rule -vmhost $AssetObject -stigsettings $Variables
            $SuccessFixes.Add($Rule)
        }
        catch {
            # Corrected: Logs warnings safely instead of terminal crash
            Write-Warning "Failed API fix [$Rule] on host [$($AssetObject.Name)]: $_"
        }
    }

    # 2. Stateful SSH/Ansible Remediations
    if ($SSHFixes.Count -gt 0) {
        $vCenter = $AssetObject.ExtensionData.Client.ServiceUrl.Split('/')[2]
        $AdminUser = $Creds.AdminCred.UserName
        $AdminPass = $Creds.AdminCred.GetNetworkCredential().Password

        try {
            Set-EsxiAccessState -vCenter $vCenter -AdminUser $AdminUser -AdminPass $AdminPass -EsxiHost $AssetObject.Name -Enabled $true
            
            $Tags = $SSHFixes -join ","
            $RootPass = $Creds.EsxiCred.GetNetworkCredential().Password
            ansible-playbook -i "$($AssetObject.Name)," -u root $Config.Playbook --tags $Tags -e "ansible_ssh_pass=$RootPass"

            foreach ($Rule in $SSHFixes) { $SuccessFixes.Add($Rule) }
        }
        catch {
            Write-Warning "SSH remediation failed on host [$($AssetObject.Name)]: $_"
        }
        finally {
            Set-EsxiAccessState -vCenter $vCenter -AdminUser $AdminUser -AdminPass $AdminPass -EsxiHost $AssetObject.Name -Enabled $false
        }
    }

    return $SuccessFixes.ToArray()
}

function Get-AssetVerificationArgs {
    param($Job, $Config, $DeltaJson)

    $ArgParts = [System.Collections.Generic.List[string]]::new()
    $ArgParts.Add("exec")
    $ArgParts.Add($Config.InspecAPI)
    $ArgParts.Add("-t")
    $ArgParts.Add("vmware://")
    $ArgParts.Add("--insecure")
    $ArgParts.Add("--input")
    $ArgParts.Add("vmhostName=$($Job.VcenterObjName)")

    if (Test-Path $Config.InputsYml) {
        $ArgParts.Add("--input-file")
        $ArgParts.Add($Config.InputsYml)
    }

    if ($Job.FixedRules -and $Job.FixedRules.Count -gt 0) {
        $ArgParts.Add("--controls")
        foreach ($r in $Job.FixedRules) { $ArgParts.Add($r) }
    }

    $ArgParts.Add("--reporter")
    $ArgParts.Add("json:$DeltaJson")

    return ,$ArgParts.ToArray()
}