# =========================================================================
# PROVIDER: VcsaRemediationProvider.psm1
# DESCRIPTION: Stub for VCSA STIG remediation.
# =========================================================================

function Get-AssetProviderConfig {
    param([string]$OverlayRoot)
    return [PSCustomObject]@{
        AnswersXml   = Join-Path $OverlayRoot "conf/vcsa/answers.xml"
        VariablesYml = Join-Path $OverlayRoot "conf/vcsa/variables.yaml"
        InspecAPI    = Join-Path $OverlayRoot "sourceDir/vsphere/inspec/vmware-vcsa-8.0"
    }
}

function Get-AssetObject {
    param([string]$Name)
    # Resolves target VCSA FQDN
    return $Name 
}

function Invoke-AssetRemediation {
    param([object]$AssetObject, [array]$FixList, [object]$Config, [object]$Creds)
    Write-Warning "VCSA dynamic remediation engine is not implemented yet. Skipping physical changes."
    return @()
}

function Get-AssetVerificationArgs {
    param($Job, $Config, $DeltaJson)
    $Controls = $Job.FixedRules -join " "
    return "exec '$($Config.InspecAPI)' -t ssh://root@$($Job.VcenterObjName) --reporter json:'$DeltaJson' --controls $Controls"
}