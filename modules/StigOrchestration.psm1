# =========================================================================
# MODULE: StigOrchestration.psm1
# DESCRIPTION: Decoupled Master Controller. Discovers inventory, routes to workers,
#              summarizes outputs, and syncs to STIG Manager by individual class.
# =========================================================================

if (Test-Path "/usr/share/stigs/orchestration_overlay") {
    $Script:OverlayRoot = "/usr/share/stigs/orchestration_overlay"
} else {
    $Script:OverlayRoot = (Resolve-Path "$PSScriptRoot/..").Path
}

# Add this back to suppress PowerCLI stdout pollution:
$WarningPreference = 'SilentlyContinue'

# Load Dependencies and Workers dynamically from the Overlay Root
Import-Module powershell-yaml -Global -Force -ErrorAction Stop 
Import-Module (Join-Path $Script:OverlayRoot "modules/CredentialManagement.psm1") -Global -Force -ErrorAction Stop
Import-Module (Join-Path $Script:OverlayRoot "modules/globalFunctions.psm1") -Global -Force -ErrorAction Stop

Import-Module (Join-Path $Script:OverlayRoot "modules/vcsa/VcsaHelpers.psm1") -Global -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/esxi/EsxiHelpers.psm1") -Global -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/vm/VmHelpers.psm1") -Global -Force -ErrorAction SilentlyContinue

Import-Module (Join-Path $Script:OverlayRoot "modules/vcsa/Invoke-VcsaAudit.psm1") -Global -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/esxi/Invoke-EsxiAudit.psm1") -Global -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/vm/Invoke-VmAudit.psm1") -Global -Force -ErrorAction SilentlyContinue

<#
.SYNOPSIS
    Discovers vCenter inventory and builds the target manifest.
#>
function Get-StigInventory {
    [CmdletBinding()]
    param (
        [string]$OverlayRoot = $Script:OverlayRoot,
        [ValidateSet('All', 'VCSA', 'ESXi', 'VM')]
        [string[]]$TargetType = @('All')
    )

    $CredentialFile = Join-Path $OverlayRoot "conf/.creds.json.encrypted"
    $DateStr        = Get-Date -Format "yyyyMMdd"

    # 1. Load global configuration settings
    $GlobalConfPath = Join-Path $OverlayRoot "conf/global_config.yml"
    if (-not (Test-Path $GlobalConfPath)) { Throw "Global configuration not found at $GlobalConfPath" }
    $GlobalConf = Get-Content $GlobalConfPath -Raw | ConvertFrom-Yaml
    
    $VmExclusionRegex = if ($GlobalConf.vm_exclusion_regex) { $GlobalConf.vm_exclusion_regex } else { "^vCLS|NSX|vCenter|Appliance.*" }

    # 2. Extract only enabled FQDNs from plain-text configuration
    $ActiveFqdns = [System.Collections.Generic.List[string]]::new()
    if ($GlobalConf.vcenter_targets) {
        foreach ($t in $GlobalConf.vcenter_targets) {
            $Fqdn    = if ($t.fqdn) { $t.fqdn } else { $t["fqdn"] }
            $Enabled = if ($null -ne $t.enabled) { $t.enabled } else { $t["enabled"] }

            if ($Enabled -eq $true -or $Enabled -eq "true") {
                [void]$ActiveFqdns.Add($Fqdn)
            } else {
                Write-StigLog -Message "vCenter scanning is disabled in global_config.yml: $Fqdn" -Severity INFO -Source "Inventory"
            }
        }
    } else {
        Throw "No vcenter_targets section defined in global_config.yml."
    }

    if ($ActiveFqdns.Count -eq 0) {
        Write-StigLog -Message "No enabled vCenter targets found in global_config.yml. Inventory manifest empty." -Severity WARN -Source "Inventory"
        return [PSCustomObject]@{ vCenters = $null; ESXiHosts = $null; VMs = $null }
    }

    # 3. Retrieve the secure credential store
    $credentials = Get-vCenterCredentialStore -FilePath $CredentialFile
    if (-not $credentials.vCenters) { Throw "No vCenter credential entries found in the secure vault." }

    $MasterTargetList = [PSCustomObject]@{
        vCenters  = $null
        ESXiHosts = $null
        VMs       = $null
    }

    $getVcsa = ($TargetType -contains 'All' -or $TargetType -contains 'VCSA')
    $getEsxi = ($TargetType -contains 'All' -or $TargetType -contains 'ESXi')
    $getVm   = ($TargetType -contains 'All' -or $TargetType -contains 'VM')

    Write-StigLog -Message "Starting Dynamic Inventory Discovery (Target Types: $($TargetType -join ', '))..." -Severity INFO -Source "Inventory"

    # 4. Process enabled targets that exist in vault
    foreach ($vCenterFQDN in $ActiveFqdns) {
        $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
        
        $vaultEntry = $credentials.vCenters | Where-Object { $_.FQDN -eq $vCenterFQDN }
        if ($null -eq $vaultEntry) {
            Write-StigLog -Message "CRITICAL: Scans enabled for '$vCenterFQDN' but no secure credentials exist in vault. Skipping." -Severity ERROR -Source "Inventory"
            continue
        }

        Write-Verbose "Processing Credentials for $vCenterFQDN ($vCenterShortName)..."
        
        $credObj   = Get-vCenterCredential -FQDN $vCenterFQDN -FilePath $CredentialFile
        $adminUser = $credObj.AdminCred.UserName
        $adminPass = $credObj.AdminCred.GetNetworkCredential().Password
        $rootPass  = $credObj.RootCred.GetNetworkCredential().Password
        $esxiRoot  = $credObj.EsxiCred.GetNetworkCredential().Password

        if ($getVcsa) {
            $VcsaReportDir = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/VCSA"
            if ($null -eq $MasterTargetList.vCenters) { $MasterTargetList.vCenters = @() }
            
            $MasterTargetList.vCenters += [PSCustomObject]@{
                FQDN             = $vCenterFQDN
                AdminUser        = $adminUser
                AdminPass        = $adminPass
                RootPass         = $rootPass
                vCenterShortName = $vCenterShortName
                DateStr          = $DateStr
                ReportDir        = $VcsaReportDir
            }
        }

        if ($getEsxi -or $getVm) {
            try {
                Write-Verbose "Connecting to PowerCLI for $vCenterFQDN to enumerate Hosts/VMs..."
                Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -InvalidCertificateAction Ignore -Confirm:$false -Scope User | Out-Null
               $InventoryConnection = Connect-VIServer -Server $vCenterFQDN -User $adminUser -Password $adminPass -Force -ErrorAction Stop
                
                if ($getEsxi) {
                    $EsxiReportDir = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/ESXi"
                    if ($null -eq $MasterTargetList.ESXiHosts) { $MasterTargetList.ESXiHosts = @() }
                    
                    $Hosts = Get-VMHost
                    foreach ($h in $Hosts) {
                        $MasterTargetList.ESXiHosts += [PSCustomObject]@{ 
                            Name             = $h.Name
                            vCenter          = $vCenterFQDN
                            AdminUser        = $adminUser
                            AdminPass        = $adminPass
                            RootPass         = $esxiRoot
                            vCenterShortName = $vCenterShortName
                            DateStr          = $DateStr
                            ReportDir        = $EsxiReportDir
                        }
                    }
                }

                if ($getVm) {
                    $VmReportDir = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/VMs"
                    if ($null -eq $MasterTargetList.VMs) { $MasterTargetList.VMs = @() }

                    $VMs = Get-VM | Where-Object { $_.PowerState -eq "PoweredOn" -and $_.Name -notmatch $VmExclusionRegex }
                    foreach ($vm in $VMs) {
                        $MasterTargetList.VMs += [PSCustomObject]@{ 
                            Name             = $vm.Name
                            vCenter          = $vCenterFQDN
                            AdminUser        = $adminUser
                            AdminPass        = $adminPass
                            vCenterShortName = $vCenterShortName
                            DateStr          = $DateStr
                            ReportDir        = $VmReportDir
                        }
                    }
                }

                Disconnect-VIServer -Server $InventoryConnection -Confirm:$false | Out-Null
            } catch {
                Write-StigLog -Message "Failed to retrieve ESXi/VM inventory from ${vCenterFQDN}: $($_.Exception.Message)" -Severity ERROR -Source "Inventory"
            }
        }
    }
    
    return $MasterTargetList
}

<#
.SYNOPSIS
    Routes targets to their respective execution workers.
#>
function Invoke-StigAudit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject]$TargetManifest,

        [string]$OverlayRoot = $Script:OverlayRoot
    )

    process {
        Write-StigLog -Message "Routing targets to execution workers..." -Severity INFO -Source "Orchestrator"
        
        # VCSA Phase
        if ($TargetManifest.vCenters) { 
            $TargetManifest.vCenters | Invoke-VcsaAudit -OverlayRoot $OverlayRoot | Format-StigChecklist -OverlayRoot $OverlayRoot 
        }

        # ESXi Phase (Staged in batches of 10)
        if ($TargetManifest.ESXiHosts) { 
            $TotalESXi = $TargetManifest.ESXiHosts.Count
            $BatchSize = 10 

            Write-StigLog -Message "Discovered $TotalESXi ESXi hosts. Processing in batches of $BatchSize..." -Severity INFO -Source "Orchestrator"
            
            for ($i = 0; $i -lt $TotalESXi; $i += $BatchSize) {
                $Batch = $TargetManifest.ESXiHosts | Select-Object -Skip $i -First $BatchSize
                $BatchNumber = [math]::Floor($i / $BatchSize) + 1
                $TotalBatches = [math]::Ceiling($TotalESXi / $BatchSize)
                
                Write-StigLog -Message "--- Processing ESXi Batch $BatchNumber of $TotalBatches ---" -Severity INFO -Source "Orchestrator"
                
                Invoke-EsxiAudit -TargetList $Batch -OverlayRoot $OverlayRoot | Format-StigChecklist -OverlayRoot $OverlayRoot
            }
        }

        # VM Phase (Staged in batches of 40)
        if ($TargetManifest.VMs) { 
            $TotalVMs  = $TargetManifest.VMs.Count
            $BatchSize = 40 

            Write-StigLog -Message "Discovered $TotalVMs VMs. Processing in batches of $BatchSize..." -Severity INFO -Source "Orchestrator"
            
            for ($i = 0; $i -lt $TotalVMs; $i += $BatchSize) {
                $Batch = $TargetManifest.VMs | Select-Object -Skip $i -First $BatchSize
                $BatchNumber = [math]::Floor($i / $BatchSize) + 1
                $TotalBatches = [math]::Ceiling($TotalVMs / $BatchSize)
                
                Write-StigLog -Message "--- Processing VM Batch $BatchNumber of $TotalBatches ---" -Severity INFO -Source "Orchestrator"
                
                Invoke-VmAudit -TargetList $Batch -OverlayRoot $OverlayRoot | Format-StigChecklist -OverlayRoot $OverlayRoot
            }
        }
    }
}

<#
.SYNOPSIS
    Master formatting engine for all STIG Checklists.
#>
function Format-StigChecklist {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject]$AuditResult,
        
        [string]$OverlayRoot = $Script:OverlayRoot
    )

    begin {
        $ResultsQueue = @()
        
        $GlobalConfPath = Join-Path $OverlayRoot "conf/global_config.yml"
        if (-not (Test-Path $GlobalConfPath)) { Throw "Global configuration not found at $GlobalConfPath" }
        $GlobalConf = Get-Content $GlobalConfPath -Raw | ConvertFrom-Yaml

        $Script:TemplateDir = Join-Path $OverlayRoot "templates/CKL_Templates/$($GlobalConf.stig_release)"
        if (-not (Test-Path $Script:TemplateDir)) { Throw "Template directory not found: $($Script:TemplateDir)" }
        
        $Script:GlobalMarking = $GlobalConf.marking
    }

    process {
        if ($null -ne $AuditResult -and -not [string]::IsNullOrWhiteSpace($AuditResult.TargetName)) {
            $ResultsQueue += $AuditResult
        }
    }

    end {
        if ($ResultsQueue.Count -gt 0) {
            Write-StigLog -Message "Initiating Parallel Formatting for $($ResultsQueue.Count) targets..." -Severity INFO -Source "Formatter"
        }

        $ResultsQueue | ForEach-Object -Parallel {
            $AuditResult   = $_
            $OverlayRoot   = $using:OverlayRoot
            $TemplateDir   = $using:Script:TemplateDir
            $GlobalMarking = $using:Script:GlobalMarking
            
            $GlobalFuncsPath = Join-Path $OverlayRoot "modules/globalFunctions.psm1"
            $GlobalFuncsText = Get-Content $GlobalFuncsPath -Raw
            $GlobalFuncsSafe = $GlobalFuncsText -replace '(?m)^Export-ModuleMember.*', ''
            Invoke-Expression $GlobalFuncsSafe

            $TargetName       = $AuditResult.TargetName
            $TargetType       = $AuditResult.TargetType
            $Component        = $AuditResult.DisaComponent
            $vCenterShortName = $AuditResult.vCenterShortName
            $DateStr          = $AuditResult.DateStr
            
            $TargetShortName  = ($TargetName -split '\.')[0].ToUpper()

            $FolderType = switch ($TargetType) {
                "VCSA" { "VCSA" }
                "ESXi" { "ESXi" }
                "VM"   { "VMs" }
            }
            $OutputCklDir = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/$FolderType"
            if (-not (Test-Path $OutputCklDir)) { New-Item -ItemType Directory -Path $OutputCklDir -Force | Out-Null }

            $AnswersXmlPath = Join-Path $OverlayRoot "conf/$($TargetType.ToLower())/answers.xml"
            $PureDisaTemplatePath = Get-DisaTemplate -TemplateDir $TemplateDir -ComponentType $Component
            $TemplateBaseName = [System.IO.Path]::GetFileNameWithoutExtension($PureDisaTemplatePath)

            $FinalCkl = Join-Path $OutputCklDir "${TargetShortName}_${TemplateBaseName}_${DateStr}.ckl"
            $StagingDir = "/tmp/stig_staging/$($TargetName)"
            $TempBase = "$StagingDir/${TargetShortName}_${Component}"

            if ($TargetType -eq "ESXi") {
                $ApiTempCkl = "${TempBase}_API_temp.ckl"
                $SshTempCkl = "${TempBase}_SSH_temp.ckl"
                $MasterTempCkl = $null

                if ($AuditResult.ApiJsonFile -and (Test-Path $AuditResult.ApiJsonFile)) {
                    bash -c "saf convert hdf2ckl -i '$($AuditResult.ApiJsonFile)' -o '$ApiTempCkl'" | Out-Null
                    if (Test-Path $ApiTempCkl) { $MasterTempCkl = $ApiTempCkl }
                }

                if ($AuditResult.SshJsonFile -and (Test-Path $AuditResult.SshJsonFile)) {
                    bash -c "saf convert hdf2ckl -i '$($AuditResult.SshJsonFile)' -o '$SshTempCkl'" | Out-Null
                    
                    if (Test-Path $SshTempCkl) {
                        if ($MasterTempCkl) {
                            $ApiXml = New-Object System.Xml.XmlDocument
                            $ApiXml.PreserveWhitespace = $true
                            $ApiXml.Load($ApiTempCkl)
                            
                            $SshXml = New-Object System.Xml.XmlDocument
                            $SshXml.Load($SshTempCkl)

                            foreach ($sshVuln in $SshXml.CHECKLIST.STIGS.iSTIG.VULN) {
                                $vulnNumNode = $sshVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Vuln_Num" }
                                if ($vulnNumNode) {
                                    $vulnNum = $vulnNumNode.SelectSingleNode("ATTRIBUTE_DATA").InnerText
                                    $xpath = "/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA/VULN_ATTRIBUTE='Vuln_Num' and STIG_DATA/ATTRIBUTE_DATA='$vulnNum']"
                                    $apiVulnNode = $ApiXml.SelectSingleNode($xpath)

                                    if ($apiVulnNode) {
                                        $apiVulnNode.SelectSingleNode("STATUS").InnerText = $sshVuln.SelectSingleNode("STATUS").InnerText
                                        $apiVulnNode.SelectSingleNode("FINDING_DETAILS").InnerXml = $sshVuln.SelectSingleNode("FINDING_DETAILS").InnerXml
                                    }
                                }
                            }
                            $ApiXml.Save($ApiTempCkl)
                        } else {
                            $MasterTempCkl = $SshTempCkl
                        }
                    }
                }
            } else {
                $MasterTempCkl = "${TempBase}_temp.ckl"
                bash -c "saf convert hdf2ckl -i '$($AuditResult.RawJsonFile)' -o '$MasterTempCkl'" | Out-Null
            }

            if (-not $MasterTempCkl) { 
                Write-StigLog -Message "Failed to generate Temp CKLs for merging on $TargetName" -Severity ERROR -Source "Formatter"
                return 
            }

            # Overlay Custom API Findings
            if ($AuditResult.CustomApiJsonFile -and (Test-Path $AuditResult.CustomApiJsonFile)) {
                $CustomApiTempCkl = "${TempBase}_CUSTOM_API_temp.ckl"
                bash -c "saf convert hdf2ckl -i '$($AuditResult.CustomApiJsonFile)' -o '$CustomApiTempCkl'" | Out-Null
                
                if ((Test-Path $CustomApiTempCkl) -and $MasterTempCkl) {
                    $MasterXml = New-Object System.Xml.XmlDocument
                    $MasterXml.PreserveWhitespace = $true
                    $MasterXml.Load($MasterTempCkl)
                    
                    $CustomXml = New-Object System.Xml.XmlDocument
                    $CustomXml.Load($CustomApiTempCkl)

                    $apiMergeCount = 0
                    foreach ($customVuln in $CustomXml.CHECKLIST.STIGS.iSTIG.VULN) {
                        $customIdNode = $customVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Vuln_Num" }
                        if ($customIdNode) {
                            $customId = $customIdNode.SelectSingleNode("ATTRIBUTE_DATA").InnerText
                            $xpath = "/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA/VULN_ATTRIBUTE='Rule_Ver' and STIG_DATA/ATTRIBUTE_DATA='$customId']"
                            $masterVulnNode = $MasterXml.SelectSingleNode($xpath)

                            if ($masterVulnNode) {
                                $masterVulnNode.SelectSingleNode("STATUS").InnerText = $customVuln.SelectSingleNode("STATUS").InnerText
                                $masterVulnNode.SelectSingleNode("FINDING_DETAILS").InnerXml = $customVuln.SelectSingleNode("FINDING_DETAILS").InnerXml
                                $apiMergeCount++
                            }
                        }
                    }
                    $MasterXml.Save($MasterTempCkl)
                }
            }

            # Overlay Custom SSH Findings
            if ($AuditResult.CustomSshJsonFile -and (Test-Path $AuditResult.CustomSshJsonFile)) {
                $CustomSshTempCkl = "${TempBase}_CUSTOM_SSH_temp.ckl"
                bash -c "saf convert hdf2ckl -i '$($AuditResult.CustomSshJsonFile)' -o '$CustomSshTempCkl'" | Out-Null
                
                if ((Test-Path $CustomSshTempCkl) -and $MasterTempCkl) {
                    $MasterXml = New-Object System.Xml.XmlDocument
                    $MasterXml.PreserveWhitespace = $true
                    $MasterXml.Load($MasterTempCkl)
                    
                    $CustomXml = New-Object System.Xml.XmlDocument
                    $CustomXml.Load($CustomSshTempCkl)

                    $sshMergeCount = 0
                    foreach ($customVuln in $CustomXml.CHECKLIST.STIGS.iSTIG.VULN) {
                        $customIdNode = $customVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Vuln_Num" }
                        if ($customIdNode) {
                            $customId = $customIdNode.SelectSingleNode("ATTRIBUTE_DATA").InnerText
                            $xpath = "/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA/VULN_ATTRIBUTE='Rule_Ver' and STIG_DATA/ATTRIBUTE_DATA='$customId']"
                            $masterVulnNode = $MasterXml.SelectSingleNode($xpath)

                            if ($masterVulnNode) {
                                $masterVulnNode.SelectSingleNode("STATUS").InnerText = $customVuln.SelectSingleNode("STATUS").InnerText
                                $masterVulnNode.SelectSingleNode("FINDING_DETAILS").InnerXml = $customVuln.SelectSingleNode("FINDING_DETAILS").InnerXml
                                $sshMergeCount++
                            }
                        }
                    }
                    $MasterXml.Save($MasterTempCkl)
                }
            }

            if (Test-Path $MasterTempCkl) {
                $UpdateJob = [PSCustomObject]@{
                    profileName      = $TargetName
                    tempCklFile      = $MasterTempCkl
                    pureTemplate     = $PureDisaTemplatePath
                    cklFile          = $FinalCkl
                    MARKING          = $GlobalMarking   
                    answerFilePath   = $AnswersXmlPath
                    vCenterShortName = $AuditResult.vCenterShortName
                    TargetName       = $AuditResult.TargetName
                    IPAddress        = $AuditResult.IPAddress
                    MACAddress       = $AuditResult.MACAddress
                    DNSName          = if ($AuditResult.DNSName) { $AuditResult.DNSName } else { "" }
                    ESXiName         = $AuditResult.TargetName
                    ESXiFQDN         = $AuditResult.TargetName
                    ESXi_IP          = $AuditResult.IPAddress
                    ESXi_MAC         = $AuditResult.MACAddress
                }

                try {
                    Update-CklTemplate -UpdateJobs @($UpdateJob) -UpdateType $TargetType
                    Write-StigLog -Message "Successfully formatted and saved: $FinalCkl" -Severity SUCCESS -Source "Formatter"
                } catch {
                    Write-StigLog -Message "Failed to apply final formatting for ${TargetName}: $($_.Exception.Message)" -Severity ERROR -Source "Formatter"
                }
            }
        } -ThrottleLimit 15
        
        $UniqueTargets = $ResultsQueue | Select-Object -ExpandProperty TargetName -Unique
        foreach ($Target in $UniqueTargets) {
            $TargetStagingDir = "/tmp/stig_staging/$Target"
            if (Test-Path $TargetStagingDir) {
                Remove-Item -Path $TargetStagingDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

<#
.SYNOPSIS
    Loads configuration settings and filters enabled FQDNs.
#>
function Get-ActiveTargets {
    param([string]$OverlayRoot)
    $GlobalConfPath = Join-Path $OverlayRoot "conf/global_config.yml"
    if (-not (Test-Path $GlobalConfPath)) { Throw "Global configuration not found at $GlobalConfPath" }
    $GlobalConf = Get-Content $GlobalConfPath -Raw | ConvertFrom-Yaml

    $ActiveList = [System.Collections.Generic.List[string]]::new()
    if ($GlobalConf.vcenter_targets) {
        foreach ($t in $GlobalConf.vcenter_targets) {
            $Fqdn    = if ($t.fqdn) { $t.fqdn } else { $t["fqdn"] }
            $Enabled = if ($null -ne $t.enabled) { $t.enabled } else { $t["enabled"] }

            if ($Enabled -eq $true -or $Enabled -eq "true") {
                [void]$ActiveList.Add($Fqdn)
            }
        }
    }
    return $ActiveList
}

# =========================================================================
# ORCHESTRATOR 1: MULTI-VCSA INDEPENDENT SERVICE RUNNER
# =========================================================================
function Invoke-MultiVcsaOrchestration {
    [CmdletBinding()]
    param (
        [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay",
        [switch]$Silent
    )

    $StartTime = Get-Date
    Initialize-StigLogging -LogDirectory (Join-Path $OverlayRoot "logs") -Silent:$Silent
    Write-StigLog -Message "Starting Multi-VCSA Dedicated STIG Audits..." -Severity INFO -Source "VcsaOrch"

    try {
        $ActiveTargets = Get-ActiveTargets -OverlayRoot $OverlayRoot
        if ($ActiveTargets.Count -eq 0) { return }

        # Optimization: Only query VCSA asset manifest
        $MasterInventory = Get-StigInventory -OverlayRoot $OverlayRoot -TargetType 'VCSA'
        $DateStr = Get-Date -Format "yyyyMMdd"

        foreach ($vCenterFQDN in $ActiveTargets) {
            $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
            $VcsaTargets = $MasterInventory.vCenters | Where-Object { $_.FQDN -eq $vCenterFQDN }
            
            if ($VcsaTargets) {
                Write-StigLog -Message "[$vCenterShortName] SECTION 1: Initiating VCSA Scan..." -Severity INFO -Source "VcsaOrch"
                $VcsaManifest = [PSCustomObject]@{ vCenters = @($VcsaTargets); ESXiHosts = $null; VMs = $null }
                
                Invoke-StigAudit -TargetManifest $VcsaManifest -OverlayRoot $OverlayRoot
                
                $VcsaReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/VCSA"
                $VcsaAnswersXml = Join-Path $OverlayRoot "conf/vcsa/answers.xml"
                Get-StigScanSummary -ReportDir $VcsaReportPath -AnswersXmlPath $VcsaAnswersXml

                Invoke-StigManSync -vCenterShortName $vCenterShortName -SectionReportDir $VcsaReportPath -OverlayRoot $OverlayRoot
                
                # Automated retention cleanup after each vCenter section
                Invoke-ReportsRetentionCleanup -ReportsBaseDir (Join-Path $OverlayRoot "reports") -KeepLast 5
            }
        }
        
        # Automated log cleanup at end of full cycle
        Invoke-LogRetentionCleanup -LogDirectory (Join-Path $OverlayRoot "logs") -KeepDays 14
        
        Write-ElapsedTime -StartTime $StartTime -Message "Multi-VCSA Auditing Cycle Complete." -Source "VcsaOrch"

        # Compile and send the final HTML report
        Send-StigExecutionReport -JobName "VCSA_STIG_Audit" -DateStr $StartTime.ToString("yyyyMMdd") -vCenterList $ActiveTargets -Scope "VCSA" -OverlayRoot $OverlayRoot
    }
    catch {
        Write-StigLog -Message "VCSA Orchestrator Failed: $($_.Exception.Message)" -Severity ERROR -Source "VcsaOrch"
    }
}

# =========================================================================
# ORCHESTRATOR 2: MULTI-ESXI INDEPENDENT SERVICE RUNNER
# =========================================================================
function Invoke-MultiEsxiOrchestration {
    [CmdletBinding()]
    param (
        [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay",
        [switch]$Silent
    )

    $StartTime = Get-Date
    Initialize-StigLogging -LogDirectory (Join-Path $OverlayRoot "logs") -Silent:$Silent
    Write-StigLog -Message "Starting Multi-ESXi Dedicated STIG Audits..." -Severity INFO -Source "EsxiOrch"

    try {
        $ActiveTargets = Get-ActiveTargets -OverlayRoot $OverlayRoot
        if ($ActiveTargets.Count -eq 0) { return }

        # Optimization: Only query ESXi asset manifest (No heavy VM discovery)
        $MasterInventory = Get-StigInventory -OverlayRoot $OverlayRoot -TargetType 'ESXi'
        $DateStr = Get-Date -Format "yyyyMMdd"

        foreach ($vCenterFQDN in $ActiveTargets) {
            $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
            $EsxiTargets = $MasterInventory.ESXiHosts | Where-Object { $_.vCenter -eq $vCenterFQDN }
            
            if ($EsxiTargets -and $EsxiTargets.Count -gt 0) {
                Write-StigLog -Message "[$vCenterShortName] SECTION 2: Initiating ESXi Scan..." -Severity INFO -Source "EsxiOrch"
                $EsxiManifest = [PSCustomObject]@{ vCenters = $null; ESXiHosts = $EsxiTargets; VMs = $null }
                
                Invoke-StigAudit -TargetManifest $EsxiManifest -OverlayRoot $OverlayRoot
                
                $EsxiReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/ESXi"
                $EsxiAnswersXml = Join-Path $OverlayRoot "conf/esxi/answers.xml"
                Get-StigScanSummary -ReportDir $EsxiReportPath -AnswersXmlPath $EsxiAnswersXml

                Invoke-StigManSync -vCenterShortName $vCenterShortName -SectionReportDir $EsxiReportPath -OverlayRoot $OverlayRoot
                
                # Automated retention cleanup after each vCenter section
                Invoke-ReportsRetentionCleanup -ReportsBaseDir (Join-Path $OverlayRoot "reports") -KeepLast 5
            }
        }
        
        # Automated log cleanup at end of full cycle
        Invoke-LogRetentionCleanup -LogDirectory (Join-Path $OverlayRoot "logs") -KeepDays 14

        Send-StigExecutionReport -JobName "ESXI_STIG_Audit" -DateStr $StartTime.ToString("yyyyMMdd") -vCenterList $ActiveTargets -Scope "ESXi" -OverlayRoot $OverlayRoot -ExitCode $LASTEXITCODE
        
        Write-ElapsedTime -StartTime $StartTime -Message "Multi-ESXi Auditing Cycle Complete." -Source "EsxiOrch"
    }
    catch {
        Write-StigLog -Message "ESXi Orchestrator Failed: $($_.Exception.Message)" -Severity ERROR -Source "EsxiOrch"
    }
}

# =========================================================================
# ORCHESTRATOR 3: MULTI-VM INDEPENDENT SERVICE RUNNER
# =========================================================================
function Invoke-MultiVmOrchestration {
    [CmdletBinding()]
    param (
        [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay",
        [switch]$Silent
    )

    $StartTime = Get-Date
    Initialize-StigLogging -LogDirectory (Join-Path $OverlayRoot "logs") -Silent:$Silent
    Write-StigLog -Message "Starting Multi-VM Dedicated STIG Audits..." -Severity INFO -Source "VmOrch"

    try {
        $ActiveTargets = Get-ActiveTargets -OverlayRoot $OverlayRoot
        if ($ActiveTargets.Count -eq 0) { return }

        # Optimization: Only query VM asset manifest
        $MasterInventory = Get-StigInventory -OverlayRoot $OverlayRoot -TargetType 'VM'
        $DateStr = Get-Date -Format "yyyyMMdd"

        foreach ($vCenterFQDN in $ActiveTargets) {
            $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
            $VmTargets = $MasterInventory.VMs | Where-Object { $_.vCenter -eq $vCenterFQDN }
            
            if ($VmTargets -and $VmTargets.Count -gt 0) {
                Write-StigLog -Message "[$vCenterShortName] SECTION 3: Initiating VM Scan..." -Severity INFO -Source "VmOrch"
                $VmManifest = [PSCustomObject]@{ vCenters = $null; ESXiHosts = $null; VMs = $VmTargets }
                
                Invoke-StigAudit -TargetManifest $VmManifest -OverlayRoot $OverlayRoot
                
                $VmReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/VMs"
                $VmAnswersXml = Join-Path $OverlayRoot "conf/vm/answers.xml"
                Get-StigScanSummary -ReportDir $VmReportPath -AnswersXmlPath $VmAnswersXml

                Invoke-StigManSync -vCenterShortName $vCenterShortName -SectionReportDir $VmReportPath -OverlayRoot $OverlayRoot
                
                # Automated retention cleanup after each vCenter section
                Invoke-ReportsRetentionCleanup -ReportsBaseDir (Join-Path $OverlayRoot "reports") -KeepLast 5
            }
        }
        
        # Automated log cleanup at end of full cycle
        Invoke-LogRetentionCleanup -LogDirectory (Join-Path $OverlayRoot "logs") -KeepDays 14
        
        Send-StigExecutionReport -JobName "VM_STIG_Audit" -DateStr $StartTime.ToString("yyyyMMdd") -vCenterList $ActiveTargets -Scope "VMs" -OverlayRoot $OverlayRoot -ExitCode $LASTEXITCODE
        
        Write-ElapsedTime -StartTime $StartTime -Message "Multi-VM Auditing Cycle Complete." -Source "VmOrch"
    }
    catch {
        Write-StigLog -Message "VM Orchestrator Failed: $($_.Exception.Message)" -Severity ERROR -Source "VmOrch"
    }
}

<#
.SYNOPSIS
    Copies section CKL files to the corresponding STIG Manager Collection inbox 
    and triggers the bash stigman-watcher one-shot upload.
    Prioritizes the globally defined collection_id from global_config.yml.
    After successful upload, removes the copied file from the inbox to keep it clean.
#>
function Invoke-StigManSync {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$vCenterShortName,
        [Parameter(Mandatory=$true)][string]$SectionReportDir,
        [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
    )

    # 1. Verify STIG Manager Integration is enabled in global configuration
    $GlobalConfPath = Join-Path $OverlayRoot "conf/global_config.yml"
    if (-not (Test-Path $GlobalConfPath)) {
        Write-StigLog -Message "Global configuration file not found at $GlobalConfPath" -Severity ERROR -Source "StigManSync"
        return
    }
    
    $GlobalConf = Get-Content $GlobalConfPath -Raw | ConvertFrom-Yaml
    $StigManConf = $GlobalConf.stigman_integration

    if ($null -eq $StigManConf -or $StigManConf.enabled -ne $true) {
        Write-StigLog -Message "STIG Manager sync bypassed (disabled or unconfigured in global_config.yml)." -Severity DEBUG -Source "StigManSync"
        return
    }

    # 2. Resolve Collection ID: 
    $CollectionId = $null

    if ($StigManConf.collection_mappings -and $StigManConf.collection_mappings.$vCenterShortName) {
        $CollectionId = $StigManConf.collection_mappings.$vCenterShortName
        Write-StigLog -Message "[$vCenterShortName] Resolved override Collection ID: $CollectionId" -Severity INFO -Source "StigManSync"
    }
    elseif ($StigManConf.collection_id) {
        $CollectionId = $StigManConf.collection_id
        Write-StigLog -Message "[$vCenterShortName] Utilizing global Collection ID: $CollectionId from global_config.yml" -Severity INFO -Source "StigManSync"
    }
    else {
        $CollectionId = "16" # Unified Fallback Default
        Write-StigLog -Message "[$vCenterShortName] No Collection ID configured. Defaulting to fallback ID: $CollectionId" -Severity WARN -Source "StigManSync"
    }

    # 3. Resolve and prepare the Collection Inbox Directory
    $InboxDir = "/usr/share/stigs/orchestration_overlay/stigman-watcher/inboxes/coll_$CollectionId"
    if (-not (Test-Path $InboxDir)) {
        New-Item -ItemType Directory -Path $InboxDir -Force | Out-Null
    }

    # 4. Copy newly formatted section CKL files to the Inbox folder
    $CklFiles = Get-ChildItem -Path $SectionReportDir -Filter "*.ckl" -Recurse
    if ($CklFiles.Count -eq 0) {
        Write-StigLog -Message "No checklists found in $SectionReportDir to upload." -Severity INFO -Source "StigManSync"
        return
    }

    $CopiedFiles = @()
    foreach ($Ckl in $CklFiles) {
        $DestPath = Join-Path $InboxDir $Ckl.Name
        Copy-Item -Path $Ckl.FullName -Destination $DestPath -Force | Out-Null
        $CopiedFiles += $DestPath
        Write-StigLog -Message "[$vCenterShortName] Copied checklist to Watcher Inbox: $($Ckl.Name)" -Severity DEBUG -Source "StigManSync"
    }

    # 5. Resolve the Unix Bash Wrapper Script path
    $WatcherScript = Join-Path $OverlayRoot "bin/run-stigman-watcher.sh"
    if (-not (Test-Path $WatcherScript)) {
        $WatcherScript = "/usr/share/stigs/orchestration_overlay/bin/run-stigman-watcher.sh"
        if (-not (Test-Path $WatcherScript)) {
            Write-StigLog -Message "Target execution script not found: $WatcherScript" -Severity ERROR -Source "StigManSync"
            return
        }
    }

    # 6. Execute Unix One-Shot upload using system-native bash interpreter
    Write-StigLog -Message "Running STIG Manager Watcher upload payload for Collection $CollectionId..." -Severity INFO -Source "StigManSync"
    
    $BashCmd = "bash '$WatcherScript' '$CollectionId'"
    $BashOutput = bash -c $BashCmd 2>&1

    # 7. Inbox Hygiene: Remove copied files after successful upload to keep inbox clean
    #    The authoritative historical copy remains in the dated /reports/ folder.
    if ($LASTEXITCODE -eq 0) {
        Write-StigLog -Message "STIG Manager synchronization successfully finalized for Collection $CollectionId." -Severity SUCCESS -Source "StigManSync"
        
        foreach ($file in $CopiedFiles) {
            if (Test-Path $file) {
                Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        Write-StigLog -Message "STIG Manager Watcher encountered errors (Exit Code: $LASTEXITCODE). Output: $BashOutput" -Severity ERROR -Source "StigManSync"
    }
}

<#
.SYNOPSIS
    Compiles a summary of open STIG findings from generated CKL files for a given job run,
    writes the summary to a JSON file, and dispatches the final HTML email report.
#>
function Send-StigExecutionReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$JobName,
        [Parameter(Mandatory=$true)][string]$DateStr,
        [Parameter(Mandatory=$true)][string[]]$vCenterList,
        [string]$Scope = "Full Suite",
        [int]$ExitCode = 0,
        [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
    )

    $vCenterSummaries = @()
    $totalCat1 = 0; $totalCat2 = 0; $totalCat3 = 0; $totalTargets = 0
    $overallStatus = "SUCCESS"

    foreach ($vCenterFQDN in $vCenterList) {
        $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
        $vCenterBaseDir   = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName"
        
        $vcCat1 = 0; $vcCat2 = 0; $vcCat3 = 0; $vcTargetCount = 0
        $vcStatus = "SUCCESS"

        if (Test-Path $vCenterBaseDir) {
            $cklFiles = Get-ChildItem -Path $vCenterBaseDir -Filter "*.ckl" -Recurse
            $vcTargetCount = $cklFiles.Count

            foreach ($ckl in $cklFiles) {
                try {
                    [xml]$cklXml = Get-Content -Path $ckl.FullName -Raw
                    $openVulns = $cklXml.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STATUS -eq "Open" }
                    
                    foreach ($v in $openVulns) {
                        $severityNode = $v.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Severity" }
                        $sev = if ($severityNode) { $severityNode.SelectSingleNode("ATTRIBUTE_DATA").InnerText } else { "medium" }

                        switch ($sev.ToLower()) {
                            "high"   { $vcCat1++ }
                            "medium" { $vcCat2++ }
                            "low"    { $vcCat3++ }
                        }
                    }
                } catch {
                    $vcStatus = "FAILED"
                    $overallStatus = "FAILED"
                }
            }
        } else {
            $vcStatus = "FAILED"
            $overallStatus = "FAILED"
        }

        $vcTotalOpen = $vcCat1 + $vcCat2 + $vcCat3
        $totalCat1 += $vcCat1
        $totalCat2 += $vcCat2
        $totalCat3 += $vcCat3
        $totalTargets += $vcTargetCount

        $vCenterSummaries += [PSCustomObject]@{
            Name           = $vCenterShortName
            Scope          = $Scope
            Status         = $vcStatus
            TargetsScanned = $vcTargetCount
            Cat1Open       = $vcCat1
            Cat2Open       = $vcCat2
            Cat3Open       = $vcCat3
            TotalOpen      = $vcTotalOpen
        }
    }

    $summaryObj = [PSCustomObject]@{
        JobName             = $JobName
        DateStr             = $DateStr
        TotalTargetsScanned = $totalTargets
        Cat1Open            = $totalCat1
        Cat2Open            = $totalCat2
        Cat3Open            = $totalCat3
        vCenters            = $vCenterSummaries
    }

    # Save summary JSON
    $summaryJsonDir  = Join-Path $OverlayRoot "reports/$DateStr"
    if (-not (Test-Path $summaryJsonDir)) { New-Item -ItemType Directory -Path $summaryJsonDir -Force | Out-Null }
    $summaryJsonPath = Join-Path $summaryJsonDir "stig_run_summary_${JobName}.json"
    $summaryObj | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryJsonPath -Force

    # Trigger the universal mailer script
    $mailScriptPath = Join-Path $OverlayRoot "bin/send_alert.ps1"
    $logPath        = Join-Path $OverlayRoot "logs/${JobName}_trace.log"

    if (Test-Path $mailScriptPath) {
        & $mailScriptPath -JobName $JobName -LogPath $logPath -ExitCode $ExitCode -Status $overallStatus -SummaryJsonPath $summaryJsonPath
    } else {
        Write-StigLog -Message "Email alert script not found at $mailScriptPath. Skipping notification." -Severity WARN -Source "Orchestrator"
    }
}

Export-ModuleMember -Function Get-StigInventory, Invoke-StigAudit, Format-StigChecklist, Invoke-MultiVcsaOrchestration, Invoke-MultiEsxiOrchestration, Invoke-MultiVmOrchestration, Invoke-MultiVMOrchestration, Invoke-StigManSync, Send-StigExecutionReport