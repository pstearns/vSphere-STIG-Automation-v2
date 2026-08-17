# =========================================================================
# MODULE: StigOrchestration.psm1
# DESCRIPTION: Decoupled Master Controller. Discovers inventory, routes to workers,
#              summarizes outputs, and syncs to STIG Manager by individual class.
# =========================================================================

# Resolve Overlay Root Dynamically at Module Import (Ensures Portability)
if (Test-Path "/usr/share/stigs/orchestration_overlay") {
    $Script:OverlayRoot = "/usr/share/stigs/orchestration_overlay"
} else {
    $Script:OverlayRoot = (Resolve-Path "$PSScriptRoot/..").FullName
}

# Silence all PowerCLI warnings globally in parent context
$WarningPreference = 'SilentlyContinue'

# Load Dependencies and Workers dynamically from the Resolved Overlay Root
Import-Module powershell-yaml -Global -Force -ErrorAction Stop -DisableNameChecking -WarningAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/CredentialManagement.psm1") -Global -Force -ErrorAction Stop -DisableNameChecking -WarningAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/globalFunctions.psm1") -Global -Force -ErrorAction Stop -DisableNameChecking -WarningAction SilentlyContinue

Import-Module (Join-Path $Script:OverlayRoot "modules/vcsa/VcsaHelpers.psm1") -Global -Force -ErrorAction SilentlyContinue -DisableNameChecking -WarningAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/esxi/EsxiHelpers.psm1") -Global -Force -ErrorAction SilentlyContinue -DisableNameChecking -WarningAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/vm/VmHelpers.psm1") -Global -Force -ErrorAction SilentlyContinue -DisableNameChecking -WarningAction SilentlyContinue

Import-Module (Join-Path $Script:OverlayRoot "modules/vcsa/Invoke-VcsaAudit.psm1") -Global -Force -ErrorAction SilentlyContinue -DisableNameChecking -WarningAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/esxi/Invoke-EsxiAudit.psm1") -Global -Force -ErrorAction SilentlyContinue -DisableNameChecking -WarningAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/vm/Invoke-VmAudit.psm1") -Global -Force -ErrorAction SilentlyContinue -DisableNameChecking -WarningAction SilentlyContinue

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

    $WarningPreference = 'SilentlyContinue'
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

    Write-Host "[*] Starting Dynamic Inventory Discovery (Target Types: $($TargetType -join ', '))..." -ForegroundColor Cyan

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
        Write-Host "[*] Routing targets to execution workers..." -ForegroundColor Cyan
        
        # VCSA Phase
        if ($TargetManifest.vCenters) { 
            $TargetManifest.vCenters | Invoke-VcsaAudit -OverlayRoot $OverlayRoot | Format-StigChecklist -OverlayRoot $OverlayRoot 
        }

        # ESXi Phase (Staged in batches of 10)
        if ($TargetManifest.ESXiHosts) { 
            $TotalESXi = $TargetManifest.ESXiHosts.Count
            $BatchSize = 10 

            Write-Host "[*] Discovered $TotalESXi ESXi hosts. Processing in batches of $BatchSize..." -ForegroundColor Cyan
            
            for ($i = 0; $i -lt $TotalESXi; $i += $BatchSize) {
                $Batch = $TargetManifest.ESXiHosts | Select-Object -Skip $i -First $BatchSize
                $BatchNumber = [math]::Floor($i / $BatchSize) + 1
                $TotalBatches = [math]::Ceiling($TotalESXi / $BatchSize)
                
                Write-Host "`n[*] --- Processing ESXi Batch $BatchNumber of $TotalBatches ---" -ForegroundColor Yellow
                
                Invoke-EsxiAudit -TargetList $Batch -OverlayRoot $OverlayRoot | Format-StigChecklist -OverlayRoot $OverlayRoot
            }
        }

        # VM Phase (Staged in batches of 40)
        if ($TargetManifest.VMs) { 
            $TotalVMs  = $TargetManifest.VMs.Count
            $BatchSize = 40 

            Write-Host "[*] Discovered $TotalVMs VMs. Processing in batches of $BatchSize..." -ForegroundColor Cyan
            
            for ($i = 0; $i -lt $TotalVMs; $i += $BatchSize) {
                $Batch = $TargetManifest.VMs | Select-Object -Skip $i -First $BatchSize
                $BatchNumber = [math]::Floor($i / $BatchSize) + 1
                $TotalBatches = [math]::Ceiling($TotalVMs / $BatchSize)
                
                Write-Host "`n[*] --- Processing VM Batch $BatchNumber of $TotalBatches ---" -ForegroundColor Yellow
                
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
            Write-Host "[*] Initiating Parallel Formatting for $($ResultsQueue.Count) targets..." -ForegroundColor Cyan
        }

        $ResultsQueue | ForEach-Object -Parallel {
            $AuditResult   = $_
            $OverlayRoot   = $using:OverlayRoot
            $TemplateDir   = $using:Script:TemplateDir
            $GlobalMarking = $using:Script:GlobalMarking
            
            $GlobalFuncsPath = Join-Path $OverlayRoot "modules/globalFunctions.psm1"
            $GlobalFuncsText = Get-Content $GlobalFuncsPath -Raw
            $GlobalFuncsSafe = $GlobalFuncsText -replace "(?m)^Export-ModuleMember.*`$", ""
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
                "VM"   { "vm" }
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
                                $vulnNumNode = $sshVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Ver" }
                                if ($vulnNumNode) {
                                    $vulnNum = $vulnNumNode.SelectSingleNode("ATTRIBUTE_DATA").InnerText
                                    $xpath = "/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA/VULN_ATTRIBUTE='Rule_Ver' and STIG_DATA/ATTRIBUTE_DATA='$vulnNum']"
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
                        $customIdNode = $customVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Ver" }
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
                        $customIdNode = $customVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Ver" }
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
                    Write-Host " [+] Successfully formatted and saved: $FinalCkl" -ForegroundColor Green
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
    param([string]$OverlayRoot = $Script:OverlayRoot)
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

Export-ModuleMember -Function Get-StigInventory, Invoke-StigAudit, Format-StigChecklist, Invoke-MultiVcsaOrchestration, Invoke-MultiEsxiOrchestration, Invoke-MultiVmOrchestration