# =========================================================================
# MODULE: StigOrchestration.psm1
# DESCRIPTION: The Master Controller. Discovers inventory, routes to workers,
# and formats the final STIG checklists into the organized reporting tree.
# =========================================================================

if (Test-Path "/usr/share/stigs/orchestration_overlay") {
    $Script:OverlayRoot = "/usr/share/stigs/orchestration_overlay"
} else {
    $Script:OverlayRoot = (Resolve-Path "$PSScriptRoot/..").Path
}

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
.DESCRIPTION
    Dynamically builds the execution manifest based on targets enabled in global_config.yml.
    Cross-references FQDNs with the secure AES-256 encrypted credential store.
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
            # Safely handle hashtable and object deserialization styles
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

    # 4. Only process targets that are enabled in plain-text config and exist in vault
    foreach ($vCenterFQDN in $ActiveFqdns) {
        $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
        
        # Verify that secure credentials exist for the enabled target
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
                Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
                Connect-VIServer -Server $vCenterFQDN -User $adminUser -Password $adminPass -Force -ErrorAction Stop | Out-Null
                
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

                Disconnect-VIServer -Server $vCenterFQDN -Confirm:$false | Out-Null
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
.DESCRIPTION
    Applies batch chunking to ESXi and VM arrays to optimize formatting performance 
    and mitigate vCenter API throttling.
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
        
        # VCSA runs sequentially but manages internal parallel services natively
        if ($TargetManifest.vCenters) { 
            $TargetManifest.vCenters | Invoke-VcsaAudit -OverlayRoot $OverlayRoot | Format-StigChecklist -OverlayRoot $OverlayRoot 
        }

        # ESXi processing in optimal batches
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

        # VM processing in optimal batches
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
.DESCRIPTION
    Collects audit results and formats them in parallel to eliminate 
    the Node.js 'saf convert' execution bottleneck.
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
        # Ignore empty/null pipeline objects caused by partial test manifests
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
            
            # Extract safe global functions to execute Update-CklTemplate in the isolated runspace
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

            # =========================================================================
            # UNIVERSAL CUSTOM OVERLAY ENGINE (Applies to ESXi, VCSA, and VMs)
            # =========================================================================
            
            # --- Overlay Custom API Findings ---
            if ($AuditResult.CustomApiJsonFile -and (Test-Path $AuditResult.CustomApiJsonFile)) {
                Write-StigLog -Message "Converting Custom API JSON to Temp CKL for $TargetName" -Severity INFO -Source "Formatter"
                $CustomApiTempCkl = "${TempBase}_CUSTOM_API_temp.ckl"
                bash -c "saf convert hdf2ckl -i '$($AuditResult.CustomApiJsonFile)' -o '$CustomApiTempCkl'" | Out-Null
                
                if ((Test-Path $CustomApiTempCkl) -and $MasterTempCkl) {
                    Write-StigLog -Message "Merging Custom API findings into Master CKL for $TargetName..." -Severity INFO -Source "Formatter"
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
                                Write-StigLog -Message " -> Overwrote baseline for $customId with Custom API result" -Severity DEBUG -Source "Formatter"
                                $apiMergeCount++
                            }
                        }
                    }
                    $MasterXml.Save($MasterTempCkl)
                    if ($apiMergeCount -gt 0) { Write-StigLog -Message "Successfully merged $apiMergeCount Custom API findings for $TargetName" -Severity SUCCESS -Source "Formatter" }
                }
            }

            # --- Overlay Custom SSH Findings ---
            if ($AuditResult.CustomSshJsonFile -and (Test-Path $AuditResult.CustomSshJsonFile)) {
                Write-StigLog -Message "Converting Custom SSH JSON to Temp CKL for $TargetName" -Severity INFO -Source "Formatter"
                $CustomSshTempCkl = "${TempBase}_CUSTOM_SSH_temp.ckl"
                bash -c "saf convert hdf2ckl -i '$($AuditResult.CustomSshJsonFile)' -o '$CustomSshTempCkl'" | Out-Null
                
                if ((Test-Path $CustomSshTempCkl) -and $MasterTempCkl) {
                    Write-StigLog -Message "Merging Custom SSH findings into Master CKL for $TargetName..." -Severity INFO -Source "Formatter"
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
                                Write-StigLog -Message " -> Overwrote baseline for $customId with Custom SSH result" -Severity DEBUG -Source "Formatter"
                                $sshMergeCount++
                            }
                        }
                    }
                    $MasterXml.Save($MasterTempCkl)
                    if ($sshMergeCount -gt 0) { Write-StigLog -Message "Successfully merged $sshMergeCount Custom SSH findings for $TargetName" -Severity SUCCESS -Source "Formatter" }
                }
            }
            # =========================================================================

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
            } else {
                Write-StigLog -Message "SAF CLI failed to generate Master Temp CKL for $TargetName" -Severity ERROR -Source "Formatter"
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
    Executes sequenced multi-vCenter scans and structures silent logging.
#>
function Invoke-MultiVCenterOrchestration {
    [CmdletBinding()]
    param (
        [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay",
        [switch]$Silent
    )

    $StartTime = Get-Date
    $LogDir = Join-Path $OverlayRoot "logs"
    Initialize-StigLogging -LogDirectory $LogDir -Silent:$Silent

    Write-StigLog -Message "Starting Multi-vCenter Sequenced STIG Auditing..." -Severity INFO -Source "MultiOrch"

    try {
        # 1. Connect once per vCenter to retrieve and build the master cross-vCenter inventory (Highly Optimized)
        Write-StigLog -Message "Phase 1: Discovering cross-vCenter assets..." -Severity INFO -Source "MultiOrch"
        $MasterInventory = Get-StigInventory -OverlayRoot $OverlayRoot -TargetType 'All'

        # 2. Iterate through each vCenter one by one for localized, section-based execution
        $CredentialFile = Join-Path $OverlayRoot "conf/.creds.json.encrypted"
        $credentials = Get-vCenterCredentialStore -FilePath $CredentialFile
        
        foreach ($vCenterEntry in $credentials.vCenters) {
            $vCenterFQDN = $vCenterEntry.FQDN
            $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
            $DateStr = Get-Date -Format "yyyyMMdd"

            Write-StigLog -Message "=========================================================" -Severity INFO -Source "MultiOrch"
            Write-StigLog -Message "Processing Orchestration Cycle for vCenter: $vCenterFQDN" -Severity INFO -Source "MultiOrch"
            Write-StigLog -Message "=========================================================" -Severity INFO -Source "MultiOrch"

            # =========================================================
            # SECTION 1: VCSA SCAN, CHECKLIST GENERATION, & SUMMARY
            # =========================================================
            $VcsaTargets = $MasterInventory.vCenters | Where-Object { $_.FQDN -eq $vCenterFQDN }
            if ($VcsaTargets) {
                Write-StigLog -Message "[$vCenterShortName] SECTION 1: Initiating VCSA Scan..." -Severity INFO -Source "MultiOrch"
                $VcsaManifest = [PSCustomObject]@{ vCenters = @($VcsaTargets); ESXiHosts = $null; VMs = $null }
                
                # Executes VCSA Scan and immediately pipelines to Format-StigChecklist
                Invoke-StigAudit -TargetManifest $VcsaManifest -OverlayRoot $OverlayRoot
                
                # Immediate Section-Based Summary for VCSA
                $VcsaReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/VCSA"
                Write-StigLog -Message "[$vCenterShortName] VCSA Scan Complete. Compiling section-based summary..." -Severity INFO -Source "MultiOrch"
                Get-StigScanSummary -ReportDir $VcsaReportPath
            }

            # =========================================================
            # SECTION 2: ESXI SCAN, CHECKLIST GENERATION, & SUMMARY
            # =========================================================
            $EsxiTargets = $MasterInventory.ESXiHosts | Where-Object { $_.vCenter -eq $vCenterFQDN }
            if ($EsxiTargets -and $EsxiTargets.Count -gt 0) {
                Write-StigLog -Message "[$vCenterShortName] SECTION 2: Initiating ESXi Scan..." -Severity INFO -Source "MultiOrch"
                $EsxiManifest = [PSCustomObject]@{ vCenters = $null; ESXiHosts = $EsxiTargets; VMs = $null }
                
                # Executes ESXi Scan (in batches) and immediately pipelines to Format-StigChecklist
                Invoke-StigAudit -TargetManifest $EsxiManifest -OverlayRoot $OverlayRoot
                
                # Immediate Section-Based Summary for ESXi
                $EsxiReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/ESXi"
                Write-StigLog -Message "[$vCenterShortName] ESXi Scan Complete. Compiling section-based summary..." -Severity INFO -Source "MultiOrch"
                Get-StigScanSummary -ReportDir $EsxiReportPath
            }

            # =========================================================
            # SECTION 3: VM SCAN, CHECKLIST GENERATION, & SUMMARY
            # =========================================================
            $VmTargets = $MasterInventory.VMs | Where-Object { $_.vCenter -eq $vCenterFQDN }
            if ($VmTargets -and $VmTargets.Count -gt 0) {
                Write-StigLog -Message "[$vCenterShortName] SECTION 3: Initiating VM Scan (Long Running)..." -Severity INFO -Source "MultiOrch"
                $VmManifest = [PSCustomObject]@{ vCenters = $null; ESXiHosts = $null; VMs = $VmTargets }
                
                # Executes VM Scan (in batches) and immediately pipelines to Format-StigChecklist
                Invoke-StigAudit -TargetManifest $VmManifest -OverlayRoot $OverlayRoot
                
                # Immediate Section-Based Summary for VMs
                $VmReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/VMs"
                Write-StigLog -Message "[$vCenterShortName] VM Scan Complete. Compiling section-based summary..." -Severity INFO -Source "MultiOrch"
                Get-StigScanSummary -ReportDir $VmReportPath
            }
        }

        Write-ElapsedTime -StartTime $StartTime -Message "Multi-vCenter sequenced scanning cycle completed successfully." -Source "MultiOrch"
    }
    catch {
        Write-StigLog -Message "Critical error halted the multi-vCenter orchestration pipeline: $($_.Exception.Message)" -Severity ERROR -Source "MultiOrch"
    }
}

Export-ModuleMember -Function Get-StigInventory, Invoke-StigAudit, Format-StigChecklist, Invoke-MultiVCenterOrchestration