# =========================================================================
# MODULE: StigOrchestration.psm1
# DESCRIPTION: The Master Controller. Discovers inventory, routes to workers,
# and formats the final STIG checklists into the organized reporting tree.
# =========================================================================

# Define the root overlay path at the module scope
$Script:OverlayRoot = "/usr/share/stigs/orchestration_overlay"

# Load Dependencies and Workers dynamically from the Overlay Root
Import-Module powershell-yaml -Force -ErrorAction Stop # Ensure YAML parsing is available
Import-Module (Join-Path $Script:OverlayRoot "modules/CredentialManagement.psm1") -Force -ErrorAction Stop
Import-Module (Join-Path $Script:OverlayRoot "modules/globalFunctions.psm1") -Force -ErrorAction Stop
Import-Module (Join-Path $Script:OverlayRoot "modules/vcsa/Invoke-VcsaAudit.psm1") -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/esxi/Invoke-EsxiAudit.psm1") -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/vm/Invoke-VmAudit.psm1") -Force -ErrorAction SilentlyContinue

<#
.SYNOPSIS
    Discovers vCenter inventory and builds the target manifest.
.DESCRIPTION
    Reads credentials from the vault, establishes PowerCLI sessions, and compiles
    target objects containing necessary metadata, including reporting paths.
#>
function Get-StigInventory {
    [CmdletBinding()]
    param (
        [string]$OverlayRoot = $Script:OverlayRoot,
        [string]$VmExclusionRegex = "^vCLS|NSX|vCenter|Appliance.*"
    )

    $CredentialFile = Join-Path $OverlayRoot "conf/.creds.json.encrypted"
    $DateStr        = Get-Date -Format "yyyyMMdd"

    $credentials = Get-vCenterCredentialStore -FilePath $CredentialFile
    if (-not $credentials.vCenters) { Throw "No vCenters found in the credential vault." }

    $MasterTargetList = [PSCustomObject]@{
        vCenters  = @()
        ESXiHosts = @()
        VMs       = @()
    }

    Write-Host "[*] Starting Dynamic Inventory Discovery..." -ForegroundColor Cyan

    foreach ($entry in $credentials.vCenters) {
        $vCenterFQDN = $entry.FQDN
        # Extract shortname (e.g., HUAFINFVC from huafinfvc.domain.local)
        $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
        
        Write-Verbose "Querying $vCenterFQDN ($vCenterShortName)..."
        
        $credObj   = Get-vCenterCredential -FQDN $vCenterFQDN -FilePath $CredentialFile
        $adminUser = $credObj.AdminCred.UserName
        $adminPass = $credObj.AdminCred.GetNetworkCredential().Password
        $rootPass  = $credObj.RootCred.GetNetworkCredential().Password
        $esxiRoot  = $credObj.EsxiCred.GetNetworkCredential().Password

        # Define specific reporting folder paths
        $VcsaReportDir = Join-Path $OverlayRoot "reports/$vCenterShortName/$DateStr/VCSA"
        $EsxiReportDir = Join-Path $OverlayRoot "reports/$vCenterShortName/$DateStr/ESXi"
        $VmReportDir   = Join-Path $OverlayRoot "reports/$vCenterShortName/$DateStr/VMs"

        # Append VCSA Target
        $MasterTargetList.vCenters += [PSCustomObject]@{
            FQDN             = $vCenterFQDN
            AdminUser        = $adminUser
            AdminPass        = $adminPass
            RootPass         = $rootPass
            vCenterShortName = $vCenterShortName
            DateStr          = $DateStr
            ReportDir        = $VcsaReportDir
        }

        try {
            Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
            Connect-VIServer -Server $vCenterFQDN -User $adminUser -Password $adminPass -Force -ErrorAction Stop | Out-Null
            
            # Append ESXi Targets
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

            # Append VM Targets
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

            Disconnect-VIServer -Server $vCenterFQDN -Confirm:$false | Out-Null
        } catch {
            Write-Error "Failed to retrieve inventory from $vCenterFQDN: $($_.Exception.Message)"
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
        
        # Stream objects to their respective worker modules
        if ($TargetManifest.vCenters)  { $TargetManifest.vCenters  | Invoke-VcsaAudit -OverlayRoot $OverlayRoot }
        if ($TargetManifest.ESXiHosts) { $TargetManifest.ESXiHosts | Invoke-EsxiAudit -OverlayRoot $OverlayRoot }
        if ($TargetManifest.VMs)       { $TargetManifest.VMs       | Invoke-VmAudit   -OverlayRoot $OverlayRoot }
    }
}

<#
.SYNOPSIS
    Master formatting engine for all STIG Checklists.
.DESCRIPTION
    Converts raw JSON data to CKL, merges API/SSH data for ESXi, injects
    answers.xml from the conf/ directories, and outputs to the organized report tree.
#>
function Format-StigChecklist {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject]$AuditResult,
        
        [string]$OverlayRoot = $Script:OverlayRoot
    )

    begin {
        # Load Global Config to determine marking and template release version
        $GlobalConfPath = Join-Path $OverlayRoot "conf/global_config.yml"
        if (-not (Test-Path $GlobalConfPath)) { Throw "Global configuration not found at $GlobalConfPath" }
        $GlobalConf = Get-Content $GlobalConfPath -Raw | ConvertFrom-Yaml

        # Use the release version from global config to map the correct template directory
        $Script:TemplateDir = Join-Path $OverlayRoot "templates/CKL_Templates/$($GlobalConf.stig_release)"
        if (-not (Test-Path $Script:TemplateDir)) { Throw "Template directory not found: $($Script:TemplateDir)" }
        
        $Script:GlobalMarking = $GlobalConf.marking
    }

    process {
        $TargetName       = $AuditResult.TargetName
        $TargetType       = $AuditResult.TargetType
        $Component        = $AuditResult.DisaComponent
        $vCenterShortName = $AuditResult.vCenterShortName
        $DateStr          = $AuditResult.DateStr
        
        # Parse the shortname of the actual target (e.g. ESX01 from esx01.domain.mil)
        $TargetShortName  = ($TargetName -split '\.')[0].ToUpper()

        # Route output folder based on target type
        $FolderType = switch ($TargetType) {
            "VCSA" { "VCSA" }
            "ESXi" { "ESXi" }
            "VM"   { "VMs" }
        }
        $OutputCklDir = Join-Path $OverlayRoot "reports/$vCenterShortName/$DateStr/$FolderType"
        if (-not (Test-Path $OutputCklDir)) { New-Item -ItemType Directory -Path $OutputCklDir -Force | Out-Null }

        $AnswersXmlPath = Join-Path $OverlayRoot "conf/$($TargetType.ToLower())/answers.xml"

        Write-Host "[*] Formatting Checklist for: $TargetName ($Component)" -ForegroundColor Cyan

        # Dynamically find the Pure DISA Template
        $PureDisaTemplatePath = Get-DisaTemplate -TemplateDir $Script:TemplateDir -ComponentType $Component
        
        # Extract the pure template base name (e.g., "U_VMW_vSphere_8-0_ESXi_V2R4")
        $TemplateBaseName = [System.IO.Path]::GetFileNameWithoutExtension($PureDisaTemplatePath)

        # Build Final Naming Convention: <TargetShortName>_<TemplateName>_<Date>.ckl
        $FinalCkl = Join-Path $OutputCklDir "${TargetShortName}_${TemplateBaseName}_${DateStr}.ckl"
        $TempBase = "/tmp/${TargetShortName}_${Component}"

        # ==========================================
        # ESXi MERGE LOGIC (API + SSH)
        # ==========================================
        if ($TargetType -eq "ESXi") {
            $ApiTempCkl = "${TempBase}_API_temp.ckl"
            $SshTempCkl = "${TempBase}_SSH_temp.ckl"

            Invoke-Expression "& bash -c 'saf convert hdf2ckl -i $($AuditResult.ApiJsonFile) -o $ApiTempCkl'" | Out-Null
            Invoke-Expression "& bash -c 'saf convert hdf2ckl -i $($AuditResult.SshJsonFile) -o $SshTempCkl'" | Out-Null

            if ((Test-Path $ApiTempCkl) -and (Test-Path $SshTempCkl)) {
                Write-Verbose " -> Merging ESXi SSH results into API Checklist..."
                $ApiXml = New-Object System.Xml.XmlDocument
                $ApiXml.PreserveWhitespace = $true
                $ApiXml.Load($ApiTempCkl)

                $SshXml = New-Object System.Xml.XmlDocument
                $SshXml.Load($SshTempCkl)

                foreach ($sshVuln in $SshXml.CHECKLIST.STIGS.iSTIG.VULN) {
                    $vulnNumNode = $sshVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Vuln_Num" }
                    if ($vulnNumNode) {
                        $vulnNum = $vulnNumNode.SelectSingleNode("ATTRIBUTE_DATA").InnerText
                        $status  = $sshVuln.SelectSingleNode("STATUS").InnerText
                        $details = $sshVuln.SelectSingleNode("FINDING_DETAILS").InnerXml

                        $xpath = "/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA/VULN_ATTRIBUTE='Vuln_Num' and STIG_DATA/ATTRIBUTE_DATA='$vulnNum']"
                        $apiVulnNode = $ApiXml.SelectSingleNode($xpath)

                        if ($apiVulnNode) {
                            $apiVulnNode.SelectSingleNode("STATUS").InnerText = $status
                            $apiVulnNode.SelectSingleNode("FINDING_DETAILS").InnerXml = $details
                        }
                    }
                }
                $ApiXml.Save($ApiTempCkl)
                $MasterTempCkl = $ApiTempCkl
            } else {
                Write-Error "Failed to generate Temp CKLs for ESXi merging on $TargetName"
                return
            }
        }
        # ==========================================
        # VCSA / VM LOGIC (Single JSON)
        # ==========================================
        else {
            $MasterTempCkl = "${TempBase}_temp.ckl"
            Invoke-Expression "& bash -c 'saf convert hdf2ckl -i $($AuditResult.RawJsonFile) -o $MasterTempCkl'" | Out-Null
        }

        # ==========================================
        # TEMPLATE UPDATE & ANSWERS.XML INJECTION
        # ==========================================
        if (Test-Path $MasterTempCkl) {
            $UpdateJob = [PSCustomObject]@{
                profileName    = $TargetName
                tempCklFile    = $MasterTempCkl
                pureTemplate   = $PureDisaTemplatePath
                cklFile        = $FinalCkl
                MARKING        = $Script:GlobalMarking   # Injected from global_config.yml
                answerFilePath = $AnswersXmlPath
            }

            try {
                Update-CklTemplate -UpdateJobs @($UpdateJob) -UpdateType $TargetType
                Write-Host "[+] Successfully formatted and saved: $FinalCkl" -ForegroundColor Green
            } catch {
                Write-Error "Failed to apply final formatting for $TargetName : $($_.Exception.Message)"
            }

            # Cleanup Ephemeral Temp Files
            Remove-Item "${TempBase}*.ckl" -Force -ErrorAction SilentlyContinue
            
            # Clean up the Raw JSON files from the worker if configured to do so
            if ($AuditResult.RawJsonFile) { Remove-Item $AuditResult.RawJsonFile -Force -ErrorAction SilentlyContinue }
            if ($AuditResult.ApiJsonFile) { Remove-Item $AuditResult.ApiJsonFile -Force -ErrorAction SilentlyContinue }
            if ($AuditResult.SshJsonFile) { Remove-Item $AuditResult.SshJsonFile -Force -ErrorAction SilentlyContinue }

        } else {
            Write-Error "SAF CLI failed to generate Master Temp CKL for $TargetName"
        }
    }
}

Export-ModuleMember -Function Get-StigInventory, Invoke-StigAudit, Format-StigChecklist