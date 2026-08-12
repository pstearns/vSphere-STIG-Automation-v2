# =========================================================================
# MODULE: StigOrchestration.psm1
# DESCRIPTION: The Master Controller. Discovers inventory, routes to workers,
# and formats the final STIG checklists into the organized reporting tree.
# =========================================================================

# Define the root overlay path at the module scope safely
if (Test-Path "/usr/share/stigs/orchestration_overlay") {
    $Script:OverlayRoot = "/usr/share/stigs/orchestration_overlay"
} else {
    $Script:OverlayRoot = (Resolve-Path "$PSScriptRoot/..").Path
}

# Load Dependencies and Workers dynamically from the Overlay Root
Import-Module powershell-yaml -Global -Force -ErrorAction Stop 
Import-Module (Join-Path $Script:OverlayRoot "modules/CredentialManagement.psm1") -Global -Force -ErrorAction Stop
Import-Module (Join-Path $Script:OverlayRoot "modules/globalFunctions.psm1") -Global -Force -ErrorAction Stop
Import-Module (Join-Path $Script:OverlayRoot "modules/vcsa/VcsaHelpers.psm1") -Global -Force

# Worker modules do not strictly need -Global, but we will load them normally
Import-Module (Join-Path $Script:OverlayRoot "modules/vcsa/Invoke-VcsaAudit.psm1") -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/esxi/Invoke-EsxiAudit.psm1") -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $Script:OverlayRoot "modules/vm/Invoke-VmAudit.psm1") -Force -ErrorAction SilentlyContinue

<#
.SYNOPSIS
    Discovers vCenter inventory and builds the target manifest.
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
        $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
        
        Write-Verbose "Querying $vCenterFQDN ($vCenterShortName)..."
        
        $credObj   = Get-vCenterCredential -FQDN $vCenterFQDN -FilePath $CredentialFile
        $adminUser = $credObj.AdminCred.UserName
        $adminPass = $credObj.AdminCred.GetNetworkCredential().Password
        $rootPass  = $credObj.RootCred.GetNetworkCredential().Password
        $esxiRoot  = $credObj.EsxiCred.GetNetworkCredential().Password

        $VcsaReportDir = Join-Path $OverlayRoot "reports/$vCenterShortName/$DateStr/VCSA"
        $EsxiReportDir = Join-Path $OverlayRoot "reports/$vCenterShortName/$DateStr/ESXi"
        $VmReportDir   = Join-Path $OverlayRoot "reports/$vCenterShortName/$DateStr/VMs"

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
            Write-Error "Failed to retrieve inventory from ${$vCenterFQDN}: $($_.Exception.Message)"
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
        
        if ($TargetManifest.vCenters)  { $TargetManifest.vCenters  | Invoke-VcsaAudit -OverlayRoot $OverlayRoot }
        if ($TargetManifest.ESXiHosts) { $TargetManifest.ESXiHosts | Invoke-EsxiAudit -OverlayRoot $OverlayRoot }
        if ($TargetManifest.VMs)       { $TargetManifest.VMs       | Invoke-VmAudit   -OverlayRoot $OverlayRoot }
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
        $GlobalConfPath = Join-Path $OverlayRoot "conf/global_config.yml"
        if (-not (Test-Path $GlobalConfPath)) { Throw "Global configuration not found at $GlobalConfPath" }
        $GlobalConf = Get-Content $GlobalConfPath -Raw | ConvertFrom-Yaml

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
        
        $TargetShortName  = ($TargetName -split '\.')[0].ToUpper()

        $FolderType = switch ($TargetType) {
            "VCSA" { "VCSA" }
            "ESXi" { "ESXi" }
            "VM"   { "VMs" }
        }
        $OutputCklDir = Join-Path $OverlayRoot "reports/$vCenterShortName/$DateStr/$FolderType"
        if (-not (Test-Path $OutputCklDir)) { New-Item -ItemType Directory -Path $OutputCklDir -Force | Out-Null }

        $AnswersXmlPath = Join-Path $OverlayRoot "conf/$($TargetType.ToLower())/answers.xml"

        Write-Host "[*] Formatting Checklist for: $TargetName ($Component)" -ForegroundColor Cyan

        $PureDisaTemplatePath = Get-DisaTemplate -TemplateDir $Script:TemplateDir -ComponentType $Component
        $TemplateBaseName = [System.IO.Path]::GetFileNameWithoutExtension($PureDisaTemplatePath)

        $FinalCkl = Join-Path $OutputCklDir "${TargetShortName}_${TemplateBaseName}_${DateStr}.ckl"
        $TempBase = "/tmp/${TargetShortName}_${Component}"

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
        else {
            $MasterTempCkl = "${TempBase}_temp.ckl"
            Invoke-Expression "& bash -c 'saf convert hdf2ckl -i $($AuditResult.RawJsonFile) -o $MasterTempCkl'" | Out-Null
        }

        if (Test-Path $MasterTempCkl) {
            $UpdateJob = [PSCustomObject]@{
                profileName      = $TargetName
                tempCklFile      = $MasterTempCkl
                pureTemplate     = $PureDisaTemplatePath
                cklFile          = $FinalCkl
                MARKING          = $Script:GlobalMarking   
                answerFilePath   = $AnswersXmlPath
                
                # VCSA ASSET DATA
                vCenterShortName = $AuditResult.vCenterShortName
                TargetName       = $AuditResult.TargetName
                IPAddress        = $AuditResult.IPAddress
                MACAddress       = $AuditResult.MACAddress
                
                # ESXi ASSET DATE
                ESXiName         = $AuditResult.TargetName
                ESXiFQDN         = $AuditResult.TargetName
                ESXi_IP          = $AuditResult.IPAddress
                ESXi_MAC         = $AuditResult.MACAddress
            }

            try {
                Update-CklTemplate -UpdateJobs @($UpdateJob) -UpdateType $TargetType
                Write-Host "[+] Successfully formatted and saved: $FinalCkl" -ForegroundColor Green

                if ($AuditResult.RawJsonFile -and (Test-Path $AuditResult.RawJsonFile)) {
                    $DestJson = Join-Path $OutputCklDir (Split-Path $AuditResult.RawJsonFile -Leaf)
                    Move-Item $AuditResult.RawJsonFile $DestJson -Force
                    Write-Host "[+] Saved Raw JSON to: $DestJson" -ForegroundColor DarkGray
                }
            } catch {
                Write-Error "Failed to apply final formatting for $TargetName : $($_.Exception.Message)"
            }

            # --- Cleanup Ephemeral Temp and Raw JSON Files ---
            $FilesToRemove = @( (Get-ChildItem "${TempBase}*.ckl" -ErrorAction SilentlyContinue).FullName )
            
            if ($AuditResult.RawJsonFile) { $FilesToRemove += $AuditResult.RawJsonFile }
            if ($AuditResult.ApiJsonFile) { $FilesToRemove += $AuditResult.ApiJsonFile }
            if ($AuditResult.SshJsonFile) { $FilesToRemove += $AuditResult.SshJsonFile }

            foreach ($file in $FilesToRemove) {
                if ($file -and (Test-Path $file)) {
                    try { Remove-Item $file -Force -ErrorAction Stop } 
                    catch { Write-StigLog -Message "Cleanup Warning: Failed to remove file $file" -Severity WARN -Source "Formatter" }
                }
            }

        } else {
            Write-Error "SAF CLI failed to generate Master Temp CKL for $TargetName"
        }
    }
}

Export-ModuleMember -Function Get-StigInventory, Invoke-StigAudit, Format-StigChecklist