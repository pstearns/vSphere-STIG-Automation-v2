# =========================================================================
# MODULE: globalFunctions.psm1
# DESCRIPTION: Core utility library containing only the universally required 
# functions for enterprise logging, XML manipulation, and STIG formatting.
# =========================================================================

# =========================================================================
# REGION: Enterprise Structured Logging
# =========================================================================

<#
.SYNOPSIS
    Initializes dual-channel logging (Structured App Log + Raw Transcript).
#>
function Initialize-StigLogging {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$LogDirectory,
        [switch]$Silent
    )
    
    if (-not (Test-Path $LogDirectory)) { 
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null 
    }
    
    $global:StigSilentMode = $Silent.IsPresent
    $global:StigAppLog     = Join-Path $LogDirectory "StigOrchestrator_$((Get-Date).ToString('yyyyMMdd')).log"
    $TranscriptPath        = Join-Path $LogDirectory "Session_Transcript_$((Get-Date).ToString('yyyyMMdd_HHmmss')).txt"
    
    Start-Transcript -Path $TranscriptPath -Append -Force | Out-Null
    Write-StigLog -Message "Pipeline Logging Initialized. Silent Mode: $($global:StigSilentMode)" -Severity INFO -Source "System"
}

<#
.SYNOPSIS
    Writes structured, fixed-width log entries to file and console.
#>
function Write-StigLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR', 'DEBUG')][string]$Severity = 'INFO',
        [string]$Source = 'Orchestrator'
    )
    
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogEntry  = "[$Timestamp] [$($Severity.PadRight(7))] [$($Source.PadRight(15))] $Message"

    if ($global:StigAppLog) { Add-Content -Path $global:StigAppLog -Value $LogEntry }

    if (-not $global:StigSilentMode) {
        switch ($Severity) {
            'INFO'    { Write-Host $LogEntry -ForegroundColor Cyan }
            'SUCCESS' { Write-Host $LogEntry -ForegroundColor Green }
            'WARN'    { Write-Host $LogEntry -ForegroundColor Yellow }
            'ERROR'   { Write-Host $LogEntry -ForegroundColor Red }
            'DEBUG'   { Write-Host $LogEntry -ForegroundColor DarkGray }
        }
    }
}

<#
.SYNOPSIS
    Calculates execution duration and routes it to the structured logger.
#>
function Write-ElapsedTime {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][datetime]$StartTime,
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Source = 'Orchestrator'
    )
    
    $elapsed = (Get-Date) - $StartTime
    $minutes = [math]::Floor($elapsed.TotalMinutes)
    $seconds = [math]::Floor($elapsed.TotalSeconds % 60)
    
    $FormattedMessage = "$Message (Duration: {0:N0}m {1:N0}s)" -f $minutes, $seconds
    Write-StigLog -Message $FormattedMessage -Severity SUCCESS -Source $Source
}

# =========================================================================
# REGION: STIG Template & XML Utilities
# =========================================================================

<#
.SYNOPSIS
    Dynamically resolves Pure DISA CKL templates by component.
#>
function Get-DisaTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$TemplateDir,
        [Parameter(Mandatory=$true)][string]$ComponentType
    )
    
    Write-StigLog -Message "Searching for $ComponentType template in $TemplateDir" -Severity DEBUG -Source "TemplateResolver"

    $RegexPattern    = "_${ComponentType}_"
    $AllTemplates    = Get-ChildItem -Path $TemplateDir -Recurse -Filter "*.ckl"
    $MatchedTemplate = $AllTemplates | Where-Object { $_.Name -match $RegexPattern } | Sort-Object Name -Descending | Select-Object -First 1

    if (-not $MatchedTemplate) { 
        Throw "Failed to locate a Pure DISA .ckl template matching '$RegexPattern' in $TemplateDir" 
    }
    
    Write-StigLog -Message "Dynamically selected template: $($MatchedTemplate.Name)" -Severity INFO -Source "TemplateResolver"
    return $MatchedTemplate.FullName
}

<#
.SYNOPSIS
    Parses answers.xml to inject statuses, justifications, and waivers.
    Includes guard clauses for empty XML files.
#>
function Get-FormattedAnswer {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][string]$AnswerFile,
        [Parameter(Mandatory=$true)][string]$vulnRuleVer,
        [Parameter(Mandatory=$false)][string]$AnswerKey = "DEFAULT",
        [Parameter(Mandatory=$false)][string]$FindingDetailsText,
        [Parameter(Mandatory=$false)][string]$CurrentStatus
    )
    
    $result = @{ Comments = ""; Status = "" }
    
    try {
        if (-not $script:AnswerXmlCache) { $script:AnswerXmlCache = @{} }

        if ($script:AnswerXmlCache.ContainsKey($AnswerFile)) {
            $answerXmlData = $script:AnswerXmlCache[$AnswerFile]
        } else {
            $rawContent = Get-Content -Path $AnswerFile -Raw
            
            if ([string]::IsNullOrWhiteSpace($rawContent)) {
                $script:AnswerXmlCache[$AnswerFile] = $null
                return $null
            }

            [xml]$answerXmlData = [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::UTF8.GetBytes($rawContent))
            $script:AnswerXmlCache[$AnswerFile] = $answerXmlData
        }

        $answerXmlData = $script:AnswerXmlCache[$AnswerFile]
        if ($null -eq $answerXmlData) { return $null }

        $answerEntry = $answerXmlData.SelectSingleNode("//STIG[@ID='$vulnRuleVer']")
        if (-not $answerEntry) { return $null }

        $answerObj       = $answerEntry.AnswerKey
        $validAnswerKeys = $answerObj.Name -split "\s+"
        
        if (-not ($AnswerKey -in $validAnswerKeys -or $answerObj.Name -eq "DEFAULT")) { return $null }

        $expectedStatus = $answerObj.ExpectedStatus.Trim()
        
        if ($expectedStatus -ne $CurrentStatus) {
            $result.Status = $CurrentStatus
            return $result
        }

        $reviewMeta       = ""
        $reviewedDateNode = $answerObj.SelectSingleNode("Reviewed")
        $frequencyNode    = $answerObj.SelectSingleNode("Frequency")

        if ($reviewedDateNode -and $frequencyNode -and $reviewedDateNode.InnerText -and $frequencyNode.InnerText) {
            $reviewedDate = [datetime]::Parse($reviewedDateNode.InnerText)
            $frequencyStr = $frequencyNode.InnerText
            
            $frequencyThreshold = switch -regex ($frequencyStr) {
                "^(\d+)d$" { (Get-Date).AddDays(-[int]$matches[1]) }
                "^(\d+)m$" { (Get-Date).AddMonths(-[int]$matches[1]) }
                "^(\d+)y$" { (Get-Date).AddYears(-[int]$matches[1]) }
            }
            
            $reviewStatus = if ($reviewedDate -gt $frequencyThreshold) { "Passed" } else { "Expired - Manual checks need reviewed." }
            $reviewMeta   = "`r`n`r`nReviewed: $($reviewedDate.ToString('yyyy-MM-dd'))`r`nFrequency: $frequencyStr`r`nStatus: $reviewStatus"
        }

        $validTrueComment  = if ($answerObj.ValidTrueComment)  { $answerObj.ValidTrueComment.InnerXml.Trim() }  else { "" }
        $validFalseComment = if ($answerObj.ValidFalseComment) { $answerObj.ValidFalseComment.InnerXml.Trim() } else { "" }

        $combinedText   = "$FindingDetailsText $CurrentStatus"
        $validationCode = $answerObj.ValidationCode.Trim()
        $isValid        = $true
        $valDetails     = ""

        if ($validationCode) {
            $escapedValidationCode = [regex]::Escape($validationCode)
            if ($combinedText -match $escapedValidationCode) {
                $valDetails = "`r`n[Validation Code Results]: String '$validationCode' found."
            } else {
                $isValid    = $false
                $valDetails = "`r`n[Validation Code Results]: String '$validationCode' NOT found."
            }
        }

        $newStatus = if ($validationCode -and -not $isValid) {
            if ($answerObj.ValidFalseStatus.Trim()) { $answerObj.ValidFalseStatus.Trim() } else { $CurrentStatus }
        } else {
            if ($answerObj.ValidTrueStatus.Trim()) { $answerObj.ValidTrueStatus.Trim() } else { $expectedStatus }
        }

        $commentBody = if ($validationCode -and -not $isValid) { 
            "`r`n[ValidFalseComment]:`r`n$validFalseComment$valDetails" 
        } else { 
            "`r`n[ValidTrueComment]:`r`n$validTrueComment" 
        }

        $commentBody += $reviewMeta
        
        if ($reviewMeta -match "Expired") { $newStatus = "Not_Reviewed" }

        $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $preComment = "INSPEC Answer file for Key '$AnswerKey' is providing the below comment on $($timestamp):`r`n"
        
        if ($newStatus -ne $CurrentStatus) {
            $preComment = "INSPEC Answer file for Key '$AnswerKey' is changing Status from '$CurrentStatus' to '$newStatus' on $($timestamp):`r`n"
        }

        $finalComment = $preComment + $commentBody
        
        if (($finalComment | Measure-Object -Character).Characters -gt 32667) {
            $finalComment = $finalComment.Substring(0, [System.Math]::Min(32617, $finalComment.Length)) + "`r`n---truncated: exceeded character limit---"
        }

        $result.Comments = $finalComment
        $result.Status   = $newStatus
    } catch { 
        Write-StigLog -Message "Failed to process answers.xml for $vulnRuleVer. Error: $($_.Exception.Message)" -Severity ERROR -Source "XMLParser"
        return $null 
    }

    return $result
}

<#
.SYNOPSIS
    Appends execution context to the Finding Details field.
#>
function Format-FindingDetail {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][string]$Status,
        [Parameter(Mandatory=$false)][string]$FindingDetails,
        [Parameter(Mandatory=$true)][string]$ModuleName
    )
    
    $currentDate = Get-Date -Format "MM/dd/yyyy"
    
    switch ($Status) {
        "Open"           { $header = "Inspec Profile: $ModuleName found this to be OPEN on $($currentDate):`r`n---------------------------------------------------------------`r`n`r`n" }
        "NotAFinding"    { $header = "Inspec Profile: $ModuleName found this to be NOT A FINDING on $($currentDate):`r`n------------------------------------------------------------------------`r`n`r`n" }
        "Not_Applicable" { $header = "Inspec Profile: $ModuleName found this to be NOT APPLICABLE on $($currentDate):`r`n-------------------------------------------------------------`r`n`r`n" }
        Default          { $header = "Inspec Profile: $ModuleName was unable to determine a Status on $($currentDate):`r`n-------------------------------------------------------------`r`n`r`n" }
    }
    
    if ($FindingDetails) { $header += $FindingDetails }
    return @{ FindingDetails = $header }
}

<#
.SYNOPSIS
    Merges SAF-converted XML data into a pristine DISA template.
.DESCRIPTION
    Safely extracts status, comments, and finding details from a temporary SAF-generated
    CKL file and injects them into a pristine DISA CKL template. Ensures strict mapping 
    of asset properties based on the TargetType (VCSA, ESXi, VM).
#>
function Update-CklTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][array]$UpdateJobs,
        [string]$UpdateType
    )
    
    foreach ($Job in $UpdateJobs) {
        $ProfileName  = $Job.profileName
        $TempCklPath  = $Job.tempCklFile
        $FinalCklPath = $Job.cklFile
        $PureTemplate = $Job.pureTemplate
        
        # 1. Safely Load XML Documents
        try {
            $templateXml = New-Object System.Xml.XmlDocument
            $templateXml.PreserveWhitespace = $true
            $templateXml.Load($PureTemplate)
            
            $workingXml = New-Object System.Xml.XmlDocument
            $workingXml.PreserveWhitespace = $true
            $workingXml.Load($TempCklPath)
        }
        catch {
            Write-StigLog -Message "Failed to load XML files for $ProfileName. Error: $($_.Exception.Message)" -Severity ERROR -Source "Formatter"
            continue 
        }

        # 2. Extract STIG ID or Fallback to Profile Name
        $stigidNode  = $templateXml.SelectSingleNode("//SI_DATA[SID_NAME='stigid']/SID_DATA")
        $stigidValue = if ($null -ne $stigidNode) { $stigidNode.InnerText } else { $ProfileName }
        
        # 3. Overlay Asset Identifiers
        $templateXml.CHECKLIST.ASSET.ROLE            = "Member Server"
        $templateXml.CHECKLIST.ASSET.MARKING         = $Job.MARKING
        $templateXml.CHECKLIST.ASSET.ASSET_TYPE      = "Computing"
        $templateXml.CHECKLIST.ASSET.WEB_OR_DATABASE = "false"
        
        # Dynamically assign host properties based on the target type
        if ($UpdateType -eq "ESXi") {
            $templateXml.CHECKLIST.ASSET.HOST_NAME = $Job.ESXiName
            $templateXml.CHECKLIST.ASSET.HOST_IP   = $Job.ESXi_IP
            $templateXml.CHECKLIST.ASSET.HOST_MAC  = $Job.ESXi_MAC
            $templateXml.CHECKLIST.ASSET.HOST_FQDN = $Job.ESXiFQDN
        } 
        elseif ($UpdateType -eq "VM") {
            $templateXml.CHECKLIST.ASSET.HOST_NAME = $Job.TargetName.ToUpper()
            $templateXml.CHECKLIST.ASSET.HOST_IP   = $Job.IPAddress
            $templateXml.CHECKLIST.ASSET.HOST_MAC  = $Job.MACAddress
            $templateXml.CHECKLIST.ASSET.HOST_FQDN = if ($Job.DNSName) { $Job.DNSName } else { $Job.TargetName }
        }
        else {
            # Defaults to VCSA/vCenter properties
            $templateXml.CHECKLIST.ASSET.HOST_NAME = $Job.vCenterShortName
            $templateXml.CHECKLIST.ASSET.HOST_IP   = $Job.IPAddress
            $templateXml.CHECKLIST.ASSET.HOST_MAC  = $Job.MACAddress
            $templateXml.CHECKLIST.ASSET.HOST_FQDN = $Job.TargetName
        }

        # 4. Iterate Vulnerabilities with Strict Null-Checking
        try {
            foreach ($vuln in $workingXml.CHECKLIST.STIGS.iSTIG.VULN) {
                $stigs        = $vuln.SelectNodes("STIG_DATA")
                $vulnRuleNode = $stigs | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Ver" }
                
                if ($null -eq $vulnRuleNode) { continue }
                
                $vulnRuleVer  = $vulnRuleNode.SelectSingleNode("ATTRIBUTE_DATA").InnerText
                $vulnSTATUS   = $vuln.SelectSingleNode("STATUS").InnerText
                $vulnFindDet  = $vuln.SelectSingleNode("FINDING_DETAILS").InnerXml
                $vulnCOMMENTS = $vuln.SelectSingleNode("COMMENTS").InnerXml

                if (Test-Path $Job.answerFilePath) {
                    $answerData = Get-FormattedAnswer -AnswerFile $Job.answerFilePath -vulnRuleVer $vulnRuleVer -CurrentStatus $vulnSTATUS -FindingDetailsText $vulnFindDet -AnswerKey "DEFAULT"
                    
                    if ($null -ne $answerData -and $answerData.Status -ne "") {
                        $vulnSTATUS   = $answerData.Status
                        $vulnCOMMENTS = $answerData.Comments
                    }
                }

                $formattedAnswer = Format-FindingDetail -Status $vulnSTATUS -FindingDetails $vulnFindDet -ModuleName $stigidValue

                $xpath = "/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA/VULN_ATTRIBUTE = 'Rule_Ver' and STIG_DATA/ATTRIBUTE_DATA = '$vulnRuleVer']"
                $templateVulnNode = $templateXml.SelectSingleNode($xpath)

                if ($null -ne $templateVulnNode) {
                    $templateVulnNode.SelectSingleNode("STATUS").InnerText          = $vulnSTATUS
                    $templateVulnNode.SelectSingleNode("FINDING_DETAILS").InnerXml  = $formattedAnswer.FindingDetails
                    $templateVulnNode.SelectSingleNode("COMMENTS").InnerXml         = $vulnCOMMENTS
                }
                else {
                    Write-StigLog -Message "No matching template vulnerability found for ID: $vulnRuleVer" -Severity WARN -Source "Formatter"
                }
            }
        }
        catch { 
            Write-StigLog -Message "Vulnerability merge failed for $ProfileName. Error: $($_.Exception.Message)" -Severity ERROR -Source "Formatter" 
        }

        # 5. Save Output with Strict UTF-8 Encoding compliance
        try {
            $templateXml.Save($FinalCklPath)
            [System.IO.File]::WriteAllText($FinalCklPath, $templateXml.OuterXml, [System.Text.Encoding]::UTF8)
        }
        catch { 
            Write-StigLog -Message "Failed to save CKL for $ProfileName. Error: $($_.Exception.Message)" -Severity ERROR -Source "Formatter" 
        }
    }
}

<#
.SYNOPSIS
    High-performance enterprise scanner compiling scan summaries from CKL files.
    Optimized with native .NET collections and direct XML stream loading.
#>
function Get-StigScanSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$ReportDir,
        [Parameter(Mandatory=$false)][string]$AnswersXmlPath,
        [Parameter(Mandatory=$false)][string]$CsvPath
    )

    Write-StigLog -Message "Compiling section-based scan summary for: $ReportDir" -Severity INFO -Source "SummaryEngine"

    if (-not (Test-Path $ReportDir)) {
        Write-StigLog -Message "Report directory not found: $ReportDir" -Severity WARN -Source "SummaryEngine"
        return
    }

    $CklFiles = Get-ChildItem -Path $ReportDir -Filter "*.ckl" -Recurse
    if ($CklFiles.Count -eq 0) {
        Write-StigLog -Message "No CKL checklist files found in $ReportDir" -Severity INFO -Source "SummaryEngine"
        return
    }

    # Optimization 1: Use .NET HashSet for high-speed O(1) lookups of answers.xml Rule_Vers
    $KnownRuleSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    
    if ($AnswersXmlPath -and (Test-Path $AnswersXmlPath)) {
        try {
            $AnswersXml = New-Object System.Xml.XmlDocument
            $AnswersXml.Load($AnswersXmlPath) # Direct .NET file-stream loading
            $StigNodes = $AnswersXml.SelectNodes("/Answers/STIG") # Direct XPath lookup
            
            if ($null -eq $StigNodes -or $StigNodes.Count -eq 0) {
                # Fallback to root search if answers file schema doesn't use standard root
                $StigNodes = $AnswersXml.SelectNodes("//STIG")
            }

            foreach ($Node in $StigNodes) {
                if ($Node.ID) { [void]$KnownRuleSet.Add($Node.ID) }
            }
            Write-StigLog -Message "Loaded $($KnownRuleSet.Count) known rules from answers.xml into fast lookup memory." -Severity INFO -Source "SummaryEngine"
        }
        catch {
            Write-StigLog -Message "Failed to parse answers.xml: $($_.Exception.Message)" -Severity WARN -Source "SummaryEngine"
        }
    }

    # Optimization 2: Use Generic List to avoid memory fragmentation from array resizing ($arr += $item)
    $OpenSummaryList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ScanDate = (Get-Date -Format "dd-MMM-yyyy HH:mm")

    # 3. Parse CKL checklists using direct .NET XML Load and Absolute XPath queries
    foreach ($File in $CklFiles) {
        try {
            $CklXml = New-Object System.Xml.XmlDocument
            $CklXml.PreserveWhitespace = $true
            $CklXml.Load($File.FullName)

            $AssetNode = $CklXml.SelectSingleNode("/CHECKLIST/ASSET")
            $HostName  = $AssetNode.SelectSingleNode("HOST_NAME").InnerText
            $HostIP    = $AssetNode.SelectSingleNode("HOST_IP").InnerText
            $HostFQDN  = $AssetNode.SelectSingleNode("HOST_FQDN").InnerText
            $AssetType = $AssetNode.SelectSingleNode("ROLE").InnerText

            # Optimization 3: Precise absolute XPath instead of recursive (//) traversal
            $OpenVulns = $CklXml.SelectNodes("/CHECKLIST/STIGS/iSTIG/VULN[STATUS='Open']")
            
            foreach ($v in $OpenVulns) {
                $StigData = $v.SelectNodes("STIG_DATA")
                $RuleID = ($StigData | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Vuln_Num" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText
                $RuleVer = ($StigData | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Ver" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText
                $Severity = ($StigData | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Severity" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText
                $Title = ($StigData | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Title" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText

                $CatLabel = switch ($Severity) {
                    "high"   { "CAT I" }
                    "medium" { "CAT II" }
                    "low"    { "CAT III" }
                    default  { "UNKNOWN" }
                }

                # High-speed HashSet check
                $Known = if ($KnownRuleSet.Contains($RuleVer)) { "True" } else { "False" }

                $OpenSummaryList.Add([PSCustomObject]@{
                    Date       = $ScanDate
                    Host       = if ($HostFQDN) { $HostFQDN } else { $HostName }
                    IPAddress  = $HostIP
                    RuleVer    = $RuleVer
                    STIGID     = $RuleID
                    Severity   = $CatLabel
                    Title      = $Title.Trim()
                    Known      = $Known
                    AssetType  = $AssetType
                    FileName   = $File.Name
                })
            }
        }
        catch {
            Write-StigLog -Message "Failed to parse XML for $($File.Name): $($_.Exception.Message)" -Severity ERROR -Source "SummaryEngine"
        }
    }

    # Convert generic list back to standard PowerShell array for formatting output
    $OpenSummaryArray = $OpenSummaryList.ToArray()

    # 4. Generate visual console output & write the same structured table to log file
    $DashboardHeader = @"

************************************************************************
  SECTION SUMMARY: OPEN STIG CONTROLS
  Source: $ReportDir
************************************************************************
"@

    $DashboardTable = ""
    if ($OpenSummaryArray.Count -gt 0) {
        $DashboardTable = $OpenSummaryArray | Sort-Object Host, Severity, RuleVer | Format-Table -Property Host, RuleVer, STIGID, Severity, Known, Title -AutoSize | Out-String
    } else {
        $DashboardTable = "  [+] No open items found in this section! Compliant status confirmed.`n"
    }

    $DashboardFooter = "************************************************************************`n"

    # Write Table to Console ONLY if not silent
    if (-not $global:StigSilentMode) {
        Write-Host $DashboardHeader -ForegroundColor Cyan
        if ($OpenSummaryArray.Count -gt 0) {
            Write-Host $DashboardTable -ForegroundColor Yellow
        } else {
            Write-Host $DashboardTable -ForegroundColor Green
        }
        Write-Host $DashboardFooter -ForegroundColor Cyan
    }

    # Capture the same output in the encrypted App Log regardless of silent mode
    if ($global:StigAppLog) {
        $FullDashboardText = $DashboardHeader + "`r`n" + $DashboardTable + $DashboardFooter
        Add-Content -Path $global:StigAppLog -Value $FullDashboardText
    }

    # Update counts in standard app log channels
    $OpenCount = $OpenSummaryArray.Count
    $KnownCount = ($OpenSummaryArray | Where-Object { $_.Known -eq "True" }).Count
    $UnknownCount = $OpenCount - $KnownCount
    Write-StigLog -Message "Section summary compiled: $OpenCount Open Vulnerabilities ($KnownCount Known/Waivered, $UnknownCount Unknown/Action Required)" -Severity SUCCESS -Source "SummaryEngine"

    # 5. Export to CSV Report
    $FinalCsvPath = if ($CsvPath) { $CsvPath } else { Join-Path $ReportDir "Open_Items_Summary_$((Get-Date).ToString('yyyyMMdd_HHmmss')).csv" }
    
    if ($OpenSummaryArray.Count -gt 0) {
        try {
            $OpenSummaryArray | Export-Csv -Path $FinalCsvPath -NoTypeInformation -Force
            Write-StigLog -Message "Exported section-based CSV summary to: $FinalCsvPath" -Severity SUCCESS -Source "SummaryEngine"
        }
        catch {
            Write-StigLog -Message "Failed to export CSV report: $($_.Exception.Message)" -Severity ERROR -Source "SummaryEngine"
        }
    } else {
        # Export a clean header-matching placeholder CSV for compliance parsing consistency
        try {
            $HeadersObj = [PSCustomObject]@{
                Date       = $ScanDate
                Host       = "N/A"
                IPAddress  = "N/A"
                RuleVer    = "N/A"
                STIGID     = "N/A"
                Severity   = "N/A"
                Title      = "No open items found."
                Known      = "N/A"
                AssetType  = "N/A"
                FileName   = "N/A"
            }
            $HeadersObj | Export-Csv -Path $FinalCsvPath -NoTypeInformation -Force
            Write-StigLog -Message "Exported clean placeholder CSV summary to: $FinalCsvPath" -Severity SUCCESS -Source "SummaryEngine"
        }
        catch {
            Write-StigLog -Message "Failed to export placeholder CSV: $($_.Exception.Message)" -Severity ERROR -Source "SummaryEngine"
        }
    }
}


<#
.SYNOPSIS
    Copies section CKL files to the corresponding STIG Manager Collection inbox 
    and triggers the bash stigman-watcher one-shot upload.
    Prioritizes the globally defined collection_id from global_config.yml.
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

    foreach ($Ckl in $CklFiles) {
        $DestPath = Join-Path $InboxDir $Ckl.Name
        Copy-Item -Path $Ckl.FullName -Destination $DestPath -Force | Out-Null
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

    # Verify exit status of execution wrapper
    if ($LASTEXITCODE -eq 0) {
        Write-StigLog -Message "STIG Manager synchronization successfully finalized for Collection $CollectionId." -Severity SUCCESS -Source "StigManSync"
    } else {
        Write-StigLog -Message "STIG Manager Watcher encountered errors (Exit Code: $LASTEXITCODE). Output: $BashOutput" -Severity ERROR -Source "StigManSync"
    }
}

Export-ModuleMember -Function Initialize-StigLogging, Write-StigLog, Write-ElapsedTime, Get-DisaTemplate, Get-FormattedAnswer, Format-FindingDetail, Update-CklTemplate, Get-StigScanSummary, Invoke-StigManSync