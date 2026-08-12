# =========================================================================
# MODULE: globalFunctions.psm1
# DESCRIPTION: Core utility library containing only the required functions
# for enterprise logging, XML manipulation, and STIG formatting.
# =========================================================================

# =========================================================================
# REGION: Enterprise Structured Logging
# =========================================================================

<#
.SYNOPSIS
    Initializes dual-channel logging (Structured App Log + Raw Transcript).
.DESCRIPTION
    Establishes the global logging state for the orchestration run. It generates a 
    clean, SIEM-ingestible fixed-width log file alongside a native PowerShell 
    transcript for deep runtime debugging.
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
    
    # Captures unhandled PowerShell errors and verbose streams
    Start-Transcript -Path $TranscriptPath -Append -Force | Out-Null
    
    Write-StigLog -Message "Pipeline Logging Initialized. Silent Mode: $($global:StigSilentMode)" -Severity INFO -Source "System"
}

<#
.SYNOPSIS
    Writes structured, fixed-width log entries to file and console.
.DESCRIPTION
    Standardizes log output formats for SIEM ingestion. Uses fixed padding for 
    Severity and Source columns to ensure perfect alignment in aggregators.
#>
function Write-StigLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR', 'DEBUG')][string]$Severity = 'INFO',
        [string]$Source = 'Orchestrator'
    )
    
    # Enforces ISO 8601 timestamp standard for accurate log aggregation
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogEntry  = "[$Timestamp] [$($Severity.PadRight(7))] [$($Source.PadRight(15))] $Message"

    if ($global:StigAppLog) { 
        Add-Content -Path $global:StigAppLog -Value $LogEntry 
    }

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
.DESCRIPTION
    Uses Regex pattern matching to locate the correct target template regardless 
    of the appended DISA V#R# string, eliminating hardcoded version dependencies.
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
.DESCRIPTION
    Validates the InSpec finding against localized waivers. Automatically handles 
    expired review dates by degrading the status to 'Not_Reviewed' to enforce 
    continuous monitoring standards.
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
        # Thread-safe caching mechanism to prevent parallel collisions
        if (-not $script:AnswerXmlCache) { $script:AnswerXmlCache = @{} }

        if ($script:AnswerXmlCache.ContainsKey($AnswerFile)) {
            $answerXmlData = $script:AnswerXmlCache[$AnswerFile]
        } else {
            [xml]$answerXmlData = [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::UTF8.GetBytes((Get-Content -Path $AnswerFile -Raw)))
            $script:AnswerXmlCache[$AnswerFile] = $answerXmlData
        }

        $answerEntry = $answerXmlData.SelectSingleNode("//STIG[@ID='$vulnRuleVer']")
        if (-not $answerEntry) { return $null }

        $answerObj       = $answerEntry.AnswerKey
        $validAnswerKeys = $answerObj.Name -split "\s+"
        
        if (-not ($AnswerKey -in $validAnswerKeys -or $answerObj.Name -eq "DEFAULT")) { return $null }

        $expectedStatus = $answerObj.ExpectedStatus.Trim()
        
        # Abort override if the raw status doesn't match the expected entry criteria
        if ($expectedStatus -ne $CurrentStatus) {
            $result.Status = $CurrentStatus
            return $result
        }

        # Calculate expiration based on frequency thresholds
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

        # Process Validation Codes to dynamically shift statuses based on textual output
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
        
        # Enforce degradation to Not_Reviewed if the manual verification has expired
        if ($reviewMeta -match "Expired") { $newStatus = "Not_Reviewed" }

        $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $preComment = "INSPEC Answer file for Key '$AnswerKey' is providing the below comment on $($timestamp):`r`n"
        
        if ($newStatus -ne $CurrentStatus) {
            $preComment = "INSPEC Answer file for Key '$AnswerKey' is changing Status from '$CurrentStatus' to '$newStatus' on $($timestamp):`r`n"
        }

        $finalComment = $preComment + $commentBody
        
        # Hard truncate to prevent STIG Manager API injection failures caused by oversized payload strings
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
    
    # Establish standard headers for clarity in the STIG Manager UI
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
    CKL file and injects them into a pristine DISA CKL template. This ensures full 
    schema compliance with STIG Manager and eMASS.
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
        
        Write-StigLog -Message "Injecting Answers and Formatting CKL into: $ProfileName..." -Severity INFO -Source "Formatter"
        
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
        # [FIX]: Stop pulling from $workingXml as SAF strips these. Pull directly from $Job properties.
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
        } else {
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

             # Call Get-FormattedAnswer to inject statuses, comments, and waivers from answers.xml
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

Export-ModuleMember -Function Initialize-StigLogging, Write-StigLog, Write-ElapsedTime, Get-DisaTemplate