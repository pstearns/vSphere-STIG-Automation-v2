# =========================================================================
# MODULE: NetAppStigHelper.psm1
# DESCRIPTION: Core helper functions for NetApp ONTAP STIG audits (FQDN & Short Name Flexible)
# =========================================================================

function Get-NetAppNetworkInfo {
    [CmdletBinding()]
    param(
        [string]$TargetFQDN,
        [string]$ClusterName,
        [PSCustomObject]$Credentials,
        [string]$ProjectRoot
    )

    $ipAddress   = ""
    $macAddress  = ""
    $homePort    = ""
    $tempInputFile = $null

    try {
        $psc = $Credentials.AdminCred
        $InSpecProfilePath = Join-Path $ProjectRoot "inspec"

        # === Robust temp file creation ===
        $tempDir = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
        $tempInputFile = Join-Path $tempDir "inspec_netapp_discovery_$(Get-Random).yml"

        "cluster: '$ClusterName'" | Out-File -FilePath $tempInputFile -Encoding UTF8 -Force

        $TargetsToTry = @()
        if (-not [string]::IsNullOrEmpty($TargetFQDN)) { $TargetsToTry += $TargetFQDN }
        if (-not [string]::IsNullOrEmpty($ClusterName) -and $ClusterName -ne $TargetFQDN) { $TargetsToTry += $ClusterName }

        foreach ($ConnectTarget in $TargetsToTry) {
            Write-StigLog "Running discovery control 'GET-CLUSTER-MGMT-INFO' for cluster [$ClusterName] using target [$ConnectTarget]..." -Severity INFO -Source "NetAppHelper"

            $ArgumentList = @(
                "exec",
                $InSpecProfilePath,
                "--target", "ontap://$($psc.UserName)@${ConnectTarget}",
                "--password", $psc.GetNetworkCredential().Password,
                "--controls", "GET-CLUSTER-MGMT-INFO",
                #"--input", "cluster=${ClusterName}",
                "--input-file", $tempInputFile
            )

            $discoveryOutput = & inspec $ArgumentList 2>&1

            foreach ($line in $discoveryOutput) {
                # FIXED: Ignored placeholder lines starting with 'Not', 'None', or similar patterns
                if ($line -match 'IP Address\s*:\s*([\d\.]+)')      { $ipAddress  = $Matches[1] }
                if ($line -match 'Home Port\s*:\s*([^Nn\s][^\s]*)') { $homePort   = $Matches[1] }
                if ($line -match 'MAC Address:\s*([0-9a-fA-F:]+)')  { $macAddress = $Matches[1] }
            }

            if (-not [string]::IsNullOrEmpty($ipAddress) -and -not [string]::IsNullOrEmpty($macAddress)) {
                break
            }
        }

        Write-StigLog "Discovered → IP: [$ipAddress] | Home Port: [$homePort] | MAC: [$macAddress]" -Severity INFO -Source "NetAppHelper"
    }
    catch {
        Write-StigLog "Error during network discovery: $($_.Exception.Message)" -Severity WARN -Source "NetAppHelper"
    }
    finally {
        if ($tempInputFile -and (Test-Path $tempInputFile)) {
            Remove-Item $tempInputFile -Force -ErrorAction SilentlyContinue
        }
    }

    return [PSCustomObject]@{
        IPAddress  = $ipAddress
        MACAddress = $macAddress
        HomePort   = $homePort
    }
}

function Get-NetAppTargets {
    [CmdletBinding()]
    param ([string]$ProjectRoot)

    $InputsPath = Join-Path $ProjectRoot "conf/inputs.yml"
    if (-not (Test-Path $InputsPath)) {
        Write-StigLog "NetApp inputs.yml not found at ${InputsPath}" -Severity ERROR -Source "NetAppHelper"
        return $null
    }
    try {
        $Inputs = Get-Content $InputsPath -Raw | ConvertFrom-Yaml -ErrorAction Stop
        $EnabledTargets = @($Inputs.netapp_targets | Where-Object { $_.enabled -eq $true -or "$($_.enabled)".ToLower() -eq "true" })
        return @{ Targets = $EnabledTargets }
    }
    catch {
        Write-StigLog "Failed to parse NetApp inputs.yml: $($_.Exception.Message)" -Severity ERROR -Source "NetAppHelper"
        return $null
    }
}

function Get-NetAppTargetCredential {
    [CmdletBinding()]
    param ([string]$FQDN, [string]$CredentialFile)
    try {
        $Creds = Get-NetAppCredential -FQDN $FQDN -FilePath $CredentialFile -ErrorAction Stop
        if (-not $Creds) { return $null }
        return $Creds
    }
    catch {
        Write-StigLog "Failed to get credentials for ${FQDN}: $($_.Exception.Message)" -Severity ERROR -Source "NetAppHelper"
        return $null
    }
}

function Start-NetAppChecklistGeneration {
    [CmdletBinding()]
    param(
        [string]$TargetFQDN,
        [string]$ClusterName,
        [PSCustomObject]$Credentials,
        [string]$DateString,
        [string]$ProjectRoot
    )

    $ReportDir = Join-Path $ProjectRoot "reports/${DateString}/${ClusterName}"
    if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

    $LogDir = Join-Path $ProjectRoot "logs"
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

    $InputsPath  = Join-Path $ProjectRoot "conf/inputs.yml"

    $LogOutput   = Join-Path $LogDir "${ClusterName}_InSpec-Run_${DateString}.log"
    $JsonOutput  = Join-Path $ReportDir "${ClusterName}_NetApp_InSpec-Results_${DateString}.json"
    $InSpecProfilePath = Join-Path $ProjectRoot "inspec"

    $NetInfo = Get-NetAppNetworkInfo -TargetFQDN $TargetFQDN -ClusterName $ClusterName -Credentials $Credentials -ProjectRoot $ProjectRoot

    Write-StigLog "Running full InSpec STIG audit for ${TargetFQDN}. Log: ${LogOutput}" -Severity INFO -Source "NetAppHelper"
    $psc = $Credentials.AdminCred

    $ExecTarget = if (-not [string]::IsNullOrEmpty($TargetFQDN)) { $TargetFQDN } else { $ClusterName }

    $ArgumentList = @(
        "exec", $InSpecProfilePath,
        "--target", "ontap://$($psc.UserName)@${ExecTarget}",
        "--password", $psc.GetNetworkCredential().Password,
        "--input-file", $InputsPath,
        "--reporter", "json:${JsonOutput}"
    )
    & inspec $ArgumentList *> $LogOutput

    $ValidExitCodes = @(0, 100)
    if ($LASTEXITCODE -notin $ValidExitCodes -or -not (Test-Path $JsonOutput) -or (Get-Item $JsonOutput).Length -eq 0) {
        Write-StigLog "ERROR: InSpec failed or produced empty JSON. See log: ${LogOutput}" -Severity ERROR -Source "NetAppHelper"
        return $null
    }

    $TempCklPath = Join-Path $ReportDir "${ClusterName}_Temp-Findings.ckl"
    & saf convert hdf2ckl -i $JsonOutput -o $TempCklPath
    if (-not (Test-Path $TempCklPath)) {
        Write-StigLog "ERROR: saf convert hdf2ckl failed." -Severity ERROR -Source "NetAppHelper"
        return $null
    }

    $TemplatePath = Join-Path $ProjectRoot "templates/CKL_Templates/U_NetApp_ONTAP_DSC_9-x_V2R4/U_NetApp_ONTAP_DSC_9-x_V2R4_STIG.ckl"
    $FinalCklPath = Join-Path $ReportDir "${ClusterName}_NetApp-ONTAP_${DateString}.ckl"
    $AnswerFile   = Join-Path $ProjectRoot "conf/answers.xml"          

    if (-not (Test-Path $TemplatePath)) {
        Write-StigLog "ERROR: Official STIG template not found at ${TemplatePath}" -Severity ERROR -Source "NetAppHelper"
        return $null
    }

    if (Test-Path $AnswerFile) {
        Write-StigLog "Answer file found at $AnswerFile - processing overrides..." -Severity INFO -Source "NetAppHelper"
    } else {
        Write-StigLog "No answers.xml found at $AnswerFile - skipping answer file processing." -Severity DEBUG -Source "NetAppHelper"
    }

    # === SURGICAL MERGE ===
    try {
        [xml]$templateXml = New-Object System.Xml.XmlDocument
        $templateXml.PreserveWhitespace = $true
        $templateXml.Load($TemplatePath)

        $rawFindings = Get-Content -Path $TempCklPath -Raw
        $sanitizedFindings = [System.Text.RegularExpressions.Regex]::Replace(
            $rawFindings,
            '[^\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD\u10000-\u10FFFF]',
            ''
        )
        [xml]$findingsXml = $sanitizedFindings

        # Update ASSET block
        $asset             = $templateXml.CHECKLIST.ASSET
        $asset.ROLE        = "Member Server"
        $asset.ASSET_TYPE  = "Computing"
        $asset.MARKING     = "CUI"
        $asset.HOST_NAME   = $ClusterName
        $asset.HOST_FQDN   = $TargetFQDN
        $asset.HOST_IP     = $NetInfo.IPAddress
        $asset.HOST_MAC    = $NetInfo.MACAddress

        # Build lookup from InSpec findings
        $findingsMap = @{}
        foreach ($vuln in $findingsXml.CHECKLIST.STIGS.iSTIG.VULN) {
            $ruleVerNode = $vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Rule_Ver" }
            if ($ruleVerNode) {
                $ruleVer = $ruleVerNode.ATTRIBUTE_DATA
                if ($ruleVer) { $findingsMap[$ruleVer] = $vuln }
            }
        }

        Write-StigLog "Found $($findingsMap.Count) InSpec findings to merge into template." -Severity INFO -Source "NetAppHelper"

        # Only update matching VULNs
        $updatedCount = 0
        foreach ($templateVuln in $templateXml.CHECKLIST.STIGS.iSTIG.VULN) {
            $ruleVerNode = $templateVuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq "Rule_Ver" }
            if (-not $ruleVerNode) { continue }

            $ruleVer = $ruleVerNode.ATTRIBUTE_DATA
            if (-not $ruleVer -or -not $findingsMap.ContainsKey($ruleVer)) { continue }

            $finding = $findingsMap[$ruleVer]

            $vulnSTATUS   = $finding.STATUS
            $vulnFindDet  = if ($finding.FINDING_DETAILS) { $finding.FINDING_DETAILS } else { "" }
            $vulnCOMMENTS = if ($finding.COMMENTS) { $finding.COMMENTS } else { "" }

            # === Answer File Override Logic ===
            if (Test-Path $AnswerFile) {
                try {
                    $answerData = Get-FormattedAnswer -AnswerFile           $AnswerFile `
                                                    -vulnRuleVer          $ruleVer `
                                                    -CurrentStatus        $vulnSTATUS `
                                                    -FindingDetailsText   $vulnFindDet `
                                                    -AnswerKey            "DEFAULT"

                    if ($null -ne $answerData -and $answerData.Status -ne "") {
                        Write-StigLog "Answer file override applied for $ruleVer → Status: $($answerData.Status)" -Severity SUCCESS -Source "NetAppHelper"
                        $vulnSTATUS   = $answerData.Status
                        $vulnCOMMENTS = $answerData.Comments
                    }
                }
                catch {
                    Write-StigLog "Error processing answer file for $ruleVer : $($_.Exception.Message)" -Severity WARN -Source "NetAppHelper"
                }
            }

            # STATUS
            $statusNode = $templateVuln.SelectSingleNode("STATUS")
            if ($statusNode) {
                $statusNode.InnerText = $vulnSTATUS
            }

            # FINDING_DETAILS
            $fdNode = $templateVuln.SelectSingleNode("FINDING_DETAILS")
            if ($fdNode) {
                $stigidNode = $templateXml.SelectSingleNode("//SI_DATA[SID_NAME='stigid']/SID_DATA")
                $moduleName = if ($stigidNode) { $stigidNode.InnerText } else { "NetApp_ONTAP_DSC_9-x_STIG" }

                $formatted = Format-FindingDetail -Status $vulnSTATUS -FindingDetails $vulnFindDet -ModuleName $moduleName
                $fdNode.InnerText = $formatted.FindingDetails
            }

            # COMMENTS
            $commentsNode = $templateVuln.SelectSingleNode("COMMENTS")
            if ($commentsNode) {
                $commentsNode.InnerText = $vulnCOMMENTS
            }

            $updatedCount++
        }

        Write-StigLog "Successfully updated $updatedCount VULN nodes in the official template." -Severity SUCCESS -Source "NetAppHelper"

        $templateXml.Save($FinalCklPath)

        try {
            [xml]::new().Load($FinalCklPath) | Out-Null
            Write-StigLog "Final CKL validated as well-formed XML: $FinalCklPath" -Severity SUCCESS -Source "NetAppHelper"
        }
        catch {
            Write-StigLog "WARNING: Final CKL failed XML validation after save." -Severity WARN -Source "NetAppHelper"
        }

        # === NetApp-native STIG Manager Upload ===
        try {
            Invoke-NetAppStigManSync -ClusterName $ClusterName `
                                     -ReportDir $ReportDir `
                                     -ProjectRoot $ProjectRoot
        }
        catch {
            Write-StigLog "STIG Manager sync encountered an issue for ${ClusterName}: $($_.Exception.Message)" -Severity WARN -Source "NetAppHelper"
        }

        return [PSCustomObject]@{ TargetFQDN = $TargetFQDN; CklFile = $FinalCklPath }
    }
    catch {
        Write-StigLog "ERROR during surgical CKL merge: $($_.Exception.Message)" -Severity ERROR -Source "NetAppHelper"
        return $null
    }
    finally {
        if (Test-Path $TempCklPath) { Remove-Item $TempCklPath -Force -ErrorAction SilentlyContinue }

        # Cleanup raw InSpec JSON results file (we only keep the final merged CKL)
        $jsonPattern = Join-Path $ReportDir "${ClusterName}_NetApp_InSpec-Results_*.json"
        Get-ChildItem -Path $jsonPattern -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-NetAppStigManSync {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ClusterName,
        [Parameter(Mandatory=$true)][string]$ReportDir,
        [Parameter(Mandatory=$true)][string]$ProjectRoot
    )

    Write-StigLog "Checking for STIG Manager upload eligibility for cluster [$ClusterName]..." -Severity DEBUG -Source "NetAppStigMan"

    # 1. Resolve collection_id from NetApp's own inputs.yml
    $InputsPath = Join-Path $ProjectRoot "conf/inputs.yml"
    $CollectionId = $null

    if (Test-Path $InputsPath) {
        try {
            $Inputs = Get-Content $InputsPath -Raw | ConvertFrom-Yaml -ErrorAction Stop
            if ($Inputs.collection_id) {
                $CollectionId = [string]$Inputs.collection_id
            }
        }
        catch {
            Write-StigLog "Could not parse collection_id from inputs.yml: $($_.Exception.Message)" -Severity WARN -Source "NetAppStigMan"
        }
    }

    if (-not $CollectionId) {
        Write-StigLog "No collection_id found in NetApp inputs.yml - skipping STIG Manager upload." -Severity DEBUG -Source "NetAppStigMan"
        return
    }

    Write-StigLog "Using STIG Manager Collection ID: $CollectionId for cluster $ClusterName" -Severity INFO -Source "NetAppStigMan"

    # 2. Prepare the stigman-watcher inbox directory
    $InboxDir = "/usr/share/stigs/orchestration_overlay/stigman-watcher/inboxes/coll_$CollectionId"

    # Fallback locations if the standard path doesn't exist
    if (-not (Test-Path $InboxDir)) {
        $altInbox = "/opt/stigs/orchestration_overlay/stigman-watcher/inboxes/coll_$CollectionId"
        if (Test-Path $altInbox) {
            $InboxDir = $altInbox
        }
    }

    if (-not (Test-Path $InboxDir)) {
        try {
            New-Item -ItemType Directory -Path $InboxDir -Force | Out-Null
            Write-StigLog "Created STIG Manager inbox directory: $InboxDir" -Severity INFO -Source "NetAppStigMan"
        }
        catch {
            Write-StigLog "Failed to create STIG Manager inbox at $InboxDir. Upload will likely fail." -Severity ERROR -Source "NetAppStigMan"
            return
        }
    }

    # 3. Copy ONLY the final .ckl file into the inbox (exclude temp/findings files)
    $CklFiles = Get-ChildItem -Path $ReportDir -Filter "*.ckl" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch 'Temp|Findings' }

    if ($CklFiles.Count -eq 0) {
        Write-StigLog "No final .ckl file found in $ReportDir to upload to STIG Manager." -Severity INFO -Source "NetAppStigMan"
        return
    }

    foreach ($ckl in $CklFiles) {
        $dest = Join-Path $InboxDir $ckl.Name
        try {
            Copy-Item -Path $ckl.FullName -Destination $dest -Force -ErrorAction Stop
            Write-StigLog "Copied $($ckl.Name) to STIG Manager inbox (coll_$CollectionId)" -Severity DEBUG -Source "NetAppStigMan"
        }
        catch {
            Write-StigLog "Failed to copy $($ckl.Name) to inbox: $($_.Exception.Message)" -Severity WARN -Source "NetAppStigMan"
        }
    }

    # 4. Trigger the stigman-watcher one-shot upload script
    $WatcherScript = "/usr/share/stigs/orchestration_overlay/bin/run-stigman-watcher.sh"
    if (-not (Test-Path $WatcherScript)) {
        $WatcherScript = "/opt/stigs/orchestration_overlay/bin/run-stigman-watcher.sh"
    }

    if (-not (Test-Path $WatcherScript)) {
        Write-StigLog "STIG Manager watcher script not found at expected locations. Cannot trigger upload." -Severity WARN -Source "NetAppStigMan"
        return
    }

    Write-StigLog "Triggering STIG Manager watcher upload for Collection $CollectionId..." -Severity INFO -Source "NetAppStigMan"

    try {
        $bashOutput = bash -c "bash '$WatcherScript' '$CollectionId'" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-StigLog "STIG Manager upload completed successfully for Collection $CollectionId" -Severity SUCCESS -Source "NetAppStigMan"
        }
        else {
            Write-StigLog "STIG Manager watcher exited with code $LASTEXITCODE. Output: $bashOutput" -Severity WARN -Source "NetAppStigMan"
        }
    }
    catch {
        Write-StigLog "Error running STIG Manager watcher: $($_.Exception.Message)" -Severity ERROR -Source "NetAppStigMan"
    }
}

function Get-NetAppCollectionId {
    [CmdletBinding()]
    param([string]$ProjectRoot)

    $InputsPath = Join-Path $ProjectRoot "conf/inputs.yml"
    if (-not (Test-Path $InputsPath)) { return $null }

    try {
        $Inputs = Get-Content $InputsPath -Raw | ConvertFrom-Yaml -ErrorAction Stop
        return $Inputs.collection_id
    }
    catch {
        return $null
    }
}

Export-ModuleMember -Function Get-NetAppTargets, Get-NetAppTargetCredential, Start-NetAppChecklistGeneration, Get-NetAppNetworkInfo, Invoke-NetAppStigManSync, Get-NetAppCollectionId