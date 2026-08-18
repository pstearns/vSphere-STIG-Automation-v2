# =========================================================================
# MODULE: RemediationOrchestration.psm1
# DESCRIPTION: Enterprise STIG Remediation & Parallel Verification Engine
#              Supports VM, ESXi, and VCSA as pluggable microservices.
#              Automatically crawls date folders backward per vCenter.
# =========================================================================

if (Test-Path "/usr/share/stigs/orchestration_overlay") {
    $Script:OverlayRoot = "/usr/share/stigs/orchestration_overlay"
} else {
    $Script:OverlayRoot = (Resolve-Path "$PSScriptRoot/..").FullName
}

$WarningPreference = 'SilentlyContinue'

# Load Global Core Dependencies
Import-Module powershell-yaml -Global -Force -ErrorAction Stop
Import-Module (Join-Path $Script:OverlayRoot "modules/CredentialManagement.psm1") -Global -Force -ErrorAction Stop
Import-Module (Join-Path $Script:OverlayRoot "modules/globalFunctions.psm1") -Global -Force -ErrorAction Stop

function Invoke-StigRemediation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("VM", "ESXi", "VCSA")]
        [string]$AssetType,

        [string]$OverlayRoot = $Script:OverlayRoot,
        [switch]$Silent,
        [string]$DateStr = (Get-Date -Format "yyyyMMdd"),
        [string]$TargetName # Filters VMName, ESXi Hostname, or VCSA FQDN
    )

    $StartTime = Get-Date
    Initialize-StigLogging -LogDirectory (Join-Path $OverlayRoot "logs") -Silent:$Silent
    Write-StigLog -Message "Starting Multi-Asset [$AssetType] STIG Remediation & Parallel Sync..." -Severity INFO -Source "Orchestrator"

    try {
        # 1. Load active vCenter targets
        $ActiveTargets = Get-ActiveTargets -OverlayRoot $OverlayRoot
        if ($ActiveTargets.Count -eq 0) {
            Write-StigLog "No enabled vCenter targets found in global_config.yml." -Severity WARN -Source "Orchestrator"
            return
        }

        # 2. Retrieve secure credentials
        $CredentialFile = Join-Path $OverlayRoot "conf/.creds.json.encrypted"
        $Credentials = Get-vCenterCredentialStore -FilePath $CredentialFile

        # Initialize Thread-Safe History Logger
        $ReportsBaseDir = Join-Path $OverlayRoot "reports"
        $HistoryCsv = Join-Path $ReportsBaseDir "Remediation_History_Master.csv"
        $HistoryBag = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

        # 3. Dynamic Service Provider Loader
        $NormalizedAsset = (Get-Culture).TextInfo.ToTitleCase($AssetType.ToLower())
        $AssetFolder     = $AssetType.ToLower()
        $ProviderPath    = Join-Path $OverlayRoot "modules/$AssetFolder/${NormalizedAsset}RemediationProvider.psm1"

        if (-not (Test-Path $ProviderPath)) {
            throw "Remediation provider not found for AssetType '$AssetType' at: $ProviderPath"
        }
        Import-Module $ProviderPath -Force -DisableNameChecking

        # Configure Asset-Specific Environment Variables
        $AssetConfig = Get-AssetProviderConfig -OverlayRoot $OverlayRoot

        # 4. Process each enabled vCenter target
        foreach ($vCenterFQDN in $ActiveTargets) {
            $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
            
            # --- DYNAMIC PER-VCENTER DATE TRAVERSAL BACKWARDS ---
            Write-StigLog "[$vCenterShortName] Searching backwards for the most recent date directory containing '$AssetType' checklists..." -Severity INFO -Source "Orchestrator"
            
            $ReportPath = $null
            $ResolvedDate = $null
            
            if (Test-Path $ReportsBaseDir) {
                # Get all date directories sorted descending (newest first)
                $DateDirs = Get-ChildItem -Path $ReportsBaseDir -Directory | 
                    Where-Object { $_.Name -match "^\d{8}$" } | 
                    Sort-Object Name -Descending

                foreach ($DateDir in $DateDirs) {
                    $vCenterReportDir = Join-Path $ReportsBaseDir "$($DateDir.Name)/$vCenterShortName"
                    if (Test-Path $vCenterReportDir) {
                        # Case-insensitive resolution of the subfolder on Linux
                        $MatchedDir = Get-ChildItem -Path $vCenterReportDir -Directory | 
                            Where-Object { $_.Name -like "$AssetType*" -or $_.Name -like "$($AssetType)s*" } | 
                            Select-Object -First 1
                        
                        if ($MatchedDir) {
                            # Verify if there are actual checklist files inside
                            $CklCount = (Get-ChildItem -Path $MatchedDir.FullName -Filter "*.ckl").Count
                            if ($CklCount -gt 0) {
                                $ReportPath = $MatchedDir.FullName
                                $ResolvedDate = $DateDir.Name
                                break # Match found! Stop traversal and use this path.
                            }
                        }
                    }
                }
            }

            if (-not $ReportPath) {
                Write-StigLog "No checklists found for $vCenterShortName matching '$AssetType' in any date folder under $ReportsBaseDir. Skipping vCenter." -Severity WARN -Source "Orchestrator"
                continue
            }

            Write-StigLog "[$vCenterShortName] Locked onto checklists at: $ReportPath (Resolved Date: $ResolvedDate)" -Severity SUCCESS -Source "Orchestrator"

            # Retrieve targets from secure vault
            $VaultEntry = $Credentials.vCenters | Where-Object { $_.FQDN -eq $vCenterFQDN }
            if ($null -eq $VaultEntry) { continue }
            
            $CredObj = Get-vCenterCredential -FQDN $vCenterFQDN -FilePath $CredentialFile
            $AdminUser = $CredObj.AdminCred.UserName
            $AdminPass = $CredObj.AdminCred.GetNetworkCredential().Password

            $CklFiles = Get-ChildItem -Path $ReportPath -Filter "*.ckl"
            if (-not [string]::IsNullOrWhiteSpace($TargetName)) {
                $CklFiles = $CklFiles | Where-Object { $_.BaseName -match $TargetName -or $_.Name -match $TargetName }
                if ($CklFiles.Count -eq 0) {
                    Write-StigLog "[$vCenterShortName] No checklists match target filter '$TargetName' inside $ReportPath. Skipping." -Severity INFO -Source "Orchestrator"
                    continue
                }
            }

            # --- PHASE 1: SEQUENTIAL REMEDIATION ---
            Write-StigLog "[$vCenterShortName] Establishing parent session for [$AssetType] remediation using resolved date [$ResolvedDate]..." -Severity INFO -Source "Orchestrator"
            Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -InvalidCertificateAction Ignore -ParticipateInCEIP $false -Confirm:$false -Scope Session | Out-Null
            $ParentConnection = Connect-VIServer -Server $vCenterFQDN -User $AdminUser -Password $AdminPass -Force -ErrorAction Stop

            $RemediatedQueue = @()

            foreach ($File in $CklFiles) {
                $XmlCkl = New-Object System.Xml.XmlDocument
                $XmlCkl.PreserveWhitespace = $true
                $XmlCkl.Load($File.FullName)

                $TargetAssetName = $XmlCkl.CHECKLIST.ASSET.HOST_NAME
                $OpenNodes = $XmlCkl.SelectNodes("/CHECKLIST/STIGS/iSTIG/VULN[STATUS='Open']")
                $FixList = [System.Collections.Generic.List[string]]::new()
                $HasWaiverChanges = $false

                foreach ($Node in $OpenNodes) {
                    $RuleVer = ($Node.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Ver" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText
                    $vulnFindDet = if ($Node.SelectSingleNode("FINDING_DETAILS")) { $Node.SelectSingleNode("FINDING_DETAILS").InnerXml } else { "" }
                    
                    # Process Waiver / Answer File updates
                    $Answer = Get-FormattedAnswer -AnswerFile $AssetConfig.AnswersXml -vulnRuleVer $RuleVer -CurrentStatus "Open" -FindingDetailsText $vulnFindDet -AnswerKey "DEFAULT"
                    
                    if ($null -ne $Answer -and $Answer.Status -eq "NotAFinding") {
                        $Node.SelectSingleNode("STATUS").InnerText = "NotAFinding"
                        $Node.SelectSingleNode("COMMENTS").InnerXml = $Answer.Comments
                        $HasWaiverChanges = $true
                        Write-StigLog " [$TargetAssetName] Waiver applied for $RuleVer" -Severity SUCCESS -Source "Orchestrator"
                    } else {
                        [void]$FixList.Add($RuleVer)
                    }
                }

                if ($HasWaiverChanges) { $XmlCkl.Save($File.FullName) }

                # Execute technical remediations via loaded Asset Provider
                if ($FixList.Count -gt 0 -or $HasWaiverChanges) {
                    $AssetObject = Get-AssetObject -Name $TargetAssetName -ErrorAction SilentlyContinue
                    if ($null -eq $AssetObject) {
                        Write-StigLog "[$TargetAssetName] Could not resolve asset object in vCenter. Skipping." -Severity ERROR -Source "Orchestrator"
                        continue
                    }

                    $SuccessFixes = @()
                    if ($FixList.Count -gt 0) {
                        $SuccessFixes = Invoke-AssetRemediation -AssetObject $AssetObject -FixList $FixList -Config $AssetConfig -Creds $CredObj
                        
                        foreach ($StigID in $SuccessFixes) {
                            $HistoryBag.Add([PSCustomObject]@{
                                Date       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                                vCenter    = $vCenterShortName
                                AssetType  = $AssetType
                                AssetName  = $TargetAssetName
                                STIGID     = $StigID
                                Status     = "Remediated"
                                Method     = "Automated Provider Pipeline"
                            })
                        }
                    }

                    if ($SuccessFixes.Count -gt 0 -or $HasWaiverChanges) {
                        $RemediatedQueue += [PSCustomObject]@{
                            File           = $File.FullName
                            AssetName      = $TargetAssetName
                            VcenterObjName = $AssetObject.Name
                            FixedRules     = $SuccessFixes
                            XmlDoc         = $XmlCkl
                        }
                    }
                }
            }

            Disconnect-VIServer -Server $ParentConnection -Confirm:$false | Out-Null

            # --- PHASE 2: PARALLEL VERIFICATION & UPLOAD (BATCH OF 40) ---
            if ($RemediatedQueue.Count -gt 0) {
                $TotalQueue = $RemediatedQueue.Count
                $BatchSize  = 40
                Write-StigLog "[$vCenterShortName] Initiating parallel verification for $TotalQueue [$AssetType] assets..." -Severity INFO -Source "Orchestrator"

                for ($i = 0; $i -lt $TotalQueue; $i += $BatchSize) {
                    $Batch = $RemediatedQueue | Select-Object -Skip $i -First $BatchSize
                    
                    $Batch | ForEach-Object -Parallel {
                        $Job = $_
                        $OverlayRoot      = $using:OverlayRoot
                        $vCenterFQDN      = $using:vCenterFQDN
                        $AdminUser        = $using:AdminUser
                        $AdminPass        = $using:AdminPass
                        $AssetType        = $using:AssetType
                        $AssetConfig      = $using:AssetConfig
                        $vCenterShortName = $using:vCenterShortName
                        $ProviderPath     = $using:ProviderPath # Pass Provider to Sub-Runspace

                        # Initialize verification runspace
                        $GlobalFuncsPath = Join-Path $OverlayRoot "modules/globalFunctions.psm1"
                        Invoke-Expression ((Get-Content $GlobalFuncsPath -Raw) -replace '(?s)Export-ModuleMember.*', '')

                        # Dynamically import the Asset Provider within the local thread context
                        Import-Module $ProviderPath -Force -DisableNameChecking

                        $StagingDir = "/tmp/remediation_staging/$($Job.AssetName)"
                        if ($Job.FixedRules.Count -gt 0) {
                            if (-not (Test-Path $StagingDir)) { New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null }
                            $DeltaJson = Join-Path $StagingDir "delta_verify.json"
                            $DeltaCkl  = Join-Path $StagingDir "delta_verify.ckl"

                            # Dynamic Provider-based Verification Runner (Cinc-Auditor)
                            $ArgTrail = Get-AssetVerificationArgs -Job $Job -Config $AssetConfig -DeltaJson $DeltaJson
                            
                            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                            $ProcessInfo.FileName = "bash"
                            $ProcessInfo.Arguments = "-c `"cinc-auditor $ArgTrail 2>&1`""
                            $ProcessInfo.UseShellExecute = $false
                            $ProcessInfo.RedirectStandardOutput = $true
                            $ProcessInfo.EnvironmentVariables["VISERVER"]          = $vCenterFQDN
                            $ProcessInfo.EnvironmentVariables["VISERVER_USERNAME"] = $AdminUser
                            $ProcessInfo.EnvironmentVariables["VISERVER_PASSWORD"] = $AdminPass

                            $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
                            $VerifyOutput = $Process.StandardOutput.ReadToEnd()
                            $Process.WaitForExit()

                            # Diagnostic Logging Output for cinc-auditor failures
                            if (-not (Test-Path $DeltaJson)) {
                                [Console]::WriteLine("[$($Job.AssetName)] ERROR: cinc-auditor did not generate delta report!")
                                [Console]::WriteLine("[$($Job.AssetName)] Raw Process Output:`n$VerifyOutput")
                            }

                            if (Test-Path $DeltaJson) {
                                bash -c "saf convert hdf2ckl -i '$DeltaJson' -o '$DeltaCkl'" | Out-Null
                                if (Test-Path $DeltaCkl) {
                                    
                                    # --- RESTORED XML MERGING LOOP (LOCAL RUNSPACE SAFE) ---
                                    $DeltaXml = New-Object System.Xml.XmlDocument
                                    $DeltaXml.Load($DeltaCkl)
                                    $XmlCkl = $Job.XmlDoc
                                    $AnswersXml = $AssetConfig.AnswersXml

                                    foreach ($FixedVuln in $DeltaXml.CHECKLIST.STIGS.iSTIG.VULN) {
                                        $FixedRuleVer = ($FixedVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Ver" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText
                                        $FixedRuleID  = ($FixedVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_ID" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText
                                        
                                        $vulnSTATUS   = $FixedVuln.SelectSingleNode("STATUS").InnerText
                                        $vulnFindDet  = $FixedVuln.SelectSingleNode("FINDING_DETAILS").InnerXml
                                        
                                        $StatusString = if ($vulnSTATUS -eq "NotAFinding") { "NOT A FINDING" } else { "OPEN" }
                                        $DateString = (Get-Date).ToString("MM/dd/yyyy")
                                        
                                        # Corrected Line Spacing Definition
                                        $StandardHeader = "Inspec Profile: VMW_vSphere_8.0_Virtual_Machine_STIG found this to be $StatusString on ${DateString}:`r`n------------------------------------------------------------------------`r`n"
                                        
                                        $finalFindingDetails = if ($vulnFindDet -like "Inspec Profile:*") {
                                            $vulnFindDet
                                        } else {
                                            $StandardHeader + $vulnFindDet
                                        }
                                        
                                        $finalComments = ""

                                        # Apply Answer File overrides
                                        if ((Test-Path $AnswersXml) -and $FixedRuleVer) {
                                            $AnswerData = Get-FormattedAnswer -AnswerFile $AnswersXml -vulnRuleVer $FixedRuleVer -CurrentStatus $vulnSTATUS -FindingDetailsText $vulnFindDet -AnswerKey "DEFAULT"
                                            if ($null -ne $AnswerData -and $AnswerData.Status -ne "") {
                                                $vulnSTATUS    = $AnswerData.Status
                                                $finalComments = $AnswerData.Comments
                                            }
                                        }

                                        # Update Master Checklist Node
                                        $MasterNode = $null
                                        if ($FixedRuleVer) {
                                            $MasterNode = $XmlCkl.SelectSingleNode("/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$FixedRuleVer']]")
                                        }
                                        if (-not $MasterNode -and $FixedRuleID) {
                                            $MasterNode = $XmlCkl.SelectSingleNode("/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$FixedRuleID']]")
                                        }

                                        if ($MasterNode) {
                                            $MasterNode.SelectSingleNode("STATUS").InnerText          = $vulnSTATUS
                                            $MasterNode.SelectSingleNode("FINDING_DETAILS").InnerXml  = $finalFindingDetails
                                            $MasterNode.SelectSingleNode("COMMENTS").InnerXml         = $finalComments
                                            [Console]::WriteLine("[$($Job.AssetName)] -> Updated Checklist: $FixedRuleVer -> Status: $vulnSTATUS")
                                        }
                                    }

                                    $XmlCkl.Save($Job.File)
                                    [Console]::WriteLine("[$($Job.AssetName)] Delta verification successfully merged.")
                                }
                            }
                            Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
                        }

                        # Real-Time STIG Manager Synchronization
                        $MutexName = "StigManWatcherMutex"
                        $Mutex = New-Object System.Threading.Mutex($false, $MutexName)
                        [void]$Mutex.WaitOne()
                        try {
                            $InboxDir = Join-Path $OverlayRoot "stigman-watcher/inboxes/coll_6"
                            $RemediatedFileName = (Split-Path $Job.File -Leaf) -replace '\.ckl$', "_Remediated_$((Get-Date).ToString('HHmmss')).ckl"
                            $StagedPath = Join-Path $InboxDir $RemediatedFileName
                            Copy-Item -Path $Job.File -Destination $StagedPath -Force | Out-Null
                            
                            $WatcherScript = Join-Path $OverlayRoot "bin/run-stigman-watcher.sh"
                            $UploadOutput = bash -c "bash '$WatcherScript' '6'" 2>&1
                        }
                        finally {
                            $Mutex.ReleaseMutex()
                            $Mutex.Dispose()
                        }
                    } -ThrottleLimit 40
                }
            }
        }

        # Step 5: Append Remediation History Log
        if ($HistoryBag.Count -gt 0) {
            $HistoryBag.ToArray() | Export-Csv -Path $HistoryCsv -NoTypeInformation -Append -Force
            Write-StigLog "Master remediation history updated: $HistoryCsv" -Severity SUCCESS -Source "Orchestrator"
        }

        Write-ElapsedTime -StartTime $StartTime -Message "Remediation Cycle Complete for [$AssetType]." -Source "Orchestrator"
    }
    catch {
        Write-StigLog -Message "Orchestrator Failed: $($_.Exception.Message)" -Severity ERROR -Source "Orchestrator"
    }
}

function Get-ActiveTargets {
    param([string]$OverlayRoot = $Script:OverlayRoot)
    $GlobalConfPath = Join-Path $OverlayRoot "conf/global_config.yml"
    if (-not (Test-Path $GlobalConfPath)) { throw "Global configuration not found at $GlobalConfPath" }
    $GlobalConf = Get-Content $GlobalConfPath -Raw | ConvertFrom-Yaml

    $ActiveList = [System.Collections.Generic.List[string]]::new()
    if ($GlobalConf.vcenter_targets) {
        foreach ($t in $GlobalConf.vcenter_targets) {
            $Fqdn    = if ($t.fqdn) { $t["fqdn"] } else { $t["fqdn"] }
            $Enabled = if ($null -ne $t.enabled) { $t["enabled"] } else { $t["enabled"] }

            if ($Enabled -eq $true -or $Enabled -eq "true") {
                [void]$ActiveList.Add($Fqdn)
            }
        }
    }
    return $ActiveList
}

# Export core module members cleanly
Export-ModuleMember -Function Invoke-StigRemediation, Get-ActiveTargets