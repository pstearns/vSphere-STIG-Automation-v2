# =========================================================================
# MODULE: RemediationOrchestration.psm1
# DESCRIPTION: Technical STIG remediation with high-speed targeted delta
#              verification, verbose tracing, and real-time STIG Manager sync.
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

<#
.SYNOPSIS
    Orchestrates sequential VM remediation followed by targeted parallel delta verification and real-time STIG Manager uploads.
#>
function Invoke-MultiVmRemediation {
    [CmdletBinding()]
    param (
        [string]$OverlayRoot = $Script:OverlayRoot,
        [switch]$Silent,
        [string]$DateStr = (Get-Date -Format "yyyyMMdd"),
        [string]$TargetVM
    )

    $StartTime = Get-Date
    Initialize-StigLogging -LogDirectory (Join-Path $OverlayRoot "logs") -Silent:$Silent
    Write-StigLog -Message "Starting Parallel Multi-VM Targeted Remediation & Real-Time Sync..." -Severity INFO -Source "VmRemediation"

    try {
        # 1. Load active vCenter targets
        $ActiveTargets = Get-ActiveTargets -OverlayRoot $OverlayRoot
        if ($ActiveTargets.Count -eq 0) {
            Write-StigLog "No enabled vCenter targets found in global_config.yml." -Severity WARN -Source "VmRemediation"
            return
        }

        # 2. Retrieve Vault credentials
        $CredentialFile = Join-Path $OverlayRoot "conf/.creds.json.encrypted"
        $Credentials = Get-vCenterCredentialStore -FilePath $CredentialFile

        # Set historical remediation CSV path at base reports root
        $ReportsBaseDir = Join-Path $OverlayRoot "reports"
        $RemediationHistoryCsv = Join-Path $ReportsBaseDir "Remediation_History_VMs.csv"
        $RemediationHistoryList = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

        # 3. Define Master STIG-Compliant Nested Settings
        $DefaultVmSettings = [ordered]@{
            copyDisable            = @{"isolation.tools.copy.disable"           = $true}        #VMCH-80-000189
            dndDisable             = @{"isolation.tools.dnd.disable"            = $true}        #VMCH-80-000191
            pasteDisable           = @{"isolation.tools.paste.disable"          = $true}        #VMCH-80-000192
            diskShrink             = @{"isolation.tools.diskShrink.disable"     = $true}        #VMCH-80-000193
            diskWiper              = @{"isolation.tools.diskWiper.disable"      = $true}        #VMCH-80-000194
            RemoteDisplayMax       = @{"RemoteDisplay.maxConnections"           = "1"}          #VMCH-80-000195
            setinfoSizeLimit       = @{"tools.setinfo.sizeLimit"                = "1048576"}    #VMCH-80-000196
            deviceConnectable      = @{"isolation.device.connectable.disable"   = $true}        #VMCH-80-000197
            guestlibEnableHostInf  = @{"tools.guestlib.enableHostInfo"          = $false }      #VMCH-80-000198
            desktopAutolock        = @{"tools.guest.desktop.autolock"           = $true}        #VMCH-80-000201
            mksEnable3d            = @{"mks.enable3d"                           = $false}       #VMCH-80-000202
            logRotateSize          = @{"log.rotateSize"                         = "2048000"}    #VMCH-80-000205
            logKeepOld             = @{"log.keepOld"                            = "10"}         #VMCH-80-000206
            schedMemPshareSalt     = "sched.mem.pshare.salt"                                    #VMCH-80-000199
            vmotionEncryption      = "opportunistic"                                            #VMCH-80-000203
            ftEncryption           = "ftEncryptionOpportunistic"                                #VMCH-80-000204
            vmLogging              = $true                                                      #VMCH-80-000207
        }

        # 4. Process each enabled vCenter target
        foreach ($vCenterFQDN in $ActiveTargets) {
            $vCenterShortName = ($vCenterFQDN -split '\.')[0].ToUpper()
            $VmReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShortName/VMs"
            $AnswersXml = Join-Path $OverlayRoot "conf/vm/answers.xml"

            if (-not (Test-Path $VmReportPath)) {
                Write-StigLog "No VM checklists found for $vCenterShortName. Ensure the audit runs first." -Severity WARN -Source "VmRemediation"
                continue
            }

            # Retrieve targets from secure vault
            $VaultEntry = $Credentials.vCenters | Where-Object { $_.FQDN -eq $vCenterFQDN }
            if ($null -eq $VaultEntry) { continue }
            
            $CredObj = Get-vCenterCredential -FQDN $vCenterFQDN -FilePath $CredentialFile
            $AdminUser = $CredObj.AdminCred.UserName
            $AdminPass = $CredObj.AdminCred.GetNetworkCredential().Password

            $CklFiles = Get-ChildItem -Path $VmReportPath -Filter "*.ckl"
            
            # Target VM Filtering (Bypasses noise on all other VMs if parameter is set)
            if (-not [string]::IsNullOrWhiteSpace($TargetVM)) {
                $CklFiles = $CklFiles | Where-Object { $_.BaseName -match $TargetVM -or $_.Name -match $TargetVM }
                if ($CklFiles.Count -eq 0) {
                    Write-StigLog "[$vCenterShortName] No checklists found matching TargetVM '$TargetVM'. Skipping vCenter." -Severity INFO -Source "VmRemediation"
                    continue
                }
            }

            # --- PHASE 1: SEQUENTIAL REMEDIATION ---
            Write-StigLog "[$vCenterShortName] Establishing parent PowerCLI connection for remediation..." -Severity INFO -Source "VmRemediation"
            
            # Scope PowerCLI configuration to memory Session to prevent RecentServerList.xml warnings
            $WarningPreference = 'SilentlyContinue'
            Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -InvalidCertificateAction Ignore -ParticipateInCEIP $false -Confirm:$false -Scope Session | Out-Null
            
            $ParentConnection = Connect-VIServer -Server $vCenterFQDN -User $AdminUser -Password $AdminPass -Force -ErrorAction Stop

            # Load the local functions module with muted warnings
            $RemediationModule = Join-Path $OverlayRoot "modules/remediation/VmRemediationFunctions.psm1"
            Import-Module $RemediationModule -Force -DisableNameChecking -WarningAction SilentlyContinue

            $RemediatedQueue = @()

            foreach ($File in $CklFiles) {
                $XmlCkl = New-Object System.Xml.XmlDocument
                $XmlCkl.PreserveWhitespace = $true
                $XmlCkl.Load($File.FullName)

                $VMName = $XmlCkl.CHECKLIST.ASSET.HOST_NAME
                $OpenNodes = $XmlCkl.SelectNodes("/CHECKLIST/STIGS/iSTIG/VULN[STATUS='Open']")
                $FixList = [System.Collections.Generic.List[string]]::new()

                foreach ($Node in $OpenNodes) {
                    $RuleVer = ($Node.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Ver" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText
                    
                    # Extract existing finding details to support validation-code and match operations
                    $vulnFindDet = if ($Node.SelectSingleNode("FINDING_DETAILS")) { $Node.SelectSingleNode("FINDING_DETAILS").InnerXml } else { "" }
                    
                    # Invoke answer file matching using correct metadata properties to avoid false remediation runs
                    $Answer = Get-FormattedAnswer -AnswerFile $AnswersXml -vulnRuleVer $RuleVer -CurrentStatus "Open" -FindingDetailsText $vulnFindDet -AnswerKey "DEFAULT"
                    
                    if ($null -eq $Answer -or $Answer.Status -ne "NotAFinding") {
                        [void]$FixList.Add($RuleVer)
                    }
                }

                # Apply targeted fixes on this specific VM sequentially
                if ($FixList.Count -gt 0) {
                    $VmObject = Get-VM -Name $VMName -ErrorAction SilentlyContinue
                    if ($null -eq $VmObject) {
                        Write-StigLog "[$VMName] VM object could not be resolved in vCenter. Skipping." -Severity ERROR -Source "VmRemediation"
                        continue
                    }

                    $SuccessFixes = @()
                    foreach ($StigID in $FixList) {
                        try {
                            Write-StigLog " [+] Executing fix $StigID on $VMName" -Severity INFO -Source "VmRemediation"
                            & $StigID -vm $VmObject -stigsettings $DefaultVmSettings
                            $SuccessFixes += $StigID  # Store RuleVer (VMCH-...) for InSpec profile mapping

                            # Log to thread-safe collection
                            $RemediationHistoryList.Add([PSCustomObject]@{
                                Date       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                                vCenter    = $vCenterShortName
                                VM         = $VMName
                                STIGID     = $StigID
                                Status     = "Remediated"
                                Method     = "Automated PowerCLI SDK"
                            })
                        }
                        catch {
                            Write-StigLog "Failed to apply fix $StigID on $VMName. Error: $($_.Exception.Message)" -Severity ERROR -Source "VmRemediation"
                        }
                    }

                    if ($SuccessFixes.Count -gt 0) {
                        # Queue VM for parallel delta verification
                        $RemediatedQueue += [PSCustomObject]@{
                            File          = $File.FullName
                            VMName        = $VMName
                            VcenterVMName = $VmObject.Name  # Exact literal inventory name matching (e.g. FQDN)
                            FixedRules    = $SuccessFixes   # Targeted InSpec controls by Rule_Ver
                            XmlDoc        = $XmlCkl
                        }
                    }
                }
            }

            # Disconnect parent session handle cleanly
            Disconnect-VIServer -Server $ParentConnection -Confirm:$false | Out-Null

            # --- PHASE 2: PARALLEL VERIFICATION & UPLOAD (BATCH OF 40) ---
            if ($RemediatedQueue.Count -gt 0) {
                $TotalQueue = $RemediatedQueue.Count
                $BatchSize  = 40
                Write-StigLog "[$vCenterShortName] Initiating parallel verification for $TotalQueue VMs in batches of $BatchSize..." -Severity INFO -Source "VmRemediation"

                for ($i = 0; $i -lt $TotalQueue; $i += $BatchSize) {
                    $Batch = $RemediatedQueue | Select-Object -Skip $i -First $BatchSize
                    $BatchNumber = [math]::Floor($i / $BatchSize) + 1
                    $TotalBatches = [math]::Ceiling($TotalQueue / $BatchSize)

                    Write-StigLog "[$vCenterShortName] --- Verifying VM Batch $BatchNumber of $TotalBatches ---" -Severity INFO -Source "VmRemediation"

                    $Batch | ForEach-Object -Parallel {
                        $Job = $_
                        $OverlayRoot = $using:OverlayRoot
                        $vCenterFQDN = $using:vCenterFQDN
                        $AdminUser = $using:AdminUser
                        $AdminPass = $using:AdminPass
                        $vCenterShortName = $using:vCenterShortName
                        $AnswersXml = $using:AnswersXml

                        # Load global functions into this parallel runspace
                        $GlobalFuncsPath = Join-Path $OverlayRoot "modules/globalFunctions.psm1"
                        $GlobalFuncsText = Get-Content $GlobalFuncsPath -Raw
                        
                        # FIX: Use single-line modifier (?s) to truncate the export module member instruction robustly
                        $GlobalFuncsSafe = $GlobalFuncsText -replace '(?s)Export-ModuleMember.*', ''
                        Invoke-Expression $GlobalFuncsSafe

                        $StagingDir = "/tmp/remediation_staging/$($Job.VMName)"
                        if (-not (Test-Path $StagingDir)) { New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null }

                        $DeltaJson = Join-Path $StagingDir "delta_verify.json"
                        $DeltaCkl  = Join-Path $StagingDir "delta_verify.ckl"
                        
                        # Dynamically resolve decoupled DISA baseline VM profile path
                        $VsphereBasePath = "/usr/share/stigs/vsphere/8.0"
                        $ApiProfilePath = Get-ChildItem -Path $VsphereBasePath -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { 
                            $_.Name -eq "vm" -and $_.Parent.Name -match "vmware-vsphere-8.0-.*"
                        } | Select-Object -ExpandProperty FullName -First 1

                        if (-not $ApiProfilePath) {
                            $LatestStigRelease = Get-ChildItem -Path $VsphereBasePath -Directory | Where-Object { $_.Name -match "^v\d+r\d+-(srg|stig)$" } | Sort-Object Name -Descending | Select-Object -ExpandProperty Name -First 1
                            $ApiProfilePath = Join-Path $VsphereBasePath "$LatestStigRelease/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/vm"
                        }

                        $VmInputsFile = Join-Path $OverlayRoot "conf/vm/inputs.yml"
                        $InputArgString = ""
                        if (Test-Path $VmInputsFile) {
                            $InputArgString = "--input-file '$VmInputsFile'"
                        }

                        # Space-separate the array elements so they are evaluated as multiple arguments by InSpec
                        $ControlsArg = $Job.FixedRules -join " "
                        $VerifyLog = Join-Path $StagingDir "cinc_verify_run.log"

                        $ArgTrail = "exec '$ApiProfilePath' -t vmware:// --input vmName='$($Job.VcenterVMName)' --reporter json:'$DeltaJson' $InputArgString --controls $ControlsArg"
                        
                        [Console]::WriteLine("[$($Job.VMName)] -> Verifying compliance state...")

                        # Thread-Safe Direct Process Execution: Pass credentials securely to individual processes
                        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                        $ProcessInfo.FileName = "bash"
                        $ProcessInfo.Arguments = "-c `"cinc-auditor $ArgTrail 2>&1`" "
                        $ProcessInfo.UseShellExecute = $false
                        $ProcessInfo.RedirectStandardOutput = $true

                        # Safely load thread-isolated environment credentials into the process start info
                        $ProcessInfo.EnvironmentVariables["VISERVER"]          = $vCenterFQDN
                        $ProcessInfo.EnvironmentVariables["VISERVER_USERNAME"] = $AdminUser
                        $ProcessInfo.EnvironmentVariables["VISERVER_PASSWORD"] = $AdminPass

                        $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
                        $VerifyOutput = $Process.StandardOutput.ReadToEnd()
                        $Process.WaitForExit()
                        $VerifyOutput | Set-Content -Path $VerifyLog -Force

                        if (-not (Test-Path $DeltaJson)) {
                            [Console]::WriteLine("[$($Job.VMName)] ERROR: Compliance check was not generated. Log: $VerifyLog")
                        }

                        if (Test-Path $DeltaJson) {
                            bash -c "saf convert hdf2ckl -i '$DeltaJson' -o '$DeltaCkl'" | Out-Null
                            
                            if (Test-Path $DeltaCkl) {
                                $DeltaXml = New-Object System.Xml.XmlDocument
                                $DeltaXml.Load($DeltaCkl)
                                
                                $XmlCkl = $Job.XmlDoc
                                foreach ($FixedVuln in $DeltaXml.CHECKLIST.STIGS.iSTIG.VULN) {
                                    $FixedRuleVer = ($FixedVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_Ver" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText
                                    $FixedRuleID  = ($FixedVuln.SelectNodes("STIG_DATA") | Where-Object { $_.SelectSingleNode("VULN_ATTRIBUTE").InnerText -eq "Rule_ID" }).SelectSingleNode("ATTRIBUTE_DATA").InnerText
                                    
                                    # 1. Extract raw compliance status details
                                    $vulnSTATUS   = $FixedVuln.SelectSingleNode("STATUS").InnerText
                                    $vulnFindDet  = $FixedVuln.SelectSingleNode("FINDING_DETAILS").InnerXml
                                    $vulnCOMMENTS = $FixedVuln.SelectSingleNode("COMMENTS").InnerXml

                                    # 2. Intercept and apply answers.xml if a waiver/mitigation is mapped (Parenthesized to resolve test-path flag parameter bug)
                                    if ((Test-Path $AnswersXml) -and $FixedRuleVer) {
                                        $AnswerData = Get-FormattedAnswer -AnswerFile $AnswersXml -vulnRuleVer $FixedRuleVer -CurrentStatus $vulnSTATUS -FindingDetailsText $vulnFindDet -AnswerKey "DEFAULT"
                                        
                                        if ($null -ne $AnswerData -and $AnswerData.Status -ne "") {
                                            $vulnSTATUS   = $AnswerData.Status
                                            $vulnCOMMENTS = $AnswerData.Comments
                                        }
                                    }

                                    # 3. Update master CKL node with validated compliance state
                                    $MasterNode = $null
                                    if ($FixedRuleVer) {
                                        $MasterNode = $XmlCkl.SelectSingleNode("/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$FixedRuleVer']]")
                                    }
                                    if (-not $MasterNode -and $FixedRuleID) {
                                        $MasterNode = $XmlCkl.SelectSingleNode("/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$FixedRuleID']]")
                                    }

                                    if ($MasterNode) {
                                        $MasterNode.SelectSingleNode("STATUS").InnerText          = $vulnSTATUS
                                        $MasterNode.SelectSingleNode("FINDING_DETAILS").InnerXml  = $vulnFindDet
                                        $MasterNode.SelectSingleNode("COMMENTS").InnerXml         = $vulnCOMMENTS
                                        [Console]::WriteLine("[$($Job.VMName)] -> Updated Checklist: $FixedRuleVer -> Status: $vulnSTATUS")
                                    } else {
                                        [Console]::WriteLine("[$($Job.VMName)] -> WARNING: Rule $FixedRuleID ($FixedRuleVer) not found in master checklist.")
                                    }
                                }
                                $XmlCkl.Save($Job.File)
                            } else {
                                [Console]::WriteLine("[$($Job.VMName)] ERROR: Failed to convert delta json to XML CKL.")
                            }
                        }

                        # Keep the staging directory on failure for troubleshooting, delete only on success
                        if (Test-Path $DeltaJson) {
                            Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
                        } else {
                            [Console]::WriteLine("[$($Job.VMName)] Troubleshooting log preserved at: $VerifyLog")
                        }

                        # Real-Time STIG Manager Synchronization using system-wide .NET Mutex
                        $MutexName = "StigManWatcherMutex"
                        $Mutex = $null
                        try {
                            $CreatedNew = $false
                            $Mutex = New-Object System.Threading.Mutex($false, $MutexName, [ref]$CreatedNew)
                            [void]$Mutex.WaitOne()
                        }
                        catch {
                            Write-Host "[$($Job.VMName)] Warning: Failed to acquire synchronization Mutex: $($_.Exception.Message). Continuing without lock." -ForegroundColor Yellow
                        }

                        try {
                            # Copy individual CKL to Collection Inbox with dynamic remediation suffix to bypass watcher history cache
                            $InboxDir = Join-Path $OverlayRoot "stigman-watcher/inboxes/coll_6"
                            if (-not (Test-Path $InboxDir)) { New-Item -ItemType Directory -Path $InboxDir -Force | Out-Null }
                            
                            $BaseName = Split-Path $Job.File -Leaf
                            # Appends a dynamic timestamp suffix to cleanly bypass watcher history cache
                            $RemediatedFileName = $BaseName -replace '\.ckl$', "_Remediated_$((Get-Date).ToString('HHmmss')).ckl"
                            $StagedPath = Join-Path $InboxDir $RemediatedFileName
                            
                            Copy-Item -Path $Job.File -Destination $StagedPath -Force | Out-Null
                            
                            # Fire Watcher sequential upload
                            $WatcherScript = Join-Path $OverlayRoot "bin/run-stigman-watcher.sh"
                            $UploadOutput = bash -c "bash '$WatcherScript' '6'" 2>&1
                            
                            # Conditional CleanUp based on exit status to prevent storage depletion
                            if ($LASTEXITCODE -eq 0) {
                                Write-StigLog "[$($Job.VMName)] Real-time checklist upload successfully finalized." -Severity SUCCESS -Source "VmRemediation"
                                if (Test-Path $StagedPath) {
                                    Remove-Item -Path $StagedPath -Force | Out-Null
                                }
                            } else {
                                Write-StigLog "[$($Job.VMName)] STIG Manager Watcher encountered errors (Exit Code: $LASTEXITCODE). Retaining staged checklist for retry." -Severity ERROR -Source "VmRemediation"
                            }
                        }
                        finally {
                            if ($null -ne $Mutex) {
                                try {
                                    $Mutex.ReleaseMutex()
                                    $Mutex.Dispose()
                                }
                                catch {}
                            }
                        }
                    } -ThrottleLimit 40
                }
            }
            # Recompile scan summary
            Get-StigScanSummary -ReportDir $VmReportPath -AnswersXmlPath $AnswersXml
        }

        # Step 5: Append Remediation History Log
        if ($RemediationHistoryList.Count -gt 0) {
            if (-not (Test-Path $RemediationHistoryCsv)) {
                $RemediationHistoryList.ToArray() | Export-Csv -Path $RemediationHistoryCsv -NoTypeInformation -Force
            } else {
                $RemediationHistoryList.ToArray() | Export-Csv -Path $RemediationHistoryCsv -NoTypeInformation -Append -Force
            }
            Write-StigLog "Remediation history logged cleanly to: $RemediationHistoryCsv" -Severity SUCCESS -Source "VmRemediation"
        }

        Write-ElapsedTime -StartTime $StartTime -Message "Multi-VM Remediation Cycle Complete." -Source "VmRemediation"
    }
    catch {
        Write-StigLog -Message "VM Remediation Orchestrator Failed: $($_.Exception.Message)" -Severity ERROR -Source "VmRemediation"
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
            $Fqdn    = if ($t.fqdn) { $t["fqdn"] } else { $t["fqdn"] }
            $Enabled = if ($null -ne $t.enabled) { $t["enabled"] } else { $t["enabled"] }

            if ($Enabled -eq $true -or $Enabled -eq "true") {
                [void]$ActiveList.Add($Fqdn)
            }
        }
    }
    return $ActiveList
}

Export-ModuleMember -Function Invoke-MultiVmRemediation