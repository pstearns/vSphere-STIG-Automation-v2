# =========================================================================
# MODULE: Format-NetAppChecklist.psm1
# DESCRIPTION: Converts NetApp InSpec JSON to DISA .ckl using official template
#              (VMware-style merge workflow)
# =========================================================================

function Format-NetAppChecklist {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$AuditResult,

        [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
    )

    begin {
        Write-StigLog -Message "Starting NetApp checklist generation (template merge)..." -Severity INFO -Source "NetAppChecklist"
    }

    process {
        if (-not $AuditResult.RawJsonFile -or -not (Test-Path $AuditResult.RawJsonFile)) {
            Write-StigLog -Message "No valid JSON file found for $($AuditResult.TargetName). Skipping." -Severity WARN -Source "NetAppChecklist"
            return
        }

        $targetName = $AuditResult.TargetName
        $shortName  = $AuditResult.ShortName
        $dateStr    = $AuditResult.DateStr
        $jsonFile   = $AuditResult.RawJsonFile
        $reportDir  = $AuditResult.ReportDir

        # === Step 1: Generate findings checklist ===
        $tempCkl = Join-Path $reportDir "$shortName`_NetApp_Findings_$dateStr.ckl"

        Write-StigLog -Message "Converting InSpec JSON to findings checklist for $targetName..." -Severity INFO -Source "NetAppChecklist"

        try {
            $convertCmd = "saf convert hdf2ckl -i `"$jsonFile`" -o `"$tempCkl`""
            $null = bash -c $convertCmd 2>&1

            if (-not (Test-Path $tempCkl)) {
                Write-StigLog -Message "saf convert failed for $targetName" -Severity ERROR -Source "NetAppChecklist"
                return
            }
        }
        catch {
            Write-StigLog -Message "Error during saf convert for ${targetName}: $_" -Severity ERROR -Source "NetAppChecklist"
            return
        }

        # === Step 2: Merge into official NetApp template ===
        $templatePath = Join-Path $OverlayRoot "templates/CKL_Templates/U_NetApp_ONTAP_DSC_9-x_V2R4/U_NetApp_ONTAP_DSC_9-x_V2R4_STIG.ckl"

        if (-not (Test-Path $templatePath)) {
            Write-StigLog -Message "NetApp template not found at $templatePath" -Severity ERROR -Source "NetAppChecklist"
            return
        }

        $finalCklName = "$shortName`_NetApp_$dateStr.ckl"
        $finalCklPath = Join-Path $reportDir $finalCklName

        Write-StigLog -Message "Merging findings into official NetApp template..." -Severity INFO -Source "NetAppChecklist"

        try {
            [xml]$templateXml = Get-Content $templatePath
            [xml]$findingsXml = Get-Content $tempCkl

            # --- Populate NetApp-specific Asset fields ---
            $asset = $templateXml.CHECKLIST.ASSET
            $asset.HOST_NAME       = $shortName
            $asset.HOST_FQDN       = $targetName
            $asset.TARGET_COMMENT  = "Automated STIG Scan - NetApp ONTAP - $dateStr"
            $asset.TECH_AREA       = "Storage"
            $asset.ASSET_TYPE      = "Computing"
            $asset.ROLE            = "None"
            $asset.MARKING         = "CUI"
            $asset.WEB_OR_DATABASE = "false"

            # === Get iSTIG node from both files ===
            $templateISTIG = $templateXml.CHECKLIST.STIGS.iSTIG
            $findingsISTIG = $findingsXml.CHECKLIST.STIGS.iSTIG

            if (-not $templateISTIG -or -not $findingsISTIG) {
                Write-StigLog -Message "Could not locate iSTIG node in template or findings file." -Severity ERROR -Source "NetAppChecklist"
                return
            }

            # Remove all existing VULN nodes from the template
            $existingVulns = $templateISTIG.SelectNodes("VULN")
            foreach ($node in $existingVulns) {
                [void]$templateISTIG.RemoveChild($node)
            }

            # Import VULN nodes from findings file and add them to template
            $findingsVulns = $findingsISTIG.SelectNodes("VULN")
            if ($findingsVulns.Count -gt 0) {
                foreach ($vulnNode in $findingsVulns) {
                    $importedNode = $templateXml.ImportNode($vulnNode, $true)
                    [void]$templateISTIG.AppendChild($importedNode)
                }
                Write-StigLog -Message "Merged $($findingsVulns.Count) findings into template." -Severity INFO -Source "NetAppChecklist"
            } else {
                Write-StigLog -Message "No VULN nodes found in findings file." -Severity WARN -Source "NetAppChecklist"
            }

            # Save the final merged checklist
            $templateXml.Save($finalCklPath)

            Write-StigLog -Message "Final checklist created successfully: $finalCklPath" -Severity SUCCESS -Source "NetAppChecklist"

            [PSCustomObject]@{
                TargetName    = $targetName
                TargetType    = "NetApp"
                DisaComponent = "NetApp ONTAP"
                ShortName     = $shortName
                DateStr       = $dateStr
                CklFile       = $finalCklPath
                JsonFile      = $jsonFile
                ReportDir     = $reportDir
                Status        = "Checklist Generated"
            }
        }
        catch {
            Write-StigLog -Message "Error during template merge for ${targetName}: $_" -Severity ERROR -Source "NetAppChecklist"
        }
        finally {
            if (Test-Path $tempCkl) { Remove-Item $tempCkl -Force -ErrorAction SilentlyContinue }
        }
    }

    end {
        Write-StigLog -Message "NetApp checklist generation completed." -Severity INFO -Source "NetAppChecklist"
    }
}

Export-ModuleMember -Function Format-NetAppChecklist