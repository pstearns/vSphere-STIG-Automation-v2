<#
.SYNOPSIS
    Pre-flight check to verify and enforce /bin/bash as the root shell on a VCSA.
.DESCRIPTION
    Logs into the VCSA via SSH to check if /bin/bash is the default shell.
    If the current shell is /bin/appliancesh, it programmatically enables the 
    shell and sets /bin/bash as the default shell for subsequent logins.
.PARAMETER FQDN
    The Fully Qualified Domain Name or IP address of the target vCenter Server Appliance.
.PARAMETER RootPassword
    The raw plain-text root password of the target VCSA.
#>
function Set-VCSABashShell {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "The FQDN or IP of the target VCSA.")]
        [string]$FQDN,

        [Parameter(Mandatory = $true, HelpMessage = "The raw root password.")]
        [string]$RootPassword
    )

    Write-Host " -> Pre-Flight Check: Verifying VCSA root shell on $FQDN..." -ForegroundColor DarkGray

    # Secure Password Masking: Use SSHPASS environment variable to avoid process-table leakage
    $env:SSHPASS = $RootPassword
    $Status = $false

    # Retry configurations to handle VCSA SSH Service startup latency (SELF-HEALING)
    $MaxAttempts = 6
    $Attempt     = 1
    $DelaySec    = 5
    $CurrentShell = ""

    while ($Attempt -le $MaxAttempts) {
        try {
            Write-Host "    [Attempt $Attempt/$MaxAttempts] Polling SSH daemon on $FQDN..." -ForegroundColor DarkGray
            
            # Check SSH connection and verify authorization
            $CurrentShell = sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o ConnectionAttempts=1 root@$FQDN 'echo $SHELL' 2>&1

            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$CurrentShell)) {
                Write-Host "    [+] SSH daemon accepted connection." -ForegroundColor Green
                break
            }
        }
        catch {
            # Catch exceptions to keep pipeline from crashing during active wait cycle
        }

        Write-Host "    [-] SSH daemon not accepting connections yet. Retrying in $DelaySec seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds $DelaySec
        $Attempt++
    }

    # Final Verification after loop completes
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$CurrentShell)) {
        Write-Host "    [CRITICAL] SSH connection failed to $FQDN after $MaxAttempts attempts. Exit Code: $LASTEXITCODE. Error: $([string]$CurrentShell)" -ForegroundColor Red
        Remove-Item env:SSHPASS -ErrorAction SilentlyContinue
        return $false
    }

    try {
        # Cast to string before trimming to prevent ErrorRecord method failures
        $CurrentShell = ([string]$CurrentShell).Trim()

        if ($CurrentShell -match "/bin/bash") {
            Write-Host "    [OK] /bin/bash is already the default shell on $FQDN. No changes needed." -ForegroundColor Green
            $Status = $true
        } 
        else {
            Write-Host "    [*] Default shell is not /bin/bash (Detected: $CurrentShell). Enabling and setting..." -ForegroundColor Yellow
            
            # 2. Multi-line Payload Pipe
            $ShellPayload = @"
shell.set --enabled true
shell
chsh -s /bin/bash root
"@

            $ShellPayload | sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$FQDN *>$null
            
            # 3. Post-Execution Validation
            $PostCheck = sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$FQDN 'echo $SHELL' 2>&1
            $PostCheck = ([string]$PostCheck).Trim()

            if ($PostCheck -match "/bin/bash") {
                Write-Host "    [OK] Successfully enforced /bin/bash root shell on $FQDN." -ForegroundColor Green
                $Status = $true
            } else {
                Write-Host "    [ERROR] Failed to set /bin/bash on $FQDN. Returned: $PostCheck" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "    [CRITICAL] An unexpected error occurred during shell verification: $_" -ForegroundColor Red
    }
    finally {
        # Secure Clean up of SSHPASS from process memory
        Remove-Item env:SSHPASS -ErrorAction SilentlyContinue
    }

    return $Status
}

<#
.SYNOPSIS
    Retrieves VCSA IP and MAC addresses via the VMware REST API.
.DESCRIPTION
    Authenticates to the vCenter API using the provided Administrator credentials 
    to pull the primary interface networking details. This function is optimized 
    to return a simple custom object for pipeline enrichment without exposing credentials.
.PARAMETER FQDN
    The Fully Qualified Domain Name or IP address of the target vCenter Server Appliance.
.PARAMETER Username
    The administrator username used to authenticate to the vCenter API.
.PARAMETER Password
    The raw plain-text password for the administrator account. Handled strictly in-memory.
.OUTPUTS
    [PSCustomObject] containing IPAddress and MACAddress strings.
#>
function Get-VCSANetworkInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage="The FQDN or IP of the target VCSA.")]
        [string]$FQDN,

        [Parameter(Mandatory=$true, HelpMessage="The administrator username (e.g., administrator@vsphere.local).")]
        [string]$Username,

        [Parameter(Mandatory=$true, HelpMessage="The raw plain-text password.")]
        [string]$Password
    )

    Write-StigLog -Message "Querying VCSA API for Networking Info: $FQDN" -Severity INFO -Source "NetInfo"
    
    $AuthURL    = "https://$FQDN/api/session"
    $AuthHeader = @{ "Content-Type" = "application/json" }
    
    # --- Secure Internal Password Handling ---
    $SecurePass = ConvertTo-SecureString $Password -AsPlainText -Force
    $Creds      = New-Object System.Management.Automation.PSCredential ($Username, $SecurePass)

    try {
        # 1. Authenticate to the API to get the session token
        $authToken = Invoke-RestMethod -Uri $AuthURL -Method Post -Headers $AuthHeader -Credential $Creds -SkipCertificateCheck
        $apiHeader = @{ "vmware-api-session-id" = $authToken }
        
        # 2. Query the networking endpoint using the session token
        $netResponse = Invoke-RestMethod -Uri "https://$FQDN/rest/appliance/networking" -Headers $apiHeader -Method Get -SkipCertificateCheck
        
        # 3. Extract and return the primary interface details
        if ($netResponse -and $netResponse.value.interfaces) {
            Write-StigLog -Message "Successfully retrieved networking info for $FQDN" -Severity SUCCESS -Source "NetInfo"
            return [PSCustomObject]@{
                IPAddress  = $netResponse.value.interfaces[0].value.ipv4.address
                MACAddress = $netResponse.value.interfaces[0].value.mac
            }
        }
    }
    catch {
        Write-StigLog -Message "Failed to retrieve VCSA networking info for $FQDN. Error: $($_.Exception.Message)" -Severity WARN -Source "NetInfo"
    }

    # Fallback if API fails (Ensures downstream pipeline execution doesn't crash)
    return [PSCustomObject]@{ IPAddress = ""; MACAddress = "" }
}

<#
.SYNOPSIS
    Enables or disables SSH on the VCSA via the REST API.
.DESCRIPTION
    Authenticates to the vCenter API using the provided Administrator credentials 
    to toggle the SSH service state with a built-in retry block to handle temporary API timeouts.
#>
function Set-VCSASshState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$FQDN,
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string]$Password,
        [Parameter(Mandatory=$true)][bool]$Enabled
    )

    $StateStr = if ($Enabled) { "Enabling" } else { "Disabling" }
    Write-StigLog -Message "$StateStr SSH on VCSA: $FQDN" -Severity INFO -Source "SSHControl"
    
    $AuthURL    = "https://$FQDN/api/session"
    $AuthHeader = @{ "Content-Type" = "application/json" }
    
    $SecurePass = ConvertTo-SecureString $Password -AsPlainText -Force
    $Creds      = New-Object System.Management.Automation.PSCredential ($Username, $SecurePass)

    # API Retry Configurations (SELF-HEALING)
    $MaxApiAttempts = 3
    $ApiAttempt     = 1
    $ApiDelaySec    = 5
    $ApiSuccess     = $false

    while ($ApiAttempt -le $MaxApiAttempts) {
        try {
            if ($ApiAttempt -gt 1) {
                Write-StigLog -Message "[$FQDN] API Retry Attempt $ApiAttempt/$MaxApiAttempts to set SSH state..." -Severity WARN -Source "SSHControl"
            }

            # 1. Authenticate to the API to get the session token
            $authToken = Invoke-RestMethod -Uri $AuthURL -Method Post -Headers $AuthHeader -Credential $Creds -SkipCertificateCheck -TimeoutSec 10
            $apiHeader = @{ "vmware-api-session-id" = $authToken; "Content-Type" = "application/json" }
            
            $body = @{ enabled = $Enabled } | ConvertTo-Json
            
            # 2. Query the SSH toggle endpoint
            Invoke-RestMethod -Uri "https://$FQDN/api/appliance/access/ssh" -Headers $apiHeader -Method Put -Body $body -SkipCertificateCheck -TimeoutSec 10 | Out-Null
            
            Write-StigLog -Message "SSH successfully set to $Enabled on $FQDN" -Severity SUCCESS -Source "SSHControl"
            $ApiSuccess = $true
            break
        }
        catch {
            Write-StigLog -Message "[$FQDN] API Attempt $ApiAttempt failed: $($_.Exception.Message)" -Severity WARN -Source "SSHControl"
            Start-Sleep -Seconds $ApiDelaySec
            $ApiAttempt++
        }
    }

    if (-not $ApiSuccess) {
        Write-StigLog -Message "Failed to set SSH state on $FQDN after $MaxApiAttempts attempts." -Severity ERROR -Source "SSHControl"
        throw "CRITICAL: Failed to modify VCSA SSH state via REST API."
    }
}

<#
.SYNOPSIS
    Dual-write PAM / password-quality files to the VCSA persistence location.
.DESCRIPTION
    After the official Photon STIG role has updated the live PAM files, this
    function mirrors the relevant files into /etc/applmgmt/appliance so the
    settings survive reboot and appliance management operations.
    Completely untagged – does not interfere with the Rule_Ver → InSpec workflow.
.PARAMETER FQDN
    The FQDN or IP of the target VCSA.
.PARAMETER RootPassword
    The raw plain-text root password.
.OUTPUTS
    [bool] $true if the dual-write completed successfully, $false otherwise.
#>
# Controls that require dual-write to /etc/applmgmt/appliance on VCSA
$script:VcsaApplmgmtControls = @(
    'PHTN-40-000004',   # faillock.conf (deny / fail_interval)
    'PHTN-40-000035',   # ucredit
    'PHTN-40-000036',   # lcredit
    'PHTN-40-000037',   # dcredit
    'PHTN-40-000038',   # difok
    'PHTN-40-000043',   # pam_pwhistory remember
    'PHTN-40-000044',   # minlen
    'PHTN-40-000086',   # ocredit
    'PHTN-40-000108',   # faillock unlock_time
    'PHTN-40-000184',   # dictcheck
    'PHTN-40-000192',   # pam_faillock in system-auth / system-account
    'PHTN-40-000193',   # faillock silent
    'PHTN-40-000194',   # faillock audit
    'PHTN-40-000195',   # faillock even_deny_root
    'PHTN-40-000196',   # faillock dir
    'PHTN-40-000197',   # pam_pwquality.so module
    'PHTN-40-000206',   # pam_faildelay
    'PHTN-40-000235',   # enforce_for_root
    'PHTN-40-000243',   # pam_pwhistory.so module
    'PHTN-40-000247'    # remove nullok
)

function Get-VcsaApplmgmtControls {
    return $script:VcsaApplmgmtControls
}

function Set-VCSAPamPersist {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FQDN,

        [Parameter(Mandatory = $true)]
        [string]$RootPassword
    )

    Write-StigLog -Message "[$FQDN] Starting VCSA PAM persistence dual-write..." -Severity INFO -Source "PamPersist"

    $env:SSHPASS = $RootPassword
    $Success = $false

    # All files that the Photon STIG role can modify for the controls above
    $FilesToMirror = @(
        @{ Src = "/etc/pam.d/system-password";    Dest = "/etc/applmgmt/appliance/system-password" },
        @{ Src = "/etc/pam.d/system-auth";        Dest = "/etc/applmgmt/appliance/system-auth" },
        @{ Src = "/etc/pam.d/system-account";     Dest = "/etc/applmgmt/appliance/system-account" },
        @{ Src = "/etc/security/pwquality.conf";  Dest = "/etc/applmgmt/appliance/pwquality.conf" },
        @{ Src = "/etc/security/pwhistory.conf";  Dest = "/etc/applmgmt/appliance/pwhistory.conf" },
        @{ Src = "/etc/security/faillock.conf";   Dest = "/etc/applmgmt/appliance/faillock.conf" }   # ← added
    )

    try {
        # 1. Ensure the persistence directory exists
        $MkdirCmd = "mkdir -p /etc/applmgmt/appliance && chmod 755 /etc/applmgmt/appliance && chown root:root /etc/applmgmt/appliance"
        $null = sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 root@$FQDN $MkdirCmd 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-StigLog -Message "[$FQDN] Failed to create /etc/applmgmt/appliance" -Severity ERROR -Source "PamPersist"
            return $false
        }

        # 2. Mirror each file that exists on the live system
        foreach ($File in $FilesToMirror) {
            $CopyCmd = @"
if [ -f '$($File.Src)' ]; then
    cp -f '$($File.Src)' '$($File.Dest)'
    chmod 644 '$($File.Dest)'
    chown root:root '$($File.Dest)'
    echo "COPIED:$($File.Src)"
else
    echo "SKIPPED:$($File.Src)"
fi
"@

            $Result = sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 root@$FQDN $CopyCmd 2>&1
            $Result = [string]$Result

            if ($Result -match "COPIED:") {
                Write-StigLog -Message "[$FQDN] Dual-wrote $($File.Src) → $($File.Dest)" -Severity SUCCESS -Source "PamPersist"
            }
            elseif ($Result -match "SKIPPED:") {
                Write-StigLog -Message "[$FQDN] Skipped $($File.Src) (does not exist on live system)" -Severity INFO -Source "PamPersist"
            }
            else {
                Write-StigLog -Message "[$FQDN] Unexpected result while copying $($File.Src): $Result" -Severity WARN -Source "PamPersist"
            }
        }

        $Success = $true
        Write-StigLog -Message "[$FQDN] PAM persistence dual-write completed." -Severity SUCCESS -Source "PamPersist"
    }
    catch {
        Write-StigLog -Message "[$FQDN] Exception during PAM dual-write: $_" -Severity ERROR -Source "PamPersist"
        $Success = $false
    }
    finally {
        Remove-Item env:SSHPASS -ErrorAction SilentlyContinue
    }

    return $Success
}

Export-ModuleMember -Function Set-VCSABashShell, Get-VCSANetworkInfo, Set-VCSASshState, Set-VCSAPamPersist, Get-VcsaApplmgmtControls