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

    try {
        # 1. Native SSH Call to check current default shell
        $CurrentShell = sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 root@$FQDN 'echo $SHELL' 2>&1

        # Check for SSH Connection / Authentication Failures (Force cast to string to handle ErrorRecords)
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$CurrentShell)) {
            Write-Host "    [CRITICAL] SSH connection failed to $FQDN. Exit Code: $LASTEXITCODE. Error: $([string]$CurrentShell)" -ForegroundColor Red
            return $false
        }

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
    # Convert the raw plain-text password to a SecureString strictly within protected RAM.
    # This prevents the password from leaking into transcript logs while allowing 
    # the creation of a PSCredential object required by Invoke-RestMethod.
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
    to toggle the SSH service state without requiring heavy PowerCLI modules.
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

    try {
        $authToken = Invoke-RestMethod -Uri $AuthURL -Method Post -Headers $AuthHeader -Credential $Creds -SkipCertificateCheck
        $apiHeader = @{ "vmware-api-session-id" = $authToken; "Content-Type" = "application/json" }
        
        $body = @{ enabled = $Enabled } | ConvertTo-Json
        
        # vCenter 7/8 API endpoint for SSH access
        Invoke-RestMethod -Uri "https://$FQDN/api/appliance/access/ssh" -Headers $apiHeader -Method Put -Body $body -SkipCertificateCheck | Out-Null
        
        Write-StigLog -Message "SSH successfully set to $Enabled on $FQDN" -Severity SUCCESS -Source "SSHControl"
    }
    catch {
        Write-StigLog -Message "Failed to set SSH state on $FQDN. Error: $($_.Exception.Message)" -Severity ERROR -Source "SSHControl"
    }
}

Export-ModuleMember -Function Set-VCSABashShell, Get-VCSANetworkInfo, Set-VCSASshState