# =========================================================================
# MODULE: EsxiRemediationFunctions.psm1
# DESCRIPTION: Core ESXi PowerCLI & Script STIG remediation definitions.
#              Defaults imported directly for VMware structure preservation.
#              Fully covers manual checks & throws safely.
# =========================================================================

<#
.SYNOPSIS
    Builds the unified $stigsettings hashtable by combining VMware static 
    defaults with dynamic variables from inputs.yml.
.EXAMPLE
    $DynamicInputs = Get-Content "inputs.yml" | ConvertFrom-Yaml
    $stigsettings = New-StigSettingsPayload -DynamicInputs $DynamicInputs
#>
Function New-StigSettingsPayload {
    param(
        [Parameter(Mandatory=$true)]
        [object]$DynamicInputs
    )

    $welcomeBanner = @"
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{hostname} , {ip}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{esxproduct} {esxversion}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{memory} RAM{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:white}  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By    {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  using this IS (which includes any device attached to this IS), you consent to the following conditions:         {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited   {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law    {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      enforcement (LE), and counterintelligence (CI) investigations.                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     At any time, the USG may inspect and seize data stored on this IS.                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     Communications using, or data stored on, this IS are not private, are subject to routine monitoring,      {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      interception, and search, and may be disclosed or used for any USG-authorized purpose.              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not   {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      for your personal benefit or privacy.                                       {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      or monitoring of the content of privileged communications, or work product, related to personal representation  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work     {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      product are private and confidential. See User Agreement for details.                       {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
{bgcolor:black} {/color}{align:left}{bgcolor:dark-grey}{color:white}  <F2> Accept Conditions and Customize System / View Logs{/align}{align:right}<F12> Accept Conditions and Shut Down/Restart  {bgcolor:black} {/color}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                        {/color}{/bgcolor}
"@

    $DefaultStigValues = [ordered]@{
        accountLockFailures     = @{"Security.AccountLockFailures" = "3"} #ESXI-80-000005
        lockdownlevel           = "lockdownNormal"  #ESXI-80-000008
        hostClientTimeout       = @{"UserVars.HostClientSessionTimeout" = "900"} #ESXI-80-000010
        logLevel                = @{"Config.HostAgent.log.level" = "info"} #ESXI-80-000015
        passwordComplexity      = @{"Security.PasswordQualityControl" = "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"} #ESXI-80-000035
        passwordHistory         = @{"Security.PasswordHistory" = "5"} #ESXI-80-000043
        enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = $false} #ESXI-80-000047
        sshIgnorerhosts         = @{"ignorerhosts" = "yes"} #ESXI-80-000052
        shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "900"} #ESXI-80-000068
        accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"} #ESXI-80-000111
        auditRecordStorageCap   = @{"Syslog.global.auditRecord.storageCapacity" = "100"} #ESXI-80-000113
        vibacceptlevel          = "PartnerSupported"  #ESXI-80-000133
        sslProtocols            = @{"UserVars.SSLSUITE" = "tls1.2,tls1.3"} #ESXI-80-000161
        sshCiphers              = @{"ciphers" = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"} #ESXI-80-000192
        sshBanner               = @{"banner" = "/etc/issue"} #ESXI-80-000187
        DCUIAccess              = @{"DCUI.Access" = "root"}  #ESXI-80-000189
        sshEnabled              = $false #ESXI-80-000193
        shellEnabled            = $false #ESXI-80-000194
        shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "600"} #ESXI-80-000195
        DCUITimeout             = @{"UserVars.DcuiTimeOut" = "600"} #ESXI-80-000196
        sshHostbasedauth        = @{"hostbasedauthentication" = "no"} #ESXI-80-000202
        sshPermituserenv        = @{"permituserenvironment" = "no"} #ESXI-80-000204
        sshGatewayports         = @{"gatewayports" = "no"} #ESXI-80-000207
        sshPermittunnel         = @{"permittunnel" = "no"} #ESXI-80-000209
        sshClientalivecountmax  = @{"clientalivecountmax" = "3"} #ESXI-80-000210
        sshClientaliveinterval  = @{"clientaliveinterval" = "200"} #ESXI-80-000211
        ShareForceSalting       = @{"Mem.ShareForceSalting" = "2"} #ESXI-80-000213
        BlockGuestBPDU          = @{"Net.BlockGuestBPDU" = "1"} #ESXI-80-000215
        DVFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress" = ""} #ESXI-80-000219
        suppressShellWarning    = @{"UserVars.SuppressShellWarning" = "0"} #ESXI-80-000222
        suppressHyperWarning    = @{"UserVars.SuppressHyperthreadWarning" = "0"} #ESXI-80-000223
        syslogCertCheck         = @{"Syslog.global.certificate.checkSSLCerts" = "true"} #ESXI-80-000224
        memEagerZero            = @{"Mem.MemEagerZero" = "1"} #ESXI-80-000225
        apiTimeout              = @{"Config.HostAgent.vmacore.soap.sessionTimeout" = "30"} #ESXI-80-000226
        passwordMaxAge          = @{"Security.PasswordMaxDays" = "90"} #ESXI-80-000227
        sshAllowtcpforwarding   = @{"allowtcpforwarding" = "no"} #ESXI-80-000230
        syslogAuditEnable       = @{"Syslog.global.auditRecord.storageEnable" = $true} #ESXI-80-000232
        syslogAuditRemote       = @{"Syslog.global.auditRecord.remoteEnable" = $true} #ESXI-80-000233
        syslogCertStrict        = @{"Syslog.global.certificate.strictX509Compliance" = $true} #ESXI-80-000234
        syslogLogLevel          = @{"Syslog.global.logLevel" = "info"} #ESXI-80-000235
        executeVibs             = @{"VMkernel.Boot.execInstalledOnly" = "true"} #ESXI-80-000244

        ##### Environment Specific STIG Values (Injected dynamically from inputs.yml) #####
        esxiLatestBuild         = $DynamicInputs.esxiBuildNumber #ESXI-80-000221
        syslogHost              = @{"Syslog.global.logHost" = $DynamicInputs.syslogServer} #ESXI-80-000114
        ntpServers              = $DynamicInputs.esxiNtpServers #ESXI-80-000124
        allowedips              = $DynamicInputs.allowedIPs  #ESXI-80-000239
        esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = $DynamicInputs.adAdminGroup} #ESXI-80-000241
        syslogScratch           = @{"Syslog.global.logDir" = $DynamicInputs.Scratch} #ESXI-80-000243
        tlsServerProfile        = "NIST_2024" #ESXI-80-000247
        bmcNetworkEnable        = @{"Net.BMCNetworkEnable" = 0} #ESXI-80-000250
        cimEnabled              = if ($DynamicInputs.cimEnabled -eq 'true') { $true } else { $false } #ESXI-80-000228
        slpdEnabled             = if ($DynamicInputs.slpdEnabled -eq 'true') { $true } else { $false } #ESXI-80-000231
        exceptionUsers          = $DynamicInputs.exceptionUsers
        domainName              = $DynamicInputs.domainName #ESXI-80-000049
        
        issueBanner             = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
        welcomeBanner           = $welcomeBanner
    }

    return $DefaultStigValues
}

# --- Internal Logging ---
if (-not (Get-Command -Name Write-StigLog -ErrorAction SilentlyContinue)) {
    function Write-StigLog {
        param([string]$Message, [string]$Severity = "INFO", [string]$Source = "EsxiRemediation")
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $color = switch ($Severity.ToUpper()) { "WARN"{"Yellow"} "ERROR"{"Red"} "SUCCESS"{"Green"} default{"Cyan"} }
        Write-Host "[$timestamp] [$Severity] $Message" -ForegroundColor $color
    }
}

Function AdvancedSettingSTIG ($vmhost, $settingName, $value) {
    if ([string]::IsNullOrWhiteSpace($settingName)) { return }
    if ($asetting = Get-AdvancedSetting -Entity $vmhost -Name $settingName -ErrorAction SilentlyContinue) {
        if ([string]$asetting.value -eq [string]$value) {
            Write-StigLog -Message "...Setting '$settingName' is correctly set to '$value' on $($vmhost.Name)"
        } else {
            Write-StigLog -Message "...Setting '$settingName' was '$($asetting.value)' on $($vmhost.Name)...updating to '$value'" -Severity WARN
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false | Out-Null
        }
    } else {
        Write-StigLog -Message "...Setting '$settingName' not found on $($vmhost.Name)...creating setting with '$value'"
        New-AdvancedSetting -Entity $vmhost -Name $settingName -Value $value -Confirm:$false | Out-Null
    }
}

# =========================================================================
# REGION: PowerCLI Advanced Settings Remediations
# =========================================================================

Function ESXI-80-000005($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.accountLockFailures.Keys)
    $value = [string]($stigsettings.accountLockFailures.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000006($vmhost, $stigsettings) {
    $name  = "Annotations.WelcomeMessage"
    $value = $stigsettings.welcomeBanner
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000010($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.hostClientTimeout.Keys)
    $value = [string]($stigsettings.hostClientTimeout.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000015($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.logLevel.Keys)
    $value = [string]($stigsettings.logLevel.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000035($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.passwordComplexity.Keys)
    $value = [string]($stigsettings.passwordComplexity.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000043($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.passwordHistory.Keys)
    $value = [string]($stigsettings.passwordHistory.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000047($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.enableMob.Keys)
    $value = [string]($stigsettings.enableMob.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000068($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.shellIntTimeout.Keys)
    $value = [string]($stigsettings.shellIntTimeout.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000111($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.accountUnlockTime.Keys)
    $value = [string]($stigsettings.accountUnlockTime.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000113($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.auditRecordStorageCap.Keys)
    $value = [string]($stigsettings.auditRecordStorageCap.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000114($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.syslogHost.Keys)
    $value = [string]($stigsettings.syslogHost.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000189($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.DCUIAccess.Keys)
    $value = [string]($stigsettings.DCUIAccess.Values)
    AdvancedSettingSTIG $vmhost $name $value
} 

Function ESXI-80-000191($vmhost, $stigsettings) {
    $name  = "Config.Etc.issue"
    $value = $stigsettings.issueBanner
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000195($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.shellTimeout.Keys)
    $value = [string]($stigsettings.shellTimeout.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000196($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.DCUITimeout.Keys)
    $value = [string]($stigsettings.DCUITimeout.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000213($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.ShareForceSalting.Keys)
    $value = [string]($stigsettings.ShareForceSalting.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000215($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.BlockGuestBPDU.Keys)
    $value = [string]($stigsettings.BlockGuestBPDU.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000219($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.DVFilterBindIpAddress.Keys)
    $value = [string]($stigsettings.DVFilterBindIpAddress.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000161($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sslProtocols.Keys)
    $value = [string]($stigsettings.sslProtocols.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000222($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.suppressShellWarning.Keys)
    $value = [string]($stigsettings.suppressShellWarning.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000223($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.suppressHyperWarning.Keys)
    $value = [string]($stigsettings.suppressHyperWarning.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000224($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.syslogCertCheck.Keys)
    $value = [string]($stigsettings.syslogCertCheck.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000225($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.memEagerZero.Keys)
    $value = [string]($stigsettings.memEagerZero.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000226($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.apiTimeout.Keys)
    $value = [string]($stigsettings.apiTimeout.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000227($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.passwordMaxAge.Keys)
    $value = [string]($stigsettings.passwordMaxAge.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000232($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.syslogAuditEnable.Keys)
    $value = [string]($stigsettings.syslogAuditEnable.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000233($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.syslogAuditRemote.Keys)
    $value = [string]($stigsettings.syslogAuditRemote.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000234($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.syslogCertStrict.Keys)
    $value = [string]($stigsettings.syslogCertStrict.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000235($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.syslogLogLevel.Keys)
    $value = [string]($stigsettings.syslogLogLevel.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000241($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.esxAdminsGroup.Keys)
    $value = [string]($stigsettings.esxAdminsGroup.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000243($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.syslogScratch.Keys)
    $value = [string]($stigsettings.syslogScratch.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000244($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.executeVibs.Keys)
    $value = [string]($stigsettings.executeVibs.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

Function ESXI-80-000250($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.bmcNetworkEnable.Keys)
    $value = [string]($stigsettings.bmcNetworkEnable.Values)
    AdvancedSettingSTIG $vmhost $name $value
}

# =========================================================================
# REGION: EsxCli & Services Remediations
# =========================================================================

Function ESXI-80-000014($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.security.fips140.ssh.get.invoke()
    if ($results.enable -eq "true" -or $results.enable -eq $true) {
        Write-StigLog -Message "...FIPS140 for SSH is already enabled on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Enabling FIPS140 for SSH on $($vmhost.name)..." -Severity WARN
        $arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs()
        $arguments.enable = $true
        $esxcli.system.security.fips140.ssh.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000052($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshIgnorerhosts.Keys)
    $value = [string]($stigsettings.sshIgnorerhosts.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000085($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.settings.encryption.get.invoke()
    if ($results.RequireSecureBoot -eq "true" -or $results.RequireSecureBoot -eq $true) {
        Write-StigLog -Message "...Secure Boot required set correctly on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring Secure Boot requirement on $($vmhost.name)" -Severity WARN
        $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
        $arguments.requiresecureboot = $true
        $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000133($vmhost, $stigsettings) {
    $value = $stigsettings.vibacceptlevel
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.software.acceptance.get.Invoke()
    if ($results -eq $value) {
        Write-StigLog -Message "...VIB Acceptance level is set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring VIB Acceptance level to $value on $($vmhost.name)..." -Severity WARN
        $arguments = $esxcli.software.acceptance.set.CreateArgs()
        $arguments.level = $value
        $esxcli.software.acceptance.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000187($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshCiphers.Keys)
    $value = [string]($stigsettings.sshCiphers.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000192($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshBanner.Keys)
    $value = [string]($stigsettings.sshBanner.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000201($vmhost, $stigsettings) {
    $vmhostv = $vmhost | Get-View
    $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
    $currentExceptions = @($lockdown.QueryLockdownExceptions())
    $targetUsers = @($stigsettings.exceptionUsers)

    foreach ($user in $targetUsers) {
        if ($currentExceptions -contains $user) {
            Write-StigLog -Message "...Lockdown exception list contains: $user" 
        } else {
            Write-StigLog -Message "...Adding exception user: $user..." -Severity WARN
            $lockdown.UpdateLockdownExceptions($user) | Out-Null
        }
    }
}

Function ESXI-80-000202($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshHostbasedauth.Keys)
    $value = [string]($stigsettings.sshHostbasedauth.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000204($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshPermituserenv.Keys)
    $value = [string]($stigsettings.sshPermituserenv.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000207($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshGatewayports.Keys)
    $value = [string]($stigsettings.sshGatewayports.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000209($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshPermittunnel.Keys)
    $value = [string]($stigsettings.sshPermittunnel.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000210($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshClientalivecountmax.Keys)
    $value = [string]($stigsettings.sshClientalivecountmax.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000211($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshClientaliveinterval.Keys)
    $value = [string]($stigsettings.sshClientaliveinterval.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000212($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.snmp.get.Invoke()
    if ($results.enable -eq "false" -or $results.enable -eq $false) {
        Write-StigLog -Message "...SNMP is disabled correctly on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Disabling SNMP on $($vmhost.name)..." -Severity WARN
        $arguments = $esxcli.system.snmp.set.CreateArgs()
        $arguments.enable = $false
        $esxcli.system.snmp.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000214($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.network.firewall.get.invoke()
    if ($results.DefaultAction -ne "DROP" -or $results.Enabled -ne "true") {
        Write-StigLog -Message "...Default firewall policy not DROP on $($vmhost.name)...configuring." -Severity WARN
        $fwargs = $esxcli.network.firewall.set.CreateArgs()
        $fwargs.enabled = $true
        $fwargs.defaultaction = $false
        $esxcli.network.firewall.set.Invoke($fwargs) | Out-Null
    } else {
        Write-StigLog -Message "...Default firewall policy drops traffic cleanly." 
    }
}

Function ESXI-80-000230($vmhost, $stigsettings) {
    $name  = [string]($stigsettings.sshAllowtcpforwarding.Keys)
    $value = [string]($stigsettings.sshAllowtcpforwarding.Values)
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    if ($results -eq $value) {
        Write-StigLog -Message "...SSH $name set correctly to $results on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring SSH $name on $($vmhost.name) to $value" -Severity WARN
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs) | Out-Null
    }
}

Function ESXI-80-000238($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.settings.encryption.get.invoke()
    if ($results.Mode -eq "TPM") {
        Write-StigLog -Message "...TPM configuration encryption already required on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring TPM encryption mode..." -Severity WARN
        $encargs = $esxcli.system.settings.encryption.set.CreateArgs()
        $encargs.mode = "TPM"
        $esxcli.system.settings.encryption.set.Invoke($encargs) | Out-Null
    }
}

Function ESXI-80-000245($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "disableHwrng"} | Select-Object -ExpandProperty Configured
    if ($results -eq "FALSE") {
        Write-StigLog -Message "...disableHwrng set correctly on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring disableHwrng on $($vmhost.name)" -Severity WARN
        $enthwargs = $esxcli.system.settings.kernel.set.CreateArgs()
        $enthwargs.setting = "disableHwrng"
        $enthwargs.value = "FALSE"
        $esxcli.system.settings.kernel.set.invoke($enthwargs) | Out-Null
    }
}

Function ESXI-80-000246($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.syslog.config.logfilter.get.invoke() | Select-Object -ExpandProperty LogFilteringEnabled
    if ($results -eq $false -or [string]$results -eq "false") {
        Write-StigLog -Message "...log filtering disabled correctly on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring log filtering on $($vmhost.name)" -Severity WARN
        $lfargs = $esxcli.system.syslog.config.logfilter.set.CreateArgs()
        $lfargs.logfilteringenabled = $false
        $esxcli.system.syslog.config.logfilter.set.invoke($lfargs) | Out-Null
    }
}

Function ESXI-80-000247($vmhost, $stigsettings) {
    $value = $stigsettings.tlsServerProfile
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $tlscheckargs = $esxcli.system.tls.server.get.CreateArgs()
    $tlscheckargs.showprofiledefaults = $true
    $tlscheckargs.showcurrentbootprofile = $true
    $results = $esxcli.system.tls.server.get.invoke($tlscheckargs) | Select-Object -ExpandProperty Profile
    if ($results -eq $value) {
        Write-StigLog -Message "...TLS server profile set correctly on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring TLS server profile to $value on $($vmhost.name)" -Severity WARN
        $tlsargs = $esxcli.system.tls.server.set.CreateArgs()
        $tlsargs.profile = $value
        $esxcli.system.tls.server.set.invoke($tlsargs) | Out-Null
    }
}

Function ESXI-80-000248($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.security.keypersistence.get.invoke() | Select-Object -ExpandProperty Enabled
    if ($results -eq $false -or [string]$results -eq "false") {
        Write-StigLog -Message "...key persistence disabled correctly on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring key persistence on $($vmhost.name)" -Severity WARN
        $kpargs = $esxcli.system.security.keypersistence.disable.CreateArgs()
        $kpargs.removeallstoredkeys = $true
        $esxcli.system.security.keypersistence.disable.invoke($kpargs) | Out-Null
    }
}

Function ESXI-80-000249($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'} | Select-Object -ExpandProperty Shellaccess
    if ($results -eq $false -or [string]$results -eq "false") {
        Write-StigLog -Message "...dcui shell access set correctly on $($vmhost.name)" 
    } else {
        Write-StigLog -Message "...Configuring dcui shell access on $($vmhost.name)" -Severity WARN
        $dcuisaargs = $esxcli.system.account.set.CreateArgs()
        $dcuisaargs.id = "dcui"
        $dcuisaargs.shellaccess = "false"
        $esxcli.system.account.set.invoke($dcuisaargs) | Out-Null
    }
}

# --- Service Enforcement (Stop-VMHostService) ---
Function ESXI-80-000193($vmhost, $stigsettings) {
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "SSH"}
    if ($esxservice.Running -eq $true -or $esxservice.Policy -eq "on") {
        Write-StigLog -Message "...Stopping SSH Service on $($vmhost.name)..." -Severity WARN
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false | Out-Null
        $esxservice | Stop-VMHostService -Confirm:$false | Out-Null
    } else {
        Write-StigLog -Message "...SSH Service is already stopped." 
    }
}

Function ESXI-80-000194($vmhost, $stigsettings) {
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "ESXi Shell"}
    if ($esxservice.Running -eq $true -or $esxservice.Policy -eq "on") {
        Write-StigLog -Message "...Stopping ESXi Shell Service on $($vmhost.name)..." -Severity WARN
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false | Out-Null
        $esxservice | Stop-VMHostService -Confirm:$false | Out-Null
    } else {
        Write-StigLog -Message "...ESXi Shell Service is already stopped." 
    }
}

Function ESXI-80-000231($vmhost, $stigsettings) {
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "slpd"}
    if ($esxservice.Running -eq $true) {
        Write-StigLog -Message "...Stopping slpd service on $($vmhost.name)..." -Severity WARN
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false | Out-Null
        $esxservice | Stop-VMHostService -Confirm:$false | Out-Null
    } else {
        Write-StigLog -Message "...slpd Service is already stopped." 
    }
}

Function ESXI-80-000228($vmhost, $stigsettings) {
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "CIM Server"}
    if ($esxservice.Running -eq $true) {
        Write-StigLog -Message "...Stopping CIM service on $($vmhost.name)..." -Severity WARN
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false | Out-Null
        $esxservice | Stop-VMHostService -Confirm:$false | Out-Null
    } else {
        Write-StigLog -Message "...CIM Service is already stopped." 
    }
}

Function ESXI-80-000124($vmhost, $stigsettings) {
    $ntpList = @($stigsettings.ntpServers)
    $CurrentNTP = @(Get-VmHostNtpServer -VMHost $vmhost)
    if ($CurrentNTP.Count -eq 0) {
        $vmhost | Add-VmHostNtpServer -NtpServer $ntpList | Out-Null
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -policy On | Out-Null
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService | Out-Null
    } elseif (Compare-object $CurrentNTP $ntpList) {
        Write-StigLog -Message "...Setting NTP on $($vmhost.name)..." -Severity WARN
        foreach ($ntp in $CurrentNTP) {
            $vmhost | Remove-VMHostNtpServer -NtpServer $ntp -Confirm:$false -ErrorAction Stop | Out-Null
        }
        $vmhost | Add-VmHostNtpServer -NtpServer $ntpList | Out-Null
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -policy On | Out-Null
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService | Out-Null
    } else {
        Write-StigLog -Message "NTP Already Set correctly on $($vmhost.name)" 
    }
}

Function ESXI-80-000049($vmhost, $stigsettings) {
    $adJoin = Get-VMHostAuthentication -VMHost $vmhost.name 
    $domain = $stigsettings.domainName
    if ($null -eq $domain) { $domain = "niprpnp.army.mil" }
    
    if ($adJoin.domain -eq $domain) {
        Write-StigLog -Message "...$($vmhost.name) is already joined to the Domain." -Severity SUCCESS
    } else {
        Write-StigLog -Message "...Skipping Active Directory Join: automated credential prompt bypassed in modular pipeline." -Severity WARN
        throw "Manual AD Join required."
    }
}

# --- Core Host State Configuration ---
Function ESXI-80-000008($vmhost, $stigsettings) {
    $val = $stigsettings.lockdownlevel
    $vmhostv = $vmhost | Get-View 
    if ($vmhostv.config.LockdownMode -ne $val) {
        Write-StigLog -Message "...Enabling Lockdown mode with level $val on $($vmhost.name)" -Severity WARN
        $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop 
        $lockdown.ChangeLockdownMode($val) | Out-Null
    } else {
        Write-StigLog -Message "...Lockdown mode already set to $val on $($vmhost.name)" 
    }
}

Function ESXI-80-000221($vmhost, $stigsettings) {
    $build = $vmhost.ExtensionData.Config.Product.build
    $TargetBuild = $stigsettings.esxiLatestBuild
    if ([int64]$build -ge [int64]$TargetBuild) {
        Write-StigLog -Message "...ESXi build $build is up-to-date (Latest target: $TargetBuild)" 
    } else {
        Write-StigLog -Message "...ESXi build $build is outdated (Latest target: $TargetBuild). Needs patch!" -Severity ERROR
    }
}

# --- Firewall Exceptions configuration ---
Function ESXI-80-000239($vmhost, $stigsettings) {
    Write-StigLog -Message "...Remediating Firewall Exceptions Rule: ESXI-80-000239" 
    $fwsys = Get-View $vmhost.ExtensionData.ConfigManager.FirewallSystem
    $fwservices = $fwsys.FirewallInfo.Ruleset | Where-Object {
        ($_.IpListUserConfigurable -eq $true) -and ($_.Enabled -eq $true) -and ($_.AllowedHosts.AllIp -eq $true)
    }

    if (-not $fwservices) {
        Write-StigLog -Message "...ESXi Firewall Rules restrict access cleanly on $($vmhost.name)." 
        return
    }

    $newIpNetworks = @()
    foreach ($networkBlock in $stigsettings.allowedips) {
        $allowedNetwork, $prefix = $networkBlock.split('/')
        $tmp = New-Object VMware.Vim.HostFirewallRulesetIpNetwork
        $tmp.network = $allowedNetwork
        $tmp.prefixLength = [int]$prefix
        $newIpNetworks += $tmp
    }

    foreach ($service in $fwservices) {
        Write-StigLog -Message "...Configuring Firewall exceptions on service '$($service.Label)' to isolate traffic." -Severity WARN
        $rulesetSpec = New-Object VMware.Vim.HostFirewallRulesetRulesetSpec
        $rulesetSpec.allowedHosts = New-Object VMware.Vim.HostFirewallRulesetIpList
        $rulesetSpec.allowedHosts.allIp = $false
        $rulesetSpec.allowedHosts.ipNetwork = $newIpNetworks
        $fwsys.UpdateRuleset($service.Key, $rulesetSpec)
    }
}

# --- Switch & Portgroup Policies ---
Function ESXI-80-000216($vmhost, $stigsettings) {
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction SilentlyContinue
    foreach ($sw in $switches) {
        $secpol = $sw | Get-SecurityPolicy
        if ($secpol.ForgedTransmits -eq $true) {
            $secpol | Set-SecurityPolicy -ForgedTransmits $false -Confirm:$false | Out-Null
        }
    }
    $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction SilentlyContinue
    foreach ($pg in $portgroups) {
        $secpol = $pg | Get-SecurityPolicy
        if ($secpol.ForgedTransmits -eq $true) {
            $secpol | Set-SecurityPolicy -ForgedTransmitsInherited $true -Confirm:$false | Out-Null
        }
    }
}

Function ESXI-80-000217($vmhost, $stigsettings) {
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction SilentlyContinue
    foreach ($sw in $switches) {
        $secpol = $sw | Get-SecurityPolicy
        if ($secpol.MacChanges -eq $true) {
            $secpol | Set-SecurityPolicy -MacChanges $false -Confirm:$false | Out-Null
        }
    }
    $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction SilentlyContinue
    foreach ($pg in $portgroups) {
        $secpol = $pg | Get-SecurityPolicy
        if ($secpol.MacChanges -eq $true) {
            $secpol | Set-SecurityPolicy -MacChangesInherited $true -Confirm:$false | Out-Null
        }
    }
}

Function ESXI-80-000218($vmhost, $stigsettings) {
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction SilentlyContinue
    foreach ($sw in $switches) {
        $secpol = $sw | Get-SecurityPolicy
        if ($secpol.AllowPromiscuous -eq $true) {
            $secpol | Set-SecurityPolicy -AllowPromiscuous $false -Confirm:$false | Out-Null
        }
    }
    $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction SilentlyContinue
    foreach ($pg in $portgroups) {
        $secpol = $pg | Get-SecurityPolicy
        if ($secpol.AllowPromiscuous -eq $true) {
            $secpol | Set-SecurityPolicy -AllowPromiscuousInherited $true -Confirm:$false | Out-Null
        }
    }
}

Function ESXI-80-000220($vmhost, $stigsettings) {
    $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction SilentlyContinue | Where-Object {$_.VlanId -eq 4095}
    if ($portgroups) {
        foreach ($pg in $portgroups) {
            Write-StigLog -Message "V-258775 Warning: Portgroup '$($pg.Name)' is configured with VLAN 4095 (VGT). Must be evaluated manually." -Severity ERROR
        }
        throw "Manual Intervention Required"
    }
}

# --- OS & Ansible Automated Files ---
Function ESXI-80-000236($vmhost, $stigsettings) {
    Write-StigLog -Message "Manual/Ansible task [ESXI-80-000236]: stat /etc/vmware/settings must be 0. Run Ansible playbook." -Severity ERROR
    throw "Ansible playbook execution required"
}

Function ESXI-80-000237($vmhost, $stigsettings) {
    Write-StigLog -Message "Manual/Ansible task [ESXI-80-000237]: grep vmx.log in /etc/vmware/config must be empty. Run Ansible playbook." -Severity ERROR
    throw "Ansible playbook execution required"
}

# --- Manual Compliance Checkpoints ---
Function ESXI-80-000240($vmhost, $stigsettings) {
    Write-StigLog -Message "Manual eval [ESXI-80-000240]: Host Profiles and Auto Deploy must utilize Authentication Proxy." -Severity ERROR
    throw "Manual Intervention Required"
}

Function ESXI-80-000160($vmhost, $stigsettings) {
    Write-StigLog -Message "Manual eval [ESXI-80-000160]: Review VMkernel adapters and VLANs to isolate vMotion traffic." -Severity ERROR
    throw "Manual Intervention Required"
}

Function ESXI-80-000198($vmhost, $stigsettings) {
    Write-StigLog -Message "Manual eval [ESXI-80-000198]: Review VMkernel adapters to isolate management traffic." -Severity ERROR
    throw "Manual Intervention Required"
}

Function ESXI-80-000199($vmhost, $stigsettings) {
    Write-StigLog -Message "Manual eval [ESXI-80-000199]: Review VMkernel adapters to isolate IP-based storage traffic." -Severity ERROR
    throw "Manual Intervention Required"
}

Function ESXI-80-000145($vmhost, $stigsettings) {
    Write-StigLog -Message "Manual eval [ESXI-80-000145]: If iSCSI is in use, require bidirectional CHAP authentication." -Severity ERROR
    throw "Manual Intervention Required"
}

Function ESXI-80-000229($vmhost, $stigsettings) {
    Write-StigLog -Message "Manual eval [ESXI-80-000229]: Replacing VMCA host certificates with DoD-approved CA certs." -Severity ERROR
    throw "Manual Intervention Required"
}

# --- Export Commands ---
Export-ModuleMember -Function ESXI-80-*, AdvancedSettingSTIG, New-StigSettingsPayload