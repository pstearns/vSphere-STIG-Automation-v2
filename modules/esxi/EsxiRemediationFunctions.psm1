# =========================================================================
# MODULE: EsxiRemediationFunctions.psm1
# DESCRIPTION: Core ESXi PowerCLI & Script STIG remediation definitions.
#              Optimized to dynamically bind unified YAML input blocks.
# =========================================================================

# Logging Proxies
Function Write-ToConsole ($Details) { Write-StigLog -Message $Details -Severity INFO -Source "Remediation" }
Function Write-ToConsoleGreen ($Details) { Write-StigLog -Message $Details -Severity SUCCESS -Source "Remediation" }
Function Write-ToConsoleYellow ($Details) { Write-StigLog -Message $Details -Severity WARN -Source "Remediation" }
Function Write-ToConsoleRed ($Details) { Write-StigLog -Message $Details -Severity ERROR -Source "Remediation" }

<#
.SYNOPSIS
    Resolves configuration parameters with safe defaults.
#>
Function Get-StigValue {
    param(
        [hashtable]$stigsettings,
        [string]$primaryKey,
        [string]$secondaryKey,
        [string]$fallbackValue
    )
    if ($null -eq $stigsettings) { return $fallbackValue }

    # 1. Nested Hashtable format (from variables.yaml)
    if ($stigsettings[$primaryKey] -is [System.Collections.IDictionary]) {
        $nested = $stigsettings[$primaryKey]
        $val = ($nested.Values | Select-Object -First 1)
        if ($null -ne $val) { return $val }
    }

    # 2. Flat Hashtable format (from inputs.yml)
    if ($null -ne $stigsettings[$primaryKey] -and [string]$stigsettings[$primaryKey] -ne "") {
        return $stigsettings[$primaryKey]
    }
    if ($null -ne $stigsettings[$secondaryKey] -and [string]$stigsettings[$secondaryKey] -ne "") {
        return $stigsettings[$secondaryKey]
    }

    return $fallbackValue
}

<#
.SYNOPSIS
    Applies an Advanced System Setting safely.
#>
Function AdvancedSettingSTIG ($vmhost, $settingName, $value) {
    if ([string]::IsNullOrWhiteSpace($settingName)) { return }
    if ($null -eq $value -or [string]$value -eq "") {
        Write-ToConsoleYellow "Warning: Value for '$settingName' is blank. Skipping."
        return
    }

    if ($asetting = Get-AdvancedSetting -Entity $vmhost -Name $settingName -ErrorAction SilentlyContinue) {
        if ([string]$asetting.value -eq [string]$value) {
            Write-ToConsoleGreen "...Setting '$settingName' is already configured correctly to '$value' on $($vmhost.name)"
        } else {
            Write-ToConsoleYellow "...Setting '$settingName' was incorrectly set to '$($asetting.value)' on $($vmhost.name)...setting to '$value'"
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false | Out-Null
        }
    } else {
        Write-ToConsoleYellow "...Setting '$settingName' does not exist on $($vmhost.name)...creating setting..."
        New-AdvancedSetting -Entity $vmhost -Name $settingName -Value $value -Confirm:$false | Out-Null
    }
}

# =========================================================================
# REGION: PowerCLI Advanced Settings Remediations
# =========================================================================

Function ESXI-80-000005($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "accountLockFailures" "account_lockout_threshold" "3"
    AdvancedSettingSTIG $vmhost "Security.AccountLockFailures" $val
}

Function ESXI-80-000006($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "AnnotationsMessage" "annotations_message" "You are accessing a U.S. Government..."
    AdvancedSettingSTIG $vmhost "Annotations.WelcomeMessage" $val
}

Function ESXI-80-000010($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "hostClientTimeout" "host_client_timeout" "900"
    AdvancedSettingSTIG $vmhost "UserVars.HostClientSessionTimeout" $val
}

Function ESXI-80-000015($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "logLevel" "log_level" "info"
    AdvancedSettingSTIG $vmhost "Config.HostAgent.log.level" $val
}

Function ESXI-80-000035($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "passwordComplexity" "password_quality_control" "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"
    AdvancedSettingSTIG $vmhost "Security.PasswordQualityControl" $val
}

Function ESXI-80-000043($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "passwordHistory" "password_history" "5"
    AdvancedSettingSTIG $vmhost "Security.PasswordHistory" $val
}

Function ESXI-80-000047($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "enableMob" "enable_mob" "false"
    AdvancedSettingSTIG $vmhost "Config.HostAgent.plugins.solo.enableMob" $val
}

Function ESXI-80-000068($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "shellIntTimeout" "shell_interactive_timeout" "900"
    AdvancedSettingSTIG $vmhost "UserVars.ESXiShellInteractiveTimeOut" $val
}

Function ESXI-80-000111($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "accountUnlockTime" "account_unlock_time" "900"
    AdvancedSettingSTIG $vmhost "Security.AccountUnlockTime" $val
}

Function ESXI-80-000113($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "auditRecordStorageCap" "audit_record_storage_capacity" "100"
    AdvancedSettingSTIG $vmhost "Syslog.global.auditRecord.storageCapacity" $val
}

Function ESXI-80-000114($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "syslogHost" "syslog_host" "tcp://huafellog2.niprpnp.army.mil:9525"
    AdvancedSettingSTIG $vmhost "Syslog.global.logHost" $val
}

Function ESXI-80-000189($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "DCUIAccess" "dcui_access" "root"
    AdvancedSettingSTIG $vmhost "DCUI.Access" $val
} 

Function ESXI-80-000191($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "ConfigEtcIssue" "config_etc_issue" "You are accessing a U.S. Government..."
    AdvancedSettingSTIG $vmhost "Config.Etc.issue" $val
}

Function ESXI-80-000195($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "shellTimeout" "shell_timeout" "600"
    AdvancedSettingSTIG $vmhost "UserVars.ESXiShellTimeOut" $val
}

Function ESXI-80-000196($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "DcuiTimeOut" "dcui_timeout" "600"
    AdvancedSettingSTIG $vmhost "UserVars.DcuiTimeOut" $val
}

Function ESXI-80-000213($vmhost, $stigsettings) {
    $isVdi = Get-StigValue $stigsettings "vdi" "vdi" "false"
    if ($isVdi -eq "y" -or $isVdi -eq $true) {
        $val = Get-StigValue $stigsettings "ShareForceSaltingVDI" "share_force_salting_vdi" "2"
    } else {
        $val = Get-StigValue $stigsettings "ShareForceSalting" "share_force_salting" "2"
    }
    AdvancedSettingSTIG $vmhost "Mem.ShareForceSalting" $val
}

Function ESXI-80-000215($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "BlockGuestBPDU" "block_guest_bpdu" "1"
    AdvancedSettingSTIG $vmhost "Net.BlockGuestBPDU" $val
}

Function ESXI-80-000219($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "DVFilterBindIpAddress" "dvfilter_bind_ip_address" ""
    AdvancedSettingSTIG $vmhost "Net.DVFilterBindIpAddress" $val
}

Function ESXI-80-000161($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "sslProtocols" "ssl_protocols" "tls1.2,tls1.3"
    AdvancedSettingSTIG $vmhost "UserVars.SSLSUITE" $val
}

Function ESXI-80-000222($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "suppressShellWarning" "suppress_shell_warning" "0"
    AdvancedSettingSTIG $vmhost "UserVars.SuppressShellWarning" $val
}

Function ESXI-80-000223($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "suppressHyperWarning" "suppress_hyperthread_warning" "0"
    AdvancedSettingSTIG $vmhost "UserVars.SuppressHyperthreadWarning" $val
}

Function ESXI-80-000224($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "syslogCertCheck" "syslog_cert_check" "true"
    AdvancedSettingSTIG $vmhost "Syslog.global.certificate.checkSSLCerts" $val
}

Function ESXI-80-000225($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "memEagerZero" "mem_eager_zero" "1"
    AdvancedSettingSTIG $vmhost "Mem.MemEagerZero" $val
}

Function ESXI-80-000226($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "apiTimeout" "api_timeout" "30"
    AdvancedSettingSTIG $vmhost "Config.HostAgent.vmacore.soap.sessionTimeout" $val
}

Function ESXI-80-000232($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "syslogAuditEnable" "syslog_audit_enable" "true"
    AdvancedSettingSTIG $vmhost "Syslog.global.auditRecord.storageEnable" $val
}

Function ESXI-80-000233($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "syslogAuditRemote" "syslog_audit_remote" "true"
    AdvancedSettingSTIG $vmhost "Syslog.global.auditRecord.remoteEnable" $val
}

Function ESXI-80-000234($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "syslogCertStrict" "syslog_cert_strict" "true"
    AdvancedSettingSTIG $vmhost "Syslog.global.certificate.strictX509Compliance" $val
}

Function ESXI-80-000235($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "syslogLogLevel" "syslog_log_level" "info"
    AdvancedSettingSTIG $vmhost "Syslog.global.logLevel" $val
}

Function ESXI-80-000241($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "esxAdminsGroup" "esx_admins_group" "G6 VI Admins"
    AdvancedSettingSTIG $vmhost "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" $val
}

Function ESXI-80-000243($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "syslogLogDir" "syslog_log_dir" "[] /scratch/log"
    AdvancedSettingSTIG $vmhost "Syslog.global.logDir" $val
}

Function ESXI-80-000244($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "executeVibs" "execute_vibs" "true"
    AdvancedSettingSTIG $vmhost "VMkernel.Boot.execInstalledOnly" $val
}

Function ESXI-80-000250($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "bmcNetworkEnable" "bmc_network_enable" "0"
    AdvancedSettingSTIG $vmhost "Net.BMCNetworkEnable" $val
}

# =========================================================================
# REGION: EsxCli, Services, & System Remediations
# =========================================================================

Function ESXI-80-000014($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.security.fips140.ssh.get.invoke()
    if ($results.enable -eq "true" -or $results.enable -eq $true) {
        Write-ToConsoleGreen "...FIPS140 for SSH is already enabled on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Enabling FIPS140 for SSH on $($vmhost.name)..."
        $arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs()
        $arguments.enable = $true
        $esxcli.system.security.fips140.ssh.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000052($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ignorerhosts'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshIgnorerhosts" "ssh_ignore_rhosts" "yes"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH ignorerhosts set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH ignorerhosts to $targetValue on $($vmhost.name)"
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "ignorerhosts"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000085($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.settings.encryption.get.invoke()
    if ($results.RequireSecureBoot -eq "true" -or $results.RequireSecureBoot -eq $true) {
        Write-ToConsoleGreen "...Secure Boot required set correctly to true on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring Secure Boot requirement on $($vmhost.name)"
        $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
        $arguments.requiresecureboot = $true
        $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000133($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.software.acceptance.get.Invoke()
    if ($results -ne "CommunitySupported") {
        Write-ToConsoleGreen "...VIB Acceptance level is set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring VIB Acceptance level back to PartnerSupported..."
        $arguments = $esxcli.software.acceptance.set.CreateArgs()
        $arguments.level = "PartnerSupported"
        $esxcli.software.acceptance.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000187($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ciphers'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshCiphers" "ssh_ciphers" "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH ciphers already set to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH ciphers on $($vmhost.name)..."
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "ciphers"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000192($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'banner'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshBanner" "ssh_banner" "/etc/issue"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH banner already set to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH banner to $targetValue on $($vmhost.name)..."
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "banner"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000201($vmhost, $stigsettings) {
    $vmhostv = $vmhost | Get-View
    $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
    $exceptions = $lockdown.QueryLockdownExceptions()
    $targetUser = Get-StigValue $stigsettings "ExceptionUser" "exception_user" "root"
    if ($exceptions -contains $targetUser) {
        Write-ToConsoleGreen "...Lockdown exception user list already contains: $targetUser"
    } else {
        Write-ToConsoleYellow "...Adding exception user: $targetUser..."
        $lockdown.UpdateLockdownExceptions($targetUser) | Out-Null
    }
}

Function ESXI-80-000202($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'hostbasedauthentication'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshHostbasedauth" "ssh_hostbased_auth" "no"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH hostbasedauthentication set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH hostbasedauthentication to $targetValue on $($vmhost.name)..."
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "hostbasedauthentication"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000204($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permituserenvironment'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshPermituserenv" "ssh_permit_user_env" "no"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH permituserenvironment set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH permituserenvironment to $targetValue on $($vmhost.name)..."
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "permituserenvironment"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000207($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'gatewayports'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshGatewayports" "ssh_gateway_ports" "no"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH gatewayports set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH gatewayports to $targetValue on $($vmhost.name)..."
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "gatewayports"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000209($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permittunnel'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshPermittunnel" "ssh_permit_tunnel" "no"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH permittunnel set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH permittunnel to $targetValue on $($vmhost.name)..."
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "permittunnel"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000210($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientalivecountmax'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshClientalivecountmax" "ssh_client_alive_count_max" "3"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH clientalivecountmax set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH clientalivecountmax to $targetValue on $($vmhost.name)..."
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "clientalivecountmax"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000211($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientaliveinterval'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshClientaliveinterval" "ssh_client_alive_interval" "200"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH clientaliveinterval set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH clientaliveinterval to $targetValue on $($vmhost.name)..."
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "clientaliveinterval"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000212($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.snmp.get.Invoke()
    if ($results.enable -eq "false" -or $results.enable -eq $false) {
        Write-ToConsoleGreen "...SNMP is disabled correctly on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Disabling SNMP on $($vmhost.name)..."
        $arguments = $esxcli.system.snmp.set.CreateArgs()
        $arguments.enable = $false
        $esxcli.system.snmp.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000214($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.network.firewall.get.invoke()
    if ($results.DefaultAction -ne "DROP" -or $results.Enabled -ne "true") {
        Write-ToConsoleYellow "...Default firewall policy not DROP on $($vmhost.name)...configuring."
        $fwargs = $esxcli.network.firewall.set.CreateArgs()
        $fwargs.enabled = $true
        $fwargs.defaultaction = $false
        $esxcli.network.firewall.set.Invoke($fwargs) | Out-Null
    } else {
        Write-ToConsoleGreen "...Default firewall policy drops traffic cleanly."
    }
}

Function ESXI-80-000230($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'allowtcpforwarding'} | Select-Object -ExpandProperty Value
    $targetValue = Get-StigValue $stigsettings "sshAllowtcpforwarding" "ssh_allow_tcp_forwarding" "no"
    if ($results -eq $targetValue) {
        Write-ToConsoleGreen "...SSH allowtcpforwarding set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring SSH allowtcpforwarding to $targetValue on $($vmhost.name)..."
        $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
        $arguments.keyword = "allowtcpforwarding"
        $arguments.value = $targetValue
        $esxcli.system.ssh.server.config.set.Invoke($arguments) | Out-Null
    }
}

Function ESXI-80-000238($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.settings.encryption.get.invoke()
    if ($results.Mode -eq "TPM") {
        Write-ToConsoleGreen "...TPM configuration encryption already required on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring TPM encryption mode..."
        $encargs = $esxcli.system.settings.encryption.set.CreateArgs()
        $encargs.mode = "TPM"
        $esxcli.system.settings.encryption.set.Invoke($encargs) | Out-Null
    }
}

Function ESXI-80-000245($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "disableHwrng"} | Select-Object -ExpandProperty Configured
    if ($results -eq "FALSE") {
        Write-ToConsoleGreen "...disableHwrng set correctly to $results on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring disableHwrng on $($vmhost.name)"
        $enthwargs = $esxcli.system.settings.kernel.set.CreateArgs()
        $enthwargs.setting = "disableHwrng"
        $enthwargs.value = "FALSE"
        $esxcli.system.settings.kernel.set.invoke($enthwargs) | Out-Null
    }
}

Function ESXI-80-000246($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.syslog.config.logfilter.get.invoke() | Select-Object -ExpandProperty LogFilteringEnabled
    if ($results -eq $false) {
        Write-ToConsoleGreen "...log filtering set correctly on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring log filtering on $($vmhost.name)"
        $lfargs = $esxcli.system.syslog.config.logfilter.set.CreateArgs()
        $lfargs.logfilteringenabled = $false
        $esxcli.system.syslog.config.logfilter.set.invoke($lfargs) | Out-Null
    }
}

Function ESXI-80-000247($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $tlscheckargs = $esxcli.system.tls.server.get.CreateArgs()
    $tlscheckargs.showprofiledefaults = $true
    $tlscheckargs.showcurrentbootprofile = $true
    $results = $esxcli.system.tls.server.get.invoke($tlscheckargs) | Select-Object -ExpandProperty Profile
    $targetProfile = Get-StigValue $stigsettings "tlsServerProfile" "tls_server_profile" "NIST_2024"
    if ($results -eq $targetProfile) {
        Write-ToConsoleGreen "...TLS server profile set correctly on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring TLS server profile on $($vmhost.name)"
        $tlsargs = $esxcli.system.tls.server.set.CreateArgs()
        $tlsargs.profile = $targetProfile
        $esxcli.system.tls.server.set.invoke($tlsargs) | Out-Null
    }
}

Function ESXI-80-000248($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.security.keypersistence.get.invoke() | Select-Object -ExpandProperty Enabled
    if ($results -eq $false) {
        Write-ToConsoleGreen "...key persistence set correctly on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring key persistence on $($vmhost.name)"
        $kpargs = $esxcli.system.security.keypersistence.disable.CreateArgs()
        $kpargs.removeallstoredkeys = $true
        $esxcli.system.security.keypersistence.disable.invoke($kpargs) | Out-Null
    }
}

Function ESXI-80-000249($vmhost, $stigsettings) {
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'} | Select-Object -ExpandProperty Shellaccess
    if ($results -eq $false) {
        Write-ToConsoleGreen "...dcui shell access set correctly on $($vmhost.name)"
    } else {
        Write-ToConsoleYellow "...Configuring dcui shell access on $($vmhost.name)"
        $dcuisaargs = $esxcli.system.account.set.CreateArgs()
        $dcuisaargs.id = "dcui"
        $dcuisaargs.shellaccess = "false"
        $esxcli.system.account.set.invoke($dcuisaargs) | Out-Null
    }
}

# --- Standard Services (Stop-VMHostService) ---

Function ESXI-80-000193($vmhost, $stigsettings) {
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "SSH"}
    if ($esxservice.Running -eq $true -or $esxservice.Policy -eq "on") {
        Write-ToConsoleYellow "...Stopping SSH Service on $($vmhost.name)..."
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false | Out-Null
        $esxservice | Stop-VMHostService -Confirm:$false | Out-Null
    } else {
        Write-ToConsoleGreen "...SSH Service is already stopped."
    }
}

Function ESXI-80-000194($vmhost, $stigsettings) {
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "ESXi Shell"}
    if ($esxservice.Running -eq $true -or $esxservice.Policy -eq "on") {
        Write-ToConsoleYellow "...Stopping ESXi Shell Service on $($vmhost.name)..."
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false | Out-Null
        $esxservice | Stop-VMHostService -Confirm:$false | Out-Null
    } else {
        Write-ToConsoleGreen "...ESXi Shell Service is already stopped."
    }
}

Function ESXI-80-000231($vmhost, $stigsettings) {
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "slpd"}
    if ($esxservice.Running -eq $true) {
        Write-ToConsoleYellow "...Stopping slpd service on $($vmhost.name)..."
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false | Out-Null
        $esxservice | Stop-VMHostService -Confirm:$false | Out-Null
    } else {
        Write-ToConsoleGreen "...slpd Service is already stopped."
    }
}

Function ESXI-80-000228($vmhost, $stigsettings) {
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "CIM Server"}
    if ($esxservice.Running -eq $true) {
        Write-ToConsoleYellow "...Stopping CIM service on $($vmhost.name)..."
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false | Out-Null
        $esxservice | Stop-VMHostService -Confirm:$false | Out-Null
    } else {
        Write-ToConsoleGreen "...CIM Service is already stopped."
    }
}

Function ESXI-80-000124($vmhost, $stigsettings) {
    $ntpList = Get-StigValue $stigsettings "esxiNtpServers" "esxi_ntp_servers" "139.231.126.100"
    $CurrentNTP = Get-VmHostNtpServer -VMHost $vmhost
    if (!$CurrentNTP){
        $vmhost | Add-VmHostNtpServer -NtpServer $ntpList | Out-Null
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -policy On | Out-Null
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService | Out-Null
    } elseif (Compare-object $CurrentNTP $ntpList) {
        Write-ToConsoleYellow "...Setting NTP on $($vmhost)..."
        foreach ($ntp in $CurrentNTP) {
            $vmhost | Remove-VMHostNtpServer -NtpServer $ntp -Confirm:$false -ErrorAction Stop | Out-Null
        }
        $vmhost | Add-VmHostNtpServer -NtpServer $ntpList | Out-Null
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -policy On | Out-Null
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService | Out-Null
    } else {
        Write-ToConsoleGreen "NTP Already Set correctly on $($vmhost.name)"
    }
}

Function ESXI-80-000049($vmhost, $stigsettings) {
    $adJoin = Get-VMHostAuthentication -VMHost $vmhost.name 
    $domain = Get-StigValue $stigsettings "domainName" "domain_name" "niprpnp.army.mil"
    if ($adJoin.domain -eq $domain) {
        Write-ToConsoleGreen "...$($vmhost.name) is already joined to the Domain."
    } else {
        Write-ToConsoleYellow "...Skipping Active Directory Join: automated credential prompt bypassed in modular pipeline."
    }
}

# --- Core Host state configuration (V-258730) ---
Function ESXI-80-000008($vmhost, $stigsettings) {
    $val = Get-StigValue $stigsettings "lockdownlevel" "lockdown_level" "lockdownNormal"
    $vmhostv = $vmhost | Get-View 
    if ($vmhostv.config.LockdownMode -ne $val) {
        Write-ToConsoleYellow "...Enabling Lockdown mode with level $val on $($vmhost.name)"
        $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop 
        $lockdown.ChangeLockdownMode($val) | Out-Null
    } else {
        Write-ToConsoleGreen "...Lockdown mode already set to $val on $($vmhost.name)"
    }
}

Function ESXI-80-000227($vmhost, $stigsettings) {
    AdvancedSettingSTIG $vmhost $stigsettings.passwordMaxAge
}

Function ESXI-80-000221($vmhost, $stigsettings) {
    $build = $vmhost.ExtensionData.Config.Product.build
    $TargetBuild = Get-StigValue $stigsettings "esxiLatestBuild" "esxi_latest_build" "25595708"
    if ($build -ge $TargetBuild) {
        Write-ToConsoleGreen "...ESXi build $build is up-to-date (Latest target: $TargetBuild)"
    } else {
        Write-ToConsoleRed "...ESXi build $build is outdated (Latest target: $TargetBuild). Needs patch!"
    }
}

# --- Firewall Exceptions configuration (V-258794) ---
Function ESXI-80-000239($vmhost, $stigsettings) {
    $STIGID = "ESXI-80-000239"
    Write-ToConsole "...Remediating Firewall Exceptions Rule: $STIGID"
    $fwsys = Get-View $vmhost.ExtensionData.ConfigManager.FirewallSystem
    $fwservices = $fwsys.FirewallInfo.Ruleset | Where-Object {
        ($_.IpListUserConfigurable -eq $true) -and ($_.Enabled -eq $true) -and ($_.AllowedHosts.AllIp -eq $true)
    }

    $allowedIpsList = Get-StigValue $stigsettings "allowedips" "allowed_ips" "10.0.0.0/8"
    if ($null -eq $fwservices) {
        Write-ToConsoleGreen "...ESXi Firewall Rules already restrict access cleanly on $($vmhost.name)."
        return
    }

    $newIpNetworks = @()
    foreach ($networkBlock in $allowedIpsList) {
        $allowedNetwork, $prefix = $networkBlock.split('/')
        $tmp = New-Object VMware.Vim.HostFirewallRulesetIpNetwork
        $tmp.network = $allowedNetwork
        $tmp.prefixLength = [int]$prefix
        $newIpNetworks += $tmp
    }

    foreach ($service in $fwservices) {
        Write-ToConsoleYellow "...Configuring Firewall exceptions on service '$($service.Label)' to isolate traffic."
        $rulesetSpec = New-Object VMware.Vim.HostFirewallRulesetRulesetSpec
        $rulesetSpec.allowedHosts = New-Object VMware.Vim.HostFirewallRulesetIpList
        $rulesetSpec.allowedHosts.allIp = $false
        $rulesetSpec.allowedHosts.ipNetwork = $newIpNetworks
        $fwsys.UpdateRuleset($service.Key, $rulesetSpec)
    }
}

# --- Switch & Portgroup Policies ---

Function ESXI-80-000216($vmhost, $stigsettings) {
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
    foreach ($sw in $switches) {
        $secpol = $sw | Get-SecurityPolicy
        if ($secpol.ForgedTransmits -eq $true) {
            $secpol | Set-SecurityPolicy -ForgedTransmits $false -Confirm:$false | Out-Null
        }
    }
    $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
    foreach ($pg in $portgroups) {
        $secpol = $pg | Get-SecurityPolicy
        if ($secpol.ForgedTransmits -eq $true) {
            $secpol | Set-SecurityPolicy -ForgedTransmitsInherited $true -Confirm:$false | Out-Null
        }
    }
}

Function ESXI-80-000217($vmhost, $stigsettings) {
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
    foreach ($sw in $switches) {
        $secpol = $sw | Get-SecurityPolicy
        if ($secpol.MacChanges -eq $true) {
            $secpol | Set-SecurityPolicy -MacChanges $false -Confirm:$false | Out-Null
        }
    }
    $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
    foreach ($pg in $portgroups) {
        $secpol = $pg | Get-SecurityPolicy
        if ($secpol.MacChanges -eq $true) {
            $secpol | Set-SecurityPolicy -MacChangesInherited $true -Confirm:$false | Out-Null
        }
    }
}

Function ESXI-80-000218($vmhost, $stigsettings) {
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
    foreach ($sw in $switches) {
        $secpol = $sw | Get-SecurityPolicy
        if ($secpol.AllowPromiscuous -eq $true) {
            $secpol | Set-SecurityPolicy -AllowPromiscuous $false -Confirm:$false | Out-Null
        }
    }
    $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
    foreach ($pg in $portgroups) {
        $secpol = $pg | Get-SecurityPolicy
        if ($secpol.AllowPromiscuous -eq $true) {
            $secpol | Set-SecurityPolicy -AllowPromiscuousInherited $true -Confirm:$false | Out-Null
        }
    }
}

Function ESXI-80-000220($vmhost, $stigsettings) {
    $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard | Where-Object {$_.VlanId -eq 4095}
    foreach ($pg in $portgroups) {
        Write-ToConsoleRed "V-258775 Warning: Portgroup '$($pg.Name)' is configured with VLAN 4095 (VGT). Must be evaluated manually."
    }
}

# --- OS & Ansible Automated Files ---

Function ESXI-80-000236($vmhost, $stigsettings) {
    Write-ToConsoleRed "Manual/Ansible task [ESXI-80-000236]: stat /etc/vmware/settings must be 0. Run Ansible playbook."
}

Function ESXI-80-000237($vmhost, $stigsettings) {
    Write-ToConsoleRed "Manual/Ansible task [ESXI-80-000237]: grep vmx.log in /etc/vmware/config must be empty. Run Ansible playbook."
}

# --- Manual Compliance Checkpoints ---

Function ESXI-80-000240($vmhost, $stigsettings) {
    Write-ToConsoleRed "Manual eval [ESXI-80-000240]: Host Profiles and Auto Deploy must utilize Authentication Proxy."
}

Function ESXI-80-000160($vmhost, $stigsettings) {
    Write-ToConsoleRed "Manual eval [ESXI-80-000160]: Review VMkernel adapters and VLANs to isolate vMotion traffic."
}

Function ESXI-80-000198($vmhost, $stigsettings) {
    Write-ToConsoleRed "Manual eval [ESXI-80-000198]: Review VMkernel adapters to isolate management traffic."
}

Function ESXI-80-000199($vmhost, $stigsettings) {
    Write-ToConsoleRed "Manual eval [ESXI-80-000199]: Review VMkernel adapters to isolate IP-based storage traffic."
}

Function ESXI-80-000145($vmhost, $stigsettings) {
    Write-ToConsoleRed "Manual eval [ESXI-80-000145]: If iSCSI is in use, require bidirectional CHAP authentication."
}

Function ESXI-80-000229($vmhost, $stigsettings) {
    Write-ToConsoleRed "Manual eval [ESXI-80-000229]: Replacing VMCA host certificates with DoD-approved CA certs."
}

# Export all STIG rule commands cleanly
Export-ModuleMember -Function ESXI-80-*, AdvancedSettingSTIG