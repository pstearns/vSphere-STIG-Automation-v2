control 'NAOT-CM-000002' do
  title 'ONTAP must be configured to use an authentication server to provide multifactor authentication.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device.

"
  desc 'check', 'Use "security login show -authentication-method domain" to see users configured to authenticate with Active Directory.

If ONTAP is not configured to use an authentication server, this is a finding.

Note: The authentication method "domain" is one example. Other authentication methods such as "publickey" and "saml" are also acceptable.'
  desc 'fix', 'Configure ONTAP to use Active Directory to authenticate users and prohibit the use of cached authenticators with "security login create -user-or-group-name <user or group name> -authentication-method domain -application ssh".

Note: The authentication method "domain" is one example. Other authentication methods such as "publickey" and "saml" are also acceptable.'
  impact 0.7
  tag check_id: 'C-50372r1211035_chk'
  tag severity: 'high'
  tag gid: 'V-246940'
  tag rid: 'SV-246940r1211037_rule'
  tag stig_id: 'NAOT-CM-000002'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-50326r1211036_fix'
  tag satisfies: ['SRG-APP-000516-NDM-000336', 'SRG-APP-000149-NDM-000247', 'SRG-APP-000175-NDM-000262', 'SRG-APP-000177-NDM-000263']
  tag 'documentable'
  tag cci: ['CCI-000370', 'CCI-000764', 'CCI-000765', 'CCI-000166', 'CCI-000185', 'CCI-000187']
  tag nist: ['CM-6 (1)', 'IA-2', 'IA-2 (1)', 'AU-10', 'IA-5 (2) (b) (1)', 'IA-5 (2) (a) (2)']

  cmd = ontap_command('security login show')

  describe 'Multifactor Authentication Configuration' do
    it 'must be configured to use an approved authentication method (domain, publickey, or saml)' do
      approved_methods_regex = /(domain|publickey|saml)/i
      failure_message = "No approved authentication methods (domain, publickey, saml) were found in the configuration."
      expect(cmd.stdout).to match(approved_methods_regex), failure_message
    end
  end

  describe 'NOT A CHECK: FOR MANUAL REVIEW OF OUTPUT' do
    skip <<~EVIDENCE 
    
      --- RAW OUTPUT FOR MANUAL VERIFICATION ---
      #{cmd}
      #{cmd.stdout.encode('UTF-8')}
    EVIDENCE
  end
end
