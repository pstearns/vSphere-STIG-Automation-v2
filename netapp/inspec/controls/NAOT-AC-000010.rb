control 'NAOT-AC-000010' do
  title 'ONTAP must be configured to enforce the limit of three consecutive failed logon attempts.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Use the command "security login role config show" to get a list of roles.

For each role, use the command "security login role config show -vserver <vserver_name> -role <role_name>" to view the password requirements for each role. 

If any role has "Maximum Number of Failed Attempts" not set to "3", this is a finding.

Use "security login role config show -role admin -instance" to see the settings for "Maximum Number of Failed Attempts" and “Lockout Duration".

Note: Lockout duration is set by default to lockout for one day or until unlocked by an administrator. It cannot be set to less than one day.

If ONTAP is not configured to enforce a limit of three consecutive invalid logon attempts, this is a finding.'
  desc 'fix', 'Use the command "security login role config show" to get a list of roles.

For each role, use the command "security login role config show -vserver <vserver_name> -role <role_name>" to view the password requirements for each role. 

For any role that does not have "Maximum Number of Failed Attempts" set to "3", use the command "security login role config modify -role <role_name> -vserver <vserver_name>  -max-failed-login-attempts 3".'
  impact 0.5
  tag check_id: 'C-50363r877994_chk'
  tag severity: 'medium'
  tag gid: 'V-246931'
  tag rid: 'SV-246931r960840_rule'
  tag stig_id: 'NAOT-AC-000010'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-50317r877995_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  cmd_roles = ontap_command('rows 0; security login role config show -fields role,max-failed-login-attempts')
  role_settings = cmd_roles.stdout.scan(/^\S+\s+(\S+)\s+(\d+)\s*$/).to_h

  cmd_logins = ontap_command('rows 0; security login show -authentication-method password')
  
  describe 'Maximum Failed Login Attempts for Password-Enabled Roles' do
    let(:password_user_roles) do
      cmd_logins.stdout.lines.map do |line|
        match = line.match(/password\s+(\S+)\s+/)
        match ? match[1] : nil
      end.compact.uniq
    end

    it 'must be set to 3 for all roles that are actively assigned to password-based users' do
      skip 'No password-based accounts were found on the system to check.' if password_user_roles.empty?

      misconfigured_roles = {}
      password_user_roles.each do |role|
        setting = role_settings.fetch(role, '0') 
        if setting.to_i != 3
          misconfigured_roles[role] = setting
        end
      end

      failure_message = "The following roles are used for password authentication but do not have the failed attempt limit set to 3: #{misconfigured_roles.to_a}"
      expect(misconfigured_roles).to be_empty, failure_message
    end
  end

  describe 'NOT A CHECK: FOR MANUAL REVIEW OF OUTPUT' do
    skip <<~EVIDENCE 
  
      --- ALL ROLE CONFIGURATIONS ---
      #{cmd_roles.stdout.encode('UTF-8')}
    EVIDENCE
  end
end