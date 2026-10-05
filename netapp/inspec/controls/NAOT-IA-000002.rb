control 'NAOT-IA-000002' do
  title 'ONTAP must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Use "security login show -role admin" to see all configured admin users and groups. 

If any account, other than the admin account used as the account of last resort, has an authentication method password, this is a finding.'
  desc 'fix', 'Configure new administrator active directory users or groups with "security login create -user-or-group-name <user_name> -role admin -authentication-method domain".'
  impact 0.5
  tag check_id: 'C-50380r1211038_chk'
  tag severity: 'medium'
  tag gid: 'V-246948'
  tag rid: 'SV-246948r1211039_rule'
  tag stig_id: 'NAOT-IA-000002'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-50334r769175_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']

  # Retrieve allowed accounts of last resort directly as an Array (e.g. ['nacadmin', 'admin'])
  allowed_last_resort_accounts = Array(input('account_last_resort'))

  cmd = ontap_command('security login show -role admin')

  describe 'Replay-Resistant Authentication for Privileged Accounts' do
    let(:password_based_admins) do
      # Parse out all usernames using password-based authentication
      admins = []
      cmd.stdout.each_line do |line|
        if line.include?('password')
          admins << line.split.first
        end
      end
      admins.uniq
    end

    it 'must not use password-based authentication for any privileged account, except for the authorized account of last resort' do
      # Subtract the authorized last resort list directly from all password-based admins
      disallowed_password_users = password_based_admins - allowed_last_resort_accounts
      
      failure_message = "The following privileged accounts are using non-replay-resistant 'password' authentication: #{disallowed_password_users.join(', ')}.\n" \
                        "Only the authorized account of last resort #{allowed_last_resort_accounts} is permitted to use password authentication."
      
      expect(disallowed_password_users).to be_empty, failure_message
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