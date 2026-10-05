control 'NAOT-AC-000005' do
  title 'ONTAP must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged-level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Use "security login show -role admin -authentication-method password" to see the local administrative account.

If ONTAP is not configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable, this is a finding.'
  desc 'fix', 'Configure a secure password for the local administrative account with "security login password -username <user_name>".'
  impact 0.5
  tag check_id: 'C-50358r860671_chk'
  tag severity: 'medium'
  tag gid: 'V-246926'
  tag rid: 'SV-246926r1051115_rule'
  tag stig_id: 'NAOT-AC-000005'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-50312r769109_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']


  # Query ONTAP for unlocked admin accounts using password auth
  cmd = ontap_command('security login show -role admin -authentication-method password -is-account-locked no')

  # Filter the raw output lines to grab just the usernames
  active_unlocked_accounts = []
  cmd.stdout.each_line do |line|
    # Only process lines containing 'password' to skip headers/footers
    if line.include?('password')
      account_name = line.split.first
      active_unlocked_accounts << account_name
    end
  end
  active_unlocked_accounts.uniq!

  # Retrieve allowed accounts directly from inputs
  allowed_accounts = Array(input('account_last_resort'))

  describe "ONTAP Local Admin Count" do
    it "must have exactly one unlocked local administrative account" do
      expect(active_unlocked_accounts.count).to eq(1),
        "Expected exactly 1 active local admin account, but found #{active_unlocked_accounts.count}: [#{active_unlocked_accounts.join(', ')}]"
    end
  end

  describe "ONTAP Account of Last Resort Validation" do
    it "must match one of the designated accounts: #{allowed_accounts}" do
      expect(allowed_accounts).to include(active_unlocked_accounts.first),
        "The active unlocked local admin '#{active_unlocked_accounts.first}' is not in the allowed list: #{allowed_accounts.join(', ')}."
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