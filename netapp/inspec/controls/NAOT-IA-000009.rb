control 'NAOT-IA-000009' do
  title 'ONTAP must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Use "security login role config show -role admin -fields passwd-min-special-chars" to see the minimum number of special characters required in a password for the role admin.

If ONTAP is not configured to enforce password complexity by requiring that at least one special character be used, this is a finding.'
  desc 'fix', 'Configure ONTAP to enforce password complexity by requiring that at least one special character be used with "security login role config modify -role admin -passwd-min-special-chars 1".'
  impact 0.5
  tag check_id: 'C-50387r835265_chk'
  tag severity: 'medium'
  tag gid: 'V-246955'
  tag rid: 'SV-246955r1015274_rule'
  tag stig_id: 'NAOT-IA-000009'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-50341r769196_fix'
  tag 'documentable'
  tag cci: ['CCI-004066', 'CCI-001619']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (a)']

  cmd = ontap_command('security login role config show -role admin -fields passwd-min-special-chars')

  describe 'Password Complexity for Admin Role: Special Characters' do
    it 'must require at least one special character' do
      expect(cmd.stdout).to match(/^\S+\s+admin\s+([1-9]\d*)\s*$/), "The admin role does not require at least 1 special character."
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