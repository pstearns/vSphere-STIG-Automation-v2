control 'NAOT-IA-000005' do
  title 'ONTAP must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Use "security login role config show -role admin -fields passwd-minlength" to see the minimum password length for the role admin.

If ONTAP is not configured to enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the minimum password length for the role admin to 15 with "security login role config modify -vserver <vserver name> -role admin -passwd-minlength 15".'
  impact 0.5
  tag check_id: 'C-50383r835255_chk'
  tag severity: 'medium'
  tag gid: 'V-246951'
  tag rid: 'SV-246951r1015270_rule'
  tag stig_id: 'NAOT-IA-000005'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-50337r945869_fix'
  tag 'documentable'
  tag cci: ['CCI-004066', 'CCI-000205']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (a)']

  cmd = ontap_command('security login role config show -role admin -fields passwd-minlength')

  describe cmd do
    let(:admin_minlength) do
      match = subject.stdout.match(/^\S+\s+admin\s+(\d+)\s*$/)
      match ? match[1].to_i : 0
    end

    it 'must enforce a minimum password length of 15 or greater for the admin role' do
      expect(admin_minlength).to be >= 15,
        "The admin role minimum password length is set to #{admin_minlength}. Expected >= 15."
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