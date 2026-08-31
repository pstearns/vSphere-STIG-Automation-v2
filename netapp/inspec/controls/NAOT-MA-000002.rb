control 'NAOT-MA-000002' do
  title 'ONTAP must be configured to implement cryptographic mechanisms using FIPS 140-2.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Satisfies: SRG-APP-000412-NDM-000331, SRG-APP-000411-NDM-000330, SRG-APP-000179-NDM-000265'
  desc 'check', 'Use "set -privilege advanced" reply "y" to continue and "security config show" to see if cluster FIPS mode is true.

If ONTAP is not configured to implement cryptographic mechanisms using FIPS 140-2, this is a finding.'
  desc 'fix', 'Configure ONTAP to use cryptographic mechanisms with "set -privilege advanced" reply "y" to continue and  "security config modify -is-fips-enabled true -interface SSL".'
  impact 0.7
  tag check_id: 'C-50390r860692_chk'
  tag severity: 'high'
  tag gid: 'V-246958'
  tag rid: 'SV-246958r961557_rule'
  tag stig_id: 'NAOT-MA-000002'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-50344r945871_fix'
  tag satisfies: ['SRG-APP-000412-NDM-000331', 'SRG-APP-000411-NDM-000330', 'SRG-APP-000179-NDM-000265']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-003123', 'CCI-002890']
  tag nist: ['IA-7', 'MA-4 (6)', 'MA-4 (6)']

  cmd = ontap_command('set -privilege advanced; y; security config show')

  describe 'FIPS 140-2 Configuration' do
    it 'must have FIPS mode enabled' do
      fips_key_value_pattern = /^Is FIPS Mode Enabled\?:\s+true\s*$/
      fips_table_pattern = /^true\s+/
      is_compliant = cmd.stdout.match?(fips_key_value_pattern) || cmd.stdout.match?(fips_table_pattern)
      failure_message = "FIPS mode is not enabled. Expected 'true' in the 'FIPS Mode' column or as a direct setting."
      expect(is_compliant).to be(true), failure_message
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