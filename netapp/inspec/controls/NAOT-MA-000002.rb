# controls/NAOT-MA-000002.rb
#
# NAOT-MA-000002
# ONTAP must be configured to implement cryptographic mechanisms using FIPS 140-2.

control 'NAOT-MA-000002' do
  title 'ONTAP must be configured to implement cryptographic mechanisms using FIPS 140-2'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag gid: 'V-246958'
  tag rid: 'SV-246958r961557_rule'
  tag stig_id: 'NAOT-MA-000002'
  tag cci: ['CCI-000803', 'CCI-003123', 'CCI-002890']
  tag nist: ['SC-13']

  describe ontap_command('set -privilege advanced; security config show') do
    its('stdout') { should match /FIPS Mode.*true/i }
    its('exit_status') { should eq 0 }
  end
end