# controls/NAOT-AC-000002.rb
#
# NAOT-AC-000002
# ONTAP must be configured to create a session lock after 15 minutes.

control 'NAOT-AC-000002' do
  title 'ONTAP must be configured to create a session lock after 15 minutes'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000003-NDM-000202'
  tag gid: 'V-246923'
  tag rid: 'SV-246923r1207671_rule'
  tag stig_id: 'NAOT-AC-000002'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11']

  describe ontap_command('system timeout show') do
    its('stdout') { should match /timeout:\s+\d+/ }
    its('stdout') { should match /timeout:\s+([0-9]|[1-9][0-9])/ } # <= 15 minutes
    its('exit_status') { should eq 0 }
  end
end