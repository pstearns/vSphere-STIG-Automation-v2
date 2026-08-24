# controls/NAOT-AC-000001.rb
#
# NAOT-AC-000001
# ONTAP must be configured to limit the number of concurrent sessions.

control 'NAOT-AC-000001' do
  title 'ONTAP must be configured to limit the number of concurrent sessions'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to denial-of-service (DoS) attacks.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag gid: 'V-246922'
  tag rid: 'SV-246922r1156802_rule'
  tag stig_id: 'NAOT-AC-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-2 (1)']

  describe ontap_command('security session limit show -interface cli') do
    its('stdout') { should match /cli\s+application\s+3/ }
    its('exit_status') { should eq 0 }
  end
end