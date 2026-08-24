# controls/NAOT-SI-000001.rb
#
# NAOT-SI-000001
# ONTAP must be configured to send audit log data to a central log server.

control 'NAOT-SI-000001' do
  title 'ONTAP must be configured to send audit log data to a central log server'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag gid: 'V-246964'
  tag rid: 'SV-246964r1137890_rule'
  tag stig_id: 'NAOT-SI-000001'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  describe ontap_command('cluster log-forwarding show') do
    its('stdout') { should match /Destination Host/ }
    its('stdout') { should match /\d+\.\d+\.\d+\.\d+/ } # At least one remote destination
    its('exit_status') { should eq 0 }
  end
end