control 'NAOT-SI-000001' do
  title 'ONTAP must be configured to send audit log data to a central log server.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Use "cluster log-forwarding show" to see if audit logs are being sent to a remote logging server.

Sample output from the command:

                                                                                           Verify   Syslog
Destination Host         Port   Protocol                   Server   Facility
------------------------ ------ ----------------------- --------  --------
192.168.0.1                     514    udp-unencrypted false       user

If no remote logging servers are listed, this is a finding.'
  desc 'fix', 'Configure ONTAP for remote syslogging with "cluster log-forwarding create -destination <hostname_or_ip_address>".'
  impact 0.7
  tag check_id: 'C-50396r860697_chk'
  tag severity: 'high'
  tag gid: 'V-246964'
  tag rid: 'SV-246964r1137890_rule'
  tag stig_id: 'NAOT-SI-000001'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-50350r769223_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  approved_syslog_servers = input('syslog_servers', value: []).to_a
  cmd = ontap_command('cluster log-forwarding show')

  describe 'Centralized Audit Log Forwarding' do
    let(:configured_servers) do
      cmd.stdout.scan(/^(\S+)\s+\d+\s+/).flatten
    end

    it "must have the 'syslog_servers' list defined in the input file" do
      failure_message = "The 'syslog_servers' input is not defined. This check cannot be automated without a list of authorized syslog servers."
      expect(approved_syslog_servers).not_to be_empty, failure_message
    end

    if !approved_syslog_servers.empty?
      it 'must be configured to forward logs to at least one approved syslog server' do
        approved_in_use = configured_servers & approved_syslog_servers
        failure_message = "No approved syslog servers are configured. Configured servers: [#{configured_servers.join(', ')}]. Approved servers: [#{approved_syslog_servers.join(', ')}]."
        expect(approved_in_use).not_to be_empty, failure_message
      end

      it 'must not forward logs to any unapproved syslog servers' do
        unapproved_in_use = configured_servers - approved_syslog_servers
        failure_message = "Log forwarding is configured for unapproved destinations: [#{unapproved_in_use.join(', ')}]."
        expect(unapproved_in_use).to be_empty, failure_message
      end
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