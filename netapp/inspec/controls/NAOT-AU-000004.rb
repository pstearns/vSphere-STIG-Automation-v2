control 'NAOT-AU-000004' do
  title 'ONTAP must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DOD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DOD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Use "cluster time-service ntp server show" to view the current network time protocol configuration for ONTAP and ensure at least two ntp servers are defined.

If ONTAP is not configured to synchronize internal information system clocks using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure network time protocol for ONTAP with "cluster time-service ntp server create -server <IP address>" to add new ntp servers. Up to 10 servers can be defined.'
  impact 0.5
  tag check_id: 'C-50368r945864_chk'
  tag severity: 'medium'
  tag gid: 'V-246936'
  tag rid: 'SV-246936r1015268_rule'
  tag stig_id: 'NAOT-AU-000004'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-50322r860679_fix'
  tag 'documentable'
  tag cci: ['CCI-004928', 'CCI-001893']
  tag nist: ['SC-45 (2) (a)', 'AU-8 (2)']

  approved_ntp_servers = input('approved_ntp_servers', value: []).to_a
  cmd = ontap_command('cluster time-service ntp server show')

  describe 'NTP Server Configuration' do
    let(:configured_servers) do
      cmd.stdout.scan(/^(\S+)\s+(auto|\d+)\s+/).map(&:first)
    end

    it "must have the 'approved_ntp_servers' list defined in the input file" do
      failure_message = "The 'approved_ntp_servers' input is not defined. This check cannot be automated without a list of authorized NTP servers."
      expect(approved_ntp_servers).not_to be_empty, failure_message
    end

    if !approved_ntp_servers.empty?
      it 'must only use approved NTP servers' do
        unapproved_servers = configured_servers - approved_ntp_servers
        failure_message = "The following configured NTP servers are not on the approved list: #{unapproved_servers.join(', ')}"
        expect(unapproved_servers).to be_empty, failure_message
      end

      it 'must have at least 2 approved NTP servers for redundancy' do
        approved_servers_in_use = configured_servers & approved_ntp_servers
        failure_message = "Expected at least 2 approved NTP servers for redundancy, but found #{approved_servers_in_use.count}: [#{approved_servers_in_use.join(', ')}]"
        expect(approved_servers_in_use.count).to be >= 2, failure_message
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
