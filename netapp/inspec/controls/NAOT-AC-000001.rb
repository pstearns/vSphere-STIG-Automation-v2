control 'NAOT-AC-000001' do
  title 'ONTAP must be configured to limit the number of concurrent sessions.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to denial-of-service (DoS) attacks.'
  desc 'check', 'Use "security session limit show -interface cli" to check the concurrent session limit.

If the security session limit is not configured to limit the number of concurrent sessions to 3, this is a finding.'
  desc 'fix', 'Configure session limits with the command, "security session limit modify -max-active-limit 3 -interface cli -category application".'
  impact 0.5
  tag check_id: 'C-50354r1156800_chk'
  tag severity: 'medium'
  tag gid: 'V-246922'
  tag rid: 'SV-246922r1156802_rule'
  tag stig_id: 'NAOT-AC-000001'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-50308r1156801_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  cmd = ontap_command('security session limit show -interface cli')

  describe cmd do
    # Capture and parse the raw command output safely
    let(:app_limit) do
      output = subject.stdout
      # Cleaned regex: removed double asterisks
      match = output.match(/cli\s+application\s+(\d+)/i)
      match ? match[1].to_i : nil
    end

    # 2. Perform the robust numeric evaluation
    its 'limits cli application sessions to 3 or fewer' do
      expect(app_limit).not_to be_nil, 'Failed to extract the session limit from command output.'
      expect(app_limit).to be <= 3
      expect(app_limit).to be > 0 
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
