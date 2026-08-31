control 'NAOT-AC-000002' do
  title 'ONTAP must be configured to create a session lock after 15 minutes.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device. Rather than relying on the user to manually lock their management session prior to vacating the vicinity, network devices need to be able to identify when a management session has idled and take action to initiate the session lock. Once invoked, the session lock must remain in place until the administrator re-authenticates. No other system activity aside from re-authentication must unlock the management session.

Note that CCI-001133 requires that administrative network sessions be disconnected after 10 minutes of idle time. This requirement may only apply to local administrative sessions.'
  desc 'check', 'Use "system timeout show" to check the current CLI timeout.

If the system timeout is not set to 15 minute(s) or less, this is a finding.'
  desc 'fix', 'Configure the CLI timeout value to 15 minutes with the command, "system timeout modify -timeout 15".'
  impact 0.5
  tag check_id: 'C-50355r835205_chk'
  tag severity: 'medium'
  tag gid: 'V-246923'
  tag rid: 'SV-246923r1207671_rule'
  tag stig_id: 'NAOT-AC-000002'
  tag gtitle: 'SRG-APP-000003-NDM-000202'
  tag fix_id: 'F-50309r769100_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']

  cmd = ontap_command('system timeout show')

  describe cmd do
    # Extract the numeric value using a simple regex capture
    let(:timeout_value) do
      match = subject.stdout.match(/timeout:\s+(\d+)/i)
      match ? match[1].to_i : nil
    end

    it 'is configured to a timeout of 15 minutes or less' do
      expect(timeout_value).not_to be_nil
      expect(timeout_value).to be <= 15
      expect(timeout_value).to be > 0
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

