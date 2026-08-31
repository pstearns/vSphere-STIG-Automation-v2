control 'NAOT-SC-000001' do
  title 'ONTAP must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Use "system timeout show" to see the session timeout in minutes.

If ONTAP does not terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure ONTAP to timeout idle sessions after 10 minutes with "system timeout modify -timeout 10".'
  impact 0.7
  tag check_id: 'C-50391r769207_chk'
  tag severity: 'high'
  tag gid: 'V-246959'
  tag rid: 'SV-246959r961068_rule'
  tag stig_id: 'NAOT-SC-000001'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-50345r769208_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  cmd = ontap_command('system timeout show')

  describe 'Idle Session Timeout' do
    let(:timeout_minutes) do
      match = cmd.stdout.match(/timeout:\s+(\d+)/)
      match ? match[1].to_i : -1
    end

    it 'must be set to a value between 1 and 10 minutes' do
      failure_message = "The session timeout is set to #{timeout_minutes} minutes. It must be between 1 and 10."
      expect(timeout_minutes).to be_between(1, 10), failure_message
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
