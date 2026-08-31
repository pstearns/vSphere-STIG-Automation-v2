control 'NAOT-AC-000004' do
  title 'ONTAP must automatically audit account-enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail, which documents the creation of application user accounts and notifies administrators and Information System Security Officer (ISSO). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Use "cluster log-forwarding show" to see if a remote syslog destination is defined for ONTAP.

Use commands available on the remote syslog server to check for new account creation or enabling a disabled account.

If ONTAP does not automatically audit account-enabling actions, this is a finding.'
  desc 'fix', 'Use "cluster log-forwarding show" to identify defined ONTAP remote syslog servers. If no remote syslog servers are defined, use "cluster log-forwarding create" to define a syslog destination.

On the remote syslog server, use commands available to check for new account creation or enabling a disabled account.'
  impact 0.5
  tag check_id: 'C-50357r769105_chk'
  tag severity: 'medium'
  tag gid: 'V-246925'
  tag rid: 'SV-246925r961290_rule'
  tag stig_id: 'NAOT-AC-000004'
  tag gtitle: 'SRG-APP-000319-NDM-000283'
  tag fix_id: 'F-50311r769106_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']

  allowed_syslog_servers = input('syslog_servers', value: [])

  cmd = ontap_command('cluster log-forwarding show')

  describe cmd do
    if allowed_syslog_servers.empty?
      it 'has syslog servers defined in inputs.yml' do
        fail 'No syslog servers were configured in inputs.yml. Please update configuration.'
      end
    else
      allowed_syslog_servers.each do |server|
        it "forwards log events to: #{server}" do
          expect(cmd.stdout).to match(Regexp.escape(server))
        end
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
