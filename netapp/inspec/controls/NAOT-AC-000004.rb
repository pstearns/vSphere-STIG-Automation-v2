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

  # Retrieve allowed syslog servers directly from inputs
  allowed_syslog_servers = Array(input('syslog_servers'))

  cmd = ontap_command('cluster log-forwarding show')

  # Sanitize to prevent UTF-8 multibyte parsing issues
  sanitized_output = cmd.stdout.encode('UTF-8', invalid: :replace, undef: :replace, replace: '')

  # Extract ONLY valid IPv4 addresses or FQDNs from the output
  # This ignores SSH banners ("Last login time"), headers, and "IPspace: Default"
  configured_destinations = []
  sanitized_output.each_line do |line|
    clean_line = line.strip

    # Ignore prompt, banners, and header blocks
    next if clean_line.include?('Last login') || 
            clean_line.include?('Destination Host') || 
            clean_line.include?('IPspace:') || 
            clean_line.start_with?('----')

    # Pull out IPv4 addresses (e.g. 139.231.125.151)
    if (match = clean_line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/))
      configured_destinations << match[0]
    end
  end
  configured_destinations.uniq!

  describe 'Syslog Configuration Input Verification' do
    it 'must have syslog servers defined in the inputs.yml' do
      expect(allowed_syslog_servers).not_to be_empty,
        'No syslog servers were configured in inputs.yml. Please update your profile configuration.'
    end
  end

  if !allowed_syslog_servers.empty?
    describe 'ONTAP Syslog Destinations' do
      it 'must have at least one remote syslog destination configured' do
        expect(configured_destinations).not_to be_empty,
          "No remote syslog destinations were found in the command output.\n" \
          "Raw output:\n#{cmd.stdout}"
      end

      it 'must only forward logs to authorized syslog servers' do
        # Checks if any destination found on the system is missing from inputs
        unauthorized_servers = configured_destinations - allowed_syslog_servers
        
        expect(unauthorized_servers).to be_empty,
          "The system is forwarding logs to unauthorized destinations: #{unauthorized_servers.join(', ')}.\n" \
          "Authorized list: #{allowed_syslog_servers.join(', ')}"
      end
    end
  end

  describe "NOT A CHECK: FOR MANUAL REVIEW OF OUTPUT" do
    skip <<~EVIDENCE
      --- RAW OUTPUT FOR MANUAL VERIFICATION ---
      #{cmd}
      #{cmd.stdout.encode('UTF-8', invalid: :replace, undef: :replace, replace: '')}
    EVIDENCE
  end
end