control 'NAOT-AU-000003' do
  title 'ONTAP must have audit guarantee enabled.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. With audit guarantee enabled, all SMB operations must generate an audit event before an ACK is returned to the client and the operation completed.  If the audit event cannot be written, then the client operation is delayed or denied.'
  desc 'check', 'Use "vserver audit show -fields audit-guarantee" to see if audit guarantee is enabled.

If audit-guarantee is set to false, this is a finding.'
  desc 'fix', 'Use the command "vserver audit modify -vserver <vserver_name> -destination <audit log location> -audit-guarantee true" to set audit-guarantee to true.  

An example command for a vserver named svm01 with the audit logs at /audit_log would be "vserver audit modify -vserver svm01 -destination /audit_log -audit-guarantee true".

Use the command "vserver audit show -fields audit-guarantee" to verify the change.'
  impact 0.5
  tag check_id: 'C-50367r856966_chk'
  tag severity: 'medium'
  tag gid: 'V-246935'
  tag rid: 'SV-246935r961401_rule'
  tag stig_id: 'NAOT-AU-000003'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-50321r856967_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']

  cmd = ontap_command('vserver audit show -fields vserver,audit-guarantee')

  describe 'VServer Audit Guarantee' do
    it 'must be enabled on all vservers with auditing configured' do
      misconfigured_vservers = cmd.stdout.scan(/^(\S+)\s+false\s*$/).flatten
      failure_message = "Audit guarantee is not enabled for the following vservers: #{misconfigured_vservers.join(', ')}"
      expect(misconfigured_vservers).to be_empty, failure_message
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
