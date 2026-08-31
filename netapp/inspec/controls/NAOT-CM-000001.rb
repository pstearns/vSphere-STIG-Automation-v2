control 'NAOT-CM-000001' do
  title 'ONTAP must enforce access restrictions associated with changes to the device configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to device configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the device could potentially have significant effects on the overall security of the device.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to device components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Use "security login show -role admin" to see users with administrative privilege that allow device configuration. 

If ONTAP does not enforce access restrictions associated with changes to the device configuration, this is a finding.'
  desc 'fix', 'Configure users with administrative privilege that allows device configuration with "security login create -user-or-group-name <user_name> -role admin".'
  impact 0.5
  tag check_id: 'C-50371r860684_chk'
  tag severity: 'medium'
  tag gid: 'V-246939'
  tag rid: 'SV-246939r961461_rule'
  tag stig_id: 'NAOT-CM-000001'
  tag gtitle: 'SRG-APP-000380-NDM-000304'
  tag fix_id: 'F-50325r769148_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']

  authorized_admins = input('authorized_admins', value: []).to_a
  cmd = ontap_command('security login show -role admin')

  describe 'Administrative Access Control' do
    if !authorized_admins.empty?
      let(:configured_admins) do
        cmd.stdout.scan(/^\S+\s+(?:console|http|ontapi|service-processor|ssh)\b/).map do |line|
          line.split.first
        end.uniq.reject { |acc| acc == 'admin' }
      end

      it 'must only grant the admin role to authorized users and groups' do
        unauthorized_accounts = configured_admins - authorized_admins
        failure_message = "The following accounts have the 'admin' role but are not on the approved list: #{unauthorized_accounts.join(', ')}"
        expect(unauthorized_accounts).to be_empty, failure_message
      end
    else
      it 'is a manual check because the `authorized_admins` input is not defined' do
        skip "This is a manual check. The 'authorized_admins' input was not provided. Please verify the accounts listed in the raw output below are authorized."
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