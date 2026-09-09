control 'NAOT-AC-000009' do
  title 'ONTAP must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations.'
  desc 'check', 'Use "security login role show” to see role-based access policies defined in ONTAP for privileged and unprivileged users. Privileged users have the role of admin.

If ONTAP does not prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures, this is a finding.'
  desc 'fix', 'Configure privileged users with "security login create -user-or-group-name <user_name> -role admin".

Configure non-privileged users with "security login create -user-or-group-name <user_name> -role <role_name>“where a non-privileged user role other than admin is used.'
  impact 0.7
  tag check_id: 'C-50362r769120_chk'
  tag severity: 'high'
  tag gid: 'V-246930'
  tag rid: 'SV-246930r961353_rule'
  tag stig_id: 'NAOT-AC-000009'
  tag gtitle: 'SRG-APP-000340-NDM-000288'
  tag fix_id: 'F-50316r769121_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

cmd = ontap_command('rows 0; security login role show -cmddirname DEFAULT')

describe 'Non-Privileged Role Restrictions' do
  let(:authorized_admin_roles) do
    # Allowed predefined and custom cluster-admin roles with DEFAULT 'all'
    ['admin', 'admin-no-fsa']
  end

  let(:unauthorized_default_all_roles) do
    default_all_roles = cmd.stdout.scan(/(?:^\S+|\s+)\s+(\S+)\s+DEFAULT\s+all\b/i).flatten.uniq
    default_all_roles.reject { |role| authorized_admin_roles.include?(role) }
  end

  it 'must not grant unrestricted DEFAULT "all" access to non-admin roles' do
    failure_message = "The following non-admin roles have excessive privileges with DEFAULT 'all' access: [#{unauthorized_default_all_roles.join(', ')}]"
    expect(unauthorized_default_all_roles).to be_empty, failure_message
  end

  describe 'NOT A CHECK: FOR MANUAL REVIEW OF OUTPUT' do
    skip <<~EVIDENCE 

      --- RAW OUTPUT FOR MANUAL VERIFICATION ---
      #{cmd}
      #{cmd.stdout.encode('UTF-8')}
    EVIDENCE
  end
end