control 'NAOT-IA-000003' do
  title 'ONTAP must be configured to authenticate SNMP messages using FIPS-validated Keyed-HMAC.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Validate that SNMP is enabled using the command "options -option-name snmp*".

If snmp.enable and snmp.san.enable are set to "off", then SNMP is not enabled and this requirement is not applicable.

Use "security snmpusers -authmethod usm" to see snmpV3 users using FIPS-validated Keyed-HMAC.

If ONTAP is not configured to authenticate SNMP messages using FIPS-validated Keyed-HMAC, this is a finding.'
  desc 'fix', %q(Configure a snmpV3 user using FIPS-validated Keyed-HMAC with "security login create -user-or-group-name snmptest2 -application snmp -authentication-method usm".

Enter the authoritative entity's EngineID [local EngineID]:

Which authentication protocol do you want to choose (none, md5, sha, sha2-256) [none]: sha2-256

Enter the authentication protocol password (minimum 8 characters long):

Enter the authentication protocol password again:

Which privacy protocol do you want to choose (none, des, aes128) [none]: aes128.)
  impact 0.5
  tag check_id: 'C-50381r860688_chk'
  tag severity: 'medium'
  tag gid: 'V-246949'
  tag rid: 'SV-246949r961506_rule'
  tag stig_id: 'NAOT-IA-000003'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-50335r769178_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']

  only_if('This requirement is not applicable because SNMP is disabled') do
    ontap_command('options snmp.enable').stdout.match?(/on/i)
  end

  cmd = ontap_command('security snmpusers -authmethod usm')

  describe 'SNMPv3 User-based Security Model (USM) Configuration' do
    it 'must have at least one SNMPv3 user configured for USM authentication' do
      expect(cmd.stdout).to match(/^\S+/), "SNMP is enabled, but no users are configured for secure USM authentication."
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
