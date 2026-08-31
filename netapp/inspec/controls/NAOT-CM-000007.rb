control 'NAOT-CM-000007' do
  title 'ONTAP must be configured to conduct backups of system level information.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Use "set -privilege advanced" reply "y" to continue and "system configuration backup show" to see if ONTAP is configured for system backups.

If ONTAP is not configured to conduct backups of system-level data when changes occur, this is a finding.'
  desc 'fix', 'Configure ONTAP to conduct backups of system level information with "set -privilege advanced" reply "y" to continue and "system configuration backup create -node <node_name> -backup-type cluster -backup-name <name>".'
  impact 0.5
  tag check_id: 'C-50376r835240_chk'
  tag severity: 'medium'
  tag gid: 'V-246944'
  tag rid: 'SV-246944r961863_rule'
  tag stig_id: 'NAOT-CM-000007'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-50330r769163_fix'
  tag 'documentable'
  tag cci: ['CCI-000537']
  tag nist: ['CP-9 (b)']

  max_backup_age_days = input('max_backup_age_days', value: 7).to_i

  cmd = ontap_command('set -privilege advanced; y; system configuration backup show')

  describe 'System Configuration Backups' do
    it 'must have at least one backup file (.7z) present' do
      expect(cmd.stdout).to match(/\.7z/i),
        'No system configuration backup files (.7z) were found on the cluster.'
    end

    let(:latest_backup_date) do
      raw_dates = cmd.stdout.scan(/\b(?:\d{1,2}\/\d{1,2}\/\d{4}|\d{4}-\d{2}-\d{2})\b/)
      parsed_dates = raw_dates.map do |d|
        begin
          Date.parse(d)
        rescue ArgumentError
          nil
        end
      end.compact
      parsed_dates.max
    end

    it "must have a backup within the last #{max_backup_age_days} days" do
      if latest_backup_date
        threshold_date = Date.today - max_backup_age_days
        failure_message = "The latest backup is from #{latest_backup_date}, which is older than the policy threshold of #{max_backup_age_days} days."
        expect(latest_backup_date).to be >= threshold_date, failure_message
      else
        expect(latest_backup_date).not_to be_nil, 'Could not determine backup recency because no valid backup dates were found.'
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