control 'NAOT-CM-000008' do
  title 'ONTAP must use DoD-approved PKI rather than proprietary or self-signed device certificates.'
  desc 'Each organization obtains user certificates from an approved, shared service provider as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority (CA) at medium assurance or higher, this CA will suffice.'
  desc 'check', 'Use the command "security certificate show -instance -type client-ca" to show information about the ca-certificates that are installed.

If any of the certificates have the name or identifier of a nonapproved source in the Issuer field, this is a finding.'
  desc 'fix', 'Generate a new key-pair from a DOD-approved certificate issuer. Sites must consult the PKI/PKI pages on the https://cyber.mil website for procedures for NIPRNet and SIPRNet.

RSA:
request security pki generate-key-pair certificate-id <cert name> type rsa size <512 | 1024 | 2048 | 4096>

ECDSA:
request security pki generate-key-pair certificate-id <cert_name> type ecdsa size <256 | 384>

Generate a CSR from RSA key-pair using the following command and options.

request security generate-certificate-request certificate-id <cert_name_from_key_file> digest <sha1 | sha256> domain <FQDN> email <admin_email> ip-address <ip_address> subject “CN=<hostname>,DC=<domain_part>,DC=<TLD_domain>,O=<organization>,OU=<organization_dept>,
L=<city>,ST=<state>,C=<us>” filename <path/filename>

Generate a CSR from ECDSA key-pair using the following command and options.

request security generate-certificate-request certificate-id <cert_name_from_key_file> digest <sha256 | sha384> domain <FQDN> email <admin_email> ip-address <ip_address> subject “CN=<hostname>,DC=<domain_part>,DC=<TLD_domain>,O=<organization>,OU=<organization_dept>,
L=<city>,ST=<state>,C=<us>” filename <path/filename>

If no filename is specified, the CSR is displayed on the standard out (terminal).

After receiving the approved certificate from the CA, install the certificate with the command "security certificate install -type client-ca -vserver <vserver_name>".

For SSH accounts, apply the public key from the cert to the user account with the following command.
 
security login publickey create -vserver <vserver name> -username <username> -index 0 -publickey "ssh-rsa <cert_text>"'
  impact 0.5
  tag check_id: 'C-50377r945866_chk'
  tag severity: 'medium'
  tag gid: 'V-246945'
  tag rid: 'SV-246945r961863_rule'
  tag stig_id: 'NAOT-CM-000008'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-50331r945867_fix'
  tag 'documentable'
  tag cci: ['CCI-001159']
  tag nist: ['SC-17 a']

  # Retrieve allowed CA issuers and ignored internal certificates from inputs
  approved_ca_issuers     = Array(input('approved_ca_issuers'))
  ignored_client_ca_certs = Array(input('ignored_client_ca_certs', value: []))

  # Query ONTAP using instance format to get precise multi-line field definitions
  cmd = ontap_command('security certificate show -type client-ca -instance')

  describe 'Client CA Certificates' do
    let(:installed_certs) do
      certs = []

      # Sanitize string to prevent any UTF-8 Multibyte exceptions
      sanitized_output = cmd.stdout.encode('UTF-8', invalid: :replace, undef: :replace, replace: '')

      # Split output by certificate instances
      sanitized_output.split('Vserver:').drop(1).map do |cert_block|
        vserver = cert_block.lines.first.strip
        cert_name = nil
        issuer_ca = nil

        cert_block.each_line do |line|
          clean_line = line.strip

          if clean_line.start_with?('Certificate Name:')
            cert_name = clean_line.split(':', 2).last.strip
          elsif clean_line.start_with?('Certificate Authority:')
            # This captures the full CA string cleanly (e.g., "IC PKI Root 4" or "DoD IC PKI Root 4")
            issuer_ca = clean_line.split(':', 2).last.strip
          end
        end

        if cert_name && issuer_ca
          certs << {
            vserver: vserver,
            name: cert_name,
            issuer: issuer_ca
          }
        end
      end
      certs
    end

    it "must have the 'approved_ca_issuers' list defined in the input file" do
      expect(approved_ca_issuers).not_to be_empty,
        "The 'approved_ca_issuers' input is not defined. This check cannot be automated without a list of authorized CA issuers."
    end

    if !approved_ca_issuers.empty?
      it 'must be issued by a DoD-approved Certificate Authority' do
        unapproved_certs = installed_certs.reject do |cert|
          # Accept if the issuer is in the approved list
          # OR if the certificate name is in the ignored internal list
          approved_ca_issuers.include?(cert[:issuer]) ||
          ignored_client_ca_certs.include?(cert[:name])
        end

        unless unapproved_certs.empty?
          details = unapproved_certs.map { |c|
            "Cert '#{c[:name]}' on Vserver '#{c[:vserver]}' has unapproved issuer '#{c[:issuer]}'"
          }.join('; ')
          failure_message = "The following certificates are not issued by an approved DoD PKI: #{details}"
          expect(unapproved_certs).to be_empty, failure_message
        end
      end
    end
  end

  describe 'NOT A CHECK: FOR MANUAL REVIEW OF OUTPUT' do
    skip <<~EVIDENCE
      --- RAW OUTPUT FOR MANUAL VERIFICATION ---
      #{cmd}
      #{cmd.stdout.encode('UTF-8', invalid: :replace, undef: :replace, replace: '')}
    EVIDENCE
  end
end