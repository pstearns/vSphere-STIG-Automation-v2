control 'GET-CLUSTER-MGMT-INFO' do
  title 'Get IP and MAC address of cluster_mgmt for checklist'

  # Query cluster management LIFs directly across the cluster without hardcoding vserver name
  ip_cmd = "network interface show -lif cluster*mgmt* -fields vserver,lif,address,home-port"
  ip_result = inspec.backend.run_command(ip_cmd)

  # Strip ANSI color/terminal codes from stdout
  clean_stdout = ip_result.stdout.gsub(/\e\[([;\d]+)?m/, '')

  # Extract IP and Home Port from matching line
  mgmt_line = clean_stdout.split("\n").find { |l| l =~ /cluster[-_]mgmt/i }
  
  ip_address = mgmt_line ? mgmt_line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) : nil
  
  # Retrieve port (matches standard port identifiers like e0M, e0a, or ifgrps like a0a-34)
  home_port = nil
  if mgmt_line && mgmt_line =~ /\s+([a-zA-Z0-9\-_]+)\s*$/
    home_port = $1.strip
  end

  # Get MAC Address
  mac_address = nil
  if home_port
    mac_cmd = "network port show -port #{home_port} -fields mac"
    mac_result = inspec.backend.run_command(mac_cmd)
    clean_mac_stdout = mac_result.stdout.gsub(/\e\[([;\d]+)?m/, '')
    
    mac_line = clean_mac_stdout.split("\n").find do |line|
      line.include?(home_port) && line.match?(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i)
    end
    mac_address = mac_line ? mac_line.match(/([0-9a-f]{2}(:[0-9a-f]{2}){5})/i) : nil
  end

  describe 'Cluster Management Interface' do
    it "has a configured IP Address: #{ip_address || 'Not Found'}" do
      expect(ip_address).not_to be_nil
    end
    it "is assigned to Home Port: #{home_port || 'Not Found'}" do
      expect(home_port).not_to be_nil
    end
    it "has a physical MAC Address: #{mac_address || 'Not Found'}" do
      expect(mac_address).not_to be_nil
    end
  end

  puts "\n=== cluster_mgmt Information ==="
  puts "IP Address : #{ip_address}"
  puts "Home Port  : #{home_port}"
  puts "MAC Address: #{mac_address}"
  puts "=================================\n"
end