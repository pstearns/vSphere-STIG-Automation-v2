control 'GET-CLUSTER-MGMT-INFO' do
  title 'Get IP and MAC address of cluster_mgmt for checklist'
  cluster = input('cluster')

  # Get IP
  ip_cmd = "network interface show -vserver #{cluster} -lif cluster_mgmt -fields address"
  ip_result = inspec.backend.run_command(ip_cmd)
  ip_line = ip_result.stdout.split("\n").find { |l| l.include?('cluster_mgmt') }
  ip_address = ip_line ? ip_line.split(/\s+/).last : nil

  # Get Home Port
  port_cmd = "network interface show -vserver #{cluster} -lif cluster_mgmt -fields home-port"
  port_result = inspec.backend.run_command(port_cmd)
  port_line = port_result.stdout.split("\n").find { |l| l.include?('cluster_mgmt') }
  home_port = port_line ? port_line.split(/\s+/).last : nil

  # Get MAC Address (improved parsing)
  mac_cmd = "network port show -port #{home_port} -fields mac"
  mac_result = inspec.backend.run_command(mac_cmd)

  # Find the line that contains the port and has a MAC-looking value
  mac_line = mac_result.stdout.split("\n").find do |line|
    line.include?(home_port.to_s) && line.match?(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i)
  end

  mac_address = mac_line ? mac_line.match(/([0-9a-f]{2}(:[0-9a-f]{2}){5})/i)[1] : nil

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

  # Output
  puts "\n=== cluster_mgmt Information ==="
  puts "IP Address : #{ip_address}"
  puts "Home Port  : #{home_port}"
  puts "MAC Address: #{mac_address}"
  puts "=================================\n"
end