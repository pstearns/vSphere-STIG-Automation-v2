# frozen_string_literal: true

require "train/transports/base"
require "net/ssh"
require "timeout"

module Train::Transports
  # Register the ONTAP transport plugin.
  # Target syntax: ontap://user@host:port
  # or ontap://user:pass@host
  class Ontap < Train.plugin(1)
    name "ontap"

    # Mirror common SSH options for compatibility with InSpec/Train target parsing
    # and to support key-based and password auth via standard mechanisms.
    option :host, required: true
    option :port, default: 22
    option :user, required: true
    option :password
    option :key_files          # Array of private key paths
    option :passphrase         # For encrypted private keys
    option :timeout, default: 30
    option :verify_host_key, default: false  # For simplicity in v1; production should use :accept_new or similar

    def connection
      @connection ||= Connection.new(@options)
    end
  end

  class Connection < BaseConnection
    attr_reader :session

    def initialize(options)
      super(options)

      @host = options[:host]
      @port = options[:port] || 22
      @user = options[:user]
      @password = options[:password]
      @key_files = options[:key_files] || []
      @passphrase = options[:passphrase]
      @timeout = options[:timeout] || 30
      @verify_host_key = options[:verify_host_key]

      @session = nil
      @platform = nil
    end

    # Establish SSH session to ONTAP management LIF.
    # Uses Net::SSH directly for full control over non-POSIX appliance behavior.
    def connect
      return if @session && !@session.closed?

      ssh_opts = {
        port: @port,
        timeout: @timeout,
        verify_host_key: @verify_host_key ? :accept_new : false,
        non_interactive: true
      }

      if @password && !@password.empty?
        ssh_opts[:password] = @password
      end

      if @key_files && !@key_files.empty?
        ssh_opts[:keys] = @key_files
        ssh_opts[:keys_only] = true if @password.nil? || @password.empty?
        ssh_opts[:passphrase] = @passphrase if @passphrase
      end

      begin
        @session = Net::SSH.start(@host, @user, ssh_opts)
      rescue Net::SSH::AuthenticationFailed => e
        raise Train::ClientError, "ONTAP SSH authentication failed for user #{@user}: #{e.message}"
      rescue => e
        raise Train::ClientError, "Failed to connect to ONTAP at #{@host}:#{@port}: #{e.message}"
      end
    end

    # Execute ONTAP CLI command non-interactively.
    # ONTAP supports ssh user@cluster "command" style execution.
    # We use exec! for simplicity and capture full result including exit status.
    def run_command(cmd)
      connect unless @session

      stdout = ""
      stderr = ""
      exit_status = nil

      begin
        Timeout.timeout(@timeout) do
          stdout, stderr, exit_status = @session.exec!(cmd.to_s)
        end
      rescue Timeout::Error
        raise Train::CommandTimeout, "Command timed out after #{@timeout} seconds: #{cmd}"
      rescue => e
        raise Train::ClientError, "ONTAP command execution failed: #{e.message}"
      end

      # ONTAP CLI typically returns meaningful exit codes:
      # 0 = success
      # non-zero = error (syntax, privilege, resource not found, etc.)
      # We pass through the real exit status when available.
      exit_status = exit_status.to_i if exit_status

      CommandResult.new(stdout.to_s, stderr.to_s, exit_status || 0)
    end

    # Platform detection specific to ONTAP.
    # Uses the lightweight "version" command (or cached result).
    # This replaces any generic Unix detection that would occur with plain SSH transport.
    def platform
      return @platform if @platform

      # Run version command once and parse.
      result = run_command("version")

      if result.exit_status != 0 || result.stdout.empty?
        # Fallback or error - but for ONTAP it should succeed on valid login
        raise Train::PlatformDetectionFailed, "Failed to detect ONTAP platform via 'version' command"
      end

      release = parse_ontap_release(result.stdout)

      @platform = force_platform!("ontap", release: release)
      @platform
    end

    # Parse realistic ONTAP version output.
    # Example input:
    #   NetApp Release 9.15.1P7: Tue Mar 04 18:43:09 UTC 2025
    #   System ID: 1234567890 (cluster1)
    #   ...
    # Returns "9.15.1P7" or similar.
    def parse_ontap_release(output)
      # Match common patterns: "NetApp Release X.Y.Z..." or "NetApp Release X.Y.ZP#"
      if match = output.match(/NetApp Release\s+([\d.]+(?:P\d+)?)/i)
        match[1]
      elsif match = output.match(/version\s*:\s*([\d.]+(?:P\d+)?)/i)
        match[1]
      else
        # Fallback to first line or generic
        output.lines.first&.strip || "unknown"
      end
    end

    def close
      if @session && !@session.closed?
        @session.close
      end
      @session = nil
      @platform = nil
    end

    # Expose for debugging / InSpec shell if needed
    def to_s
      "ONTAP Connection to #{@user}@#{@host}:#{@port}"
    end
  end
end