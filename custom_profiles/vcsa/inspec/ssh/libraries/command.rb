require "inspec/resource"
require "inspec/resources/platform"
require "inspec/resources/os"

module Inspec::Resources
  class Cmd < Inspec.resource(1)
    name "command"
    supports platform: "unix"
    supports platform: "esx"
    supports platform: "windows"
    desc "Use the command InSpec audit resource to test an arbitrary command that is run on the system."

    attr_reader :command

    def initialize(cmd, options = {})
      if cmd.nil?
        raise "InSpec `command` was called with `nil` as the argument. This is not supported."
      end

      @command = cmd
      
      # FIX: Removed the Inspec::Config dependency that crashes CINC 7!
      @timeout = options[:timeout]&.to_i

      if options[:redact_regex]
        unless options[:redact_regex].is_a?(Regexp)
          @command = "ERROR"
          raise Inspec::Exceptions::ResourceFailed, "The `redact_regex` option must be a regular expression"
        end
        @redact_regex = options[:redact_regex]
      end
    end

    def result
      @result ||= begin
        inspec.backend.run_command(@command, timeout: @timeout)
                  rescue Train::CommandTimeoutReached
                    sleep 0.1
                    raise Inspec::Exceptions::ResourceFailed, "Command `#{@command}` timed out after #{@timeout} seconds"
      end
    end

    def stdout
      result.stdout
    end

    def stderr
      result.stderr
    end

    def exit_status
      result.exit_status.to_i
    end

    def exist? 
      return false if inspec.os.name.nil? || inspec.os.name == "mock"

      if inspec.os.linux?
        res = if inspec.platform.name == "alpine"
                inspec.backend.run_command("which \"#{@command}\"")
              else
                inspec.backend.run_command("sh -c 'type \"#{@command}\"'")
              end
      elsif inspec.os.windows?
        res = inspec.backend.run_command("Get-Command \"#{@command}\"")
      elsif inspec.os.unix? || inspec.os.vmkernel?
        res = inspec.backend.run_command("type \"#{@command}\"")
      else
        warn "`command(#{@command}).exist?` is not supported on your OS: #{inspec.os[:name]}"
        return false
      end
      res.exit_status.to_i == 0
    end

    def resource_id
      to_s || "command"
    end

    def to_s
      output = "Command: `#{@command}`"
      output.gsub!(@redact_regex, '\1REDACTED\2') unless @redact_regex.nil?
      output
    end
  end
end