# libraries/ontap_command.rb
# frozen_string_literal: true

class OntapCommand < Inspec.resource(1)
  name 'ontap_command'
  desc 'Execute a command on NetApp ONTAP (via train-ontap plugin)'

  def initialize(cmd)
    @cmd = cmd
    @result = inspec.backend.run_command(cmd)
  end

  def stdout
    @result.stdout
  end

  def stderr
    @result.stderr
  end

  def exit_status
    @result.exit_status
  end

  def to_s
    "ONTAP Command: #{@cmd}"
  end
end