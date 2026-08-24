# frozen_string_literal: true

lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "train-ontap/version"

Gem::Specification.new do |spec|
  spec.name          = "train-ontap"
  spec.version       = TrainPlugins::Ontap::VERSION
  spec.authors       = ["Your Name"]
  spec.email         = ["your.email@example.com"]
  spec.summary       = "Train plugin for NetApp ONTAP over SSH"
  spec.description   = "A Chef Train transport plugin for connecting to NetApp ONTAP clusters via SSH for use with Chef InSpec. Enables platform detection and command execution against ONTAP CLI."
  spec.homepage      = "https://github.com/yourorg/train-ontap"
  spec.license       = "Apache-2.0"

  spec.files         = Dir.glob("{lib,exe}/**/*") + %w[LICENSE README.md]
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 3.0"

  spec.add_dependency "train", "~> 3.0"
  spec.add_dependency "net-ssh", "~> 7.0"
end