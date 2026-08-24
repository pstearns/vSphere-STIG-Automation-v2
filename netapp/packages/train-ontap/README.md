# train-ontap

A minimal Chef Train transport plugin for NetApp ONTAP over SSH, intended for use with Chef InSpec.

## Installation (Development)

```bash
cd train-ontap
gem build train-ontap.gemspec
inspec plugin install ./train-ontap-0.1.0.gem
```

For Chef Workstation / embedded Ruby:

```bash
chef exec inspec plugin install ./train-ontap-0.1.0.gem
```

For air-gapped: copy the .gem file and use the same `inspec plugin install` command on the target system.

## Usage

```bash
# Password auth (InSpec will prompt securely or use env/credentials)
inspec exec my-profile --target ontap://admin@cluster-mgmt.example.com

# With explicit password (avoid in scripts)
INSPEC_TARGET_PASSWORD=secret inspec exec ... --target ontap://admin@cluster-mgmt.example.com

# SSH key auth
inspec exec my-profile --target ontap://admin@cluster-mgmt.example.com --key-files /path/to/id_rsa

# Debug
inspec exec my-profile --target ontap://... --log-level debug
```

## Platform Support in inspec.yml

```yaml
name: my-ontap-profile
title: ONTAP Compliance Profile
version: 0.1.0
supports:
  - platform-name: ontap
```

## Verification

```bash
inspec detect -t ontap://admin@cluster-mgmt.example.com
inspec plugin list | grep ontap
```

## Notes

- This plugin uses direct Net::SSH for ONTAP CLI command execution.
- It forces platform "ontap" with release parsed from the `version` command.
- Standard `command()` resources work without patching Chef InSpec.
- Only read-only, non-interactive commands are recommended for v1.
- Future: SVM context switching, structured output parsing, ONTAP-specific resources.

See the source in lib/train/transports/ontap.rb for implementation details.