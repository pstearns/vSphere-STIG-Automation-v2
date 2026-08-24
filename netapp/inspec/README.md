# NetApp ONTAP InSpec Profile

This folder contains the InSpec profile for validating NetApp ONTAP DSC 9.x clusters against the DISA STIG.

## Structure

```
inspec/
├── inspec.yml
├── libraries/
│   └── ontap_command.rb          # SSH helper library
├── controls/
│   ├── NAOT-*.rb                 # One control per STIG rule
└── README.md
```

## Usage

```bash
# From within the inspec directory
inspec exec . -t ssh://user@ontap-cluster-ip --input ontap_targets=172.16.34.200
```

## Design Notes

- Follows the same patterns used in the ESXi InSpec profile (`custom_profiles/esxi/inspec/ssh/`).
- Uses a shared `ontap_command` resource for SSH command execution.
- Controls are named using the official `Rule_Ver` from the STIG (e.g., `NAOT-AC-000001.rb`).
- High-value, fully automatable checks are prioritized.

## Current Status

See `../docs/NetApp_STIG_Mapping.md` for the complete mapping of all 29 rules and their automation status.

## Next Steps

1. Implement remaining controls following the established pattern.
2. Enhance `ontap_command.rb` with real SSH connection logic using inputs.
3. Add support for `answers.yml` for the small number of checks requiring manual designation.