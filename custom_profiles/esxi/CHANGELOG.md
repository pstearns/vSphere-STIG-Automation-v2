# Changelog

All notable changes to the ESXi Custom STIG Overlay profiles will be documented in this file.

## [8.0-V2R4-Overlay] - 2026-08-13

### Added
- **ESXI-80-000199 (API):** Fully automated the previously manual NFS IP-based storage isolation check. Replaced the manual `skip` block with dynamic PowerCLI logic that locates VMkernel adapters tied to `nfsVlanId` (via standard or distributed switches) and audits their enabled services.

### Changed
- **Architecture Refactor:** Completely decoupled Custom Overlay profiles from the VMware Baseline profile. Removed all `depends:` and `include_controls` logic to prevent upstream path breakages.
- **Transport Isolation:** Split custom controls into `/api` (vmware://) and `/ssh` (ssh://) profiles to prevent InSpec backend session hijacking (`command / vmkernel` execution crashes).
- **ESXI-80-000160 (API):** Refactored `vMotionVlanId` logic. Removed the `excluded-inputs-for-source.yaml` requirement by leveraging native Ruby string parsing (`to_s.split(',').map(&:strip)`), allowing the custom control to safely evaluate arrays without triggering upstream strict type validation failures.

### Fixed
- **ESXI-80-000201 (API):** Fixed a bug in the upstream VMware Ruby code where `#{input('exceptionUsers')}` incorrectly cast arrays to literal strings, which broke backslash parsing for Active Directory service accounts (e.g., `NIPRPNP\svc.acas.sa`). Removed the string interpolation wrapper to correctly evaluate the YAML array.

---

## [8.0-V2R3-Overlay] - 2025-05-15

### Added
- Created initial custom folder structure for ESXi overrides.

### Changed
- **ESXI-80-000160:** Modified to protect the confidentiality and integrity of transmitted information by isolating vMotion traffic. Changed `vMotionVlanId` to validate as an array for multi-VLAN flexibility.
  - *Old:* `it { should cmp "#{input('vMotionVlanId')}" }`
  - *New:* `it { should be_in "#{input('vMotionVlanId')}" }`

---

## [8.0-V1R1-Overlay] - 2024-10-23

### Added
- **ESXI-80-000236 (SSH):** Automated the manual check ensuring the ESXi host is not configured to override virtual machine (VM) configurations. 
  - *Logic:* Executes `stat -c "%s" /etc/vmware/settings` via SSH expecting a result of `0`.
- **ESXI-80-000237 (SSH):** Automated the manual check ensuring the ESXi host is not configured to override VM logger settings.
  - *Logic:* Executes `grep "^vmx\.log" /etc/vmware/config` via SSH ensuring no output is returned.