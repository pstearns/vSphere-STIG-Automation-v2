# NetApp ONTAP STIG Automation

This folder contains all NetApp ONTAP-specific automation, documentation, and configuration for the DISA STIG (NetApp ONTAP DSC 9.x).

## Design Philosophy

This is a **self-contained product module** under `orchestration_overlay/netapp/`. It follows these principles:

- All NetApp-related code, configuration, and documentation lives in this folder.
- It leverages the shared orchestration layer (`modules/StigOrchestration.psm1`, `RemediationOrchestration.psm1`, `globalFunctions.psm1`, etc.) located in the parent `orchestration_overlay/` directory.
- It does **not** pollute the shared `modules/`, `conf/`, or `custom_profiles/` folders with NetApp-specific logic.

## Folder Structure

```
netapp/
├── README.md                          # This file
├── modules/
│   └── NetAppRemediationFunctions.psm1   # Core automation functions
├── conf/
│   ├── answers.yml                    # Manual / partial automation inputs
│   └── inputs.yml                     # Target-specific configuration
├── docs/
│   └── NetApp_STIG_Mapping.md         # Maps every STIG requirement to CLI + automation status
├── checklists/                        # .ckl files and baseline exports
├── reports/                           # Generated reports
├── tests/                             # Targeted test / validation scripts
└── bin/                               # Optional product-specific helper scripts
```

## Current Status

- **STIG Version**: NetApp ONTAP DSC 9.x V2R4 (Benchmark Date: 01 Jul 2026)
- **Primary Method**: SSH + CLI command execution (consistent with existing framework)
- **InSpec**: Not primary at this time (can be added later under `custom_profiles/netapp/` if needed)

## Getting Started

1. Review `docs/NetApp_STIG_Mapping.md` for automation coverage.
2. Update `conf/answers.yml` with site-specific values (e.g., designated "account of last resort").
3. Use the shared orchestration functions from the parent layer to call NetApp functions.

## Contributing

When adding new automation:
- Add the function to `modules/NetAppRemediationFunctions.psm1`
- Update the mapping document in `docs/`
- Add any required answer file fields to `conf/answers.yml`

---
Maintained as part of the STIG Orchestration Overlay project.