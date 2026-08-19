# VMware STIG Tools Appliance Customization & Orchestration
**Enterprise STIG Auditing + Remediation Orchestration Engine**  
*Overlay for the official VMware / Broadcom DoD STIG Automation Appliance (OVA)*

---

## Overview

This repository provides a complete, production-grade **overlay** for the official VMware STIG Tools Appliance. It transforms the appliance into a fully automated, enterprise-capable STIG compliance platform for VMware vSphere 8.0 environments.

By keeping all custom logic in this overlay repository, the base OVA remains **ephemeral infrastructure**. When a new OVA is released, simply redeploy and re-apply this overlay.

### What This Project Delivers

| Capability              | Coverage                                                                 | Key Features |
|-------------------------|--------------------------------------------------------------------------|--------------|
| **Auditing**            | VCSA (10 components), ESXi, Virtual Machines                             | Parallel execution, custom InSpec overlays, dynamic inventory |
| **Remediation**         | VCSA, ESXi, Virtual Machines                                             | Waiver-driven, technical fixes + verification loop, delta merge |
| **Reporting**           | DISA CKL generation, centralized CSV summaries, historical trends        | STIG Manager integration, remediation history tracking |
| **Security**            | AES-256 encrypted credential vault                                       | No plaintext credentials, interactive vault management |
| **Integration**         | STIG Manager (via stigman-watcher)                                       | Real-time automated upload after remediation |

---

## Architecture

The system is split into two primary pipelines that share common infrastructure:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        STIG ORCHESTRATION PLATFORM                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   AUDIT PIPELINE                          REMEDIATION PIPELINE              │
│   (StigOrchestration.psm1)               (RemediationOrchestration.psm1)    │
│                                                                             │
│   • Dynamic Inventory Discovery           • Waiver Pre-Processing           │
│   • Parallel Workers (VCSA / ESXi / VM)   • Technical Remediation           │
│   • Custom InSpec Profile Support         • InSpec Verification (cinc)      │
│   • DISA CKL Generation                   • Delta Merge back to Master CKL  │
│   • Section Summaries + CSV History       • Real-time STIG Manager Sync     │
│                                                                             │
│   Shared Services:                                                          │
│   • CredentialManagement.psm1 (AES-256 Vault)                               │
│   • globalFunctions.psm1 (Logging, XML, Answer Files, Summaries)            │
│   • Pluggable Providers (ESXi / VCSA / VM)                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Design Principles**
- **Pluggable Providers**: Each asset type (ESXi, VCSA, VM) has its own remediation provider with lifecycle hooks (`Initialize-AssetProvider` / `Finalize-AssetProvider`).
- **Verify What Actually Happened**: Remediation is always followed by fresh InSpec verification — never trust "it should have worked."
- **Thread-Safe by Design**: Isolated staging sandboxes per runspace + `ConcurrentBag` + named Mutex for STIG Manager uploads.
- **Resilient Date Handling**: Automatically crawls date folders backward to find the most recent valid checklists per vCenter.

---

## Directory & File Structure

### Core Orchestration Modules

| File | Purpose |
|------|---------|
| `modules/StigOrchestration.psm1` | Master audit controller. Inventory discovery, routing, parallel batching, and section orchestration. |
| `modules/RemediationOrchestration.psm1` | Master remediation engine. Waiver processing, technical remediation, verification, delta merge, and STIG Manager sync. |
| `modules/globalFunctions.psm1` | Shared utilities: structured logging, XML/CKL manipulation, answer file processing, scan summaries. |
| `modules/CredentialManagement.psm1` | AES-256 encrypted local vault + interactive management menu. |

### Asset-Specific Providers & Helpers

| Asset | Audit | Remediation | Helpers |
|-------|-------|-------------|---------|
| **VCSA** | `Invoke-VcsaAudit.psm1` | `VcsaRemediationProvider.psm1` | `VcsaHelpers.psm1` |
| **ESXi** | `Invoke-EsxiAudit.psm1` | `EsxiRemediationProvider.psm1` + `EsxiRemediationFunctions.psm1` | `EsxiHelpers.psm1` |
| **VM**   | `Invoke-VmAudit.psm1` | `VmRemediationProvider.psm1` + `VmRemediationFunctions.psm1` | `VmHelpers.psm1` |

### Execution Wrappers (`bin/`)

| Script | Purpose |
|--------|---------|
| `run-cron-vcsa.sh` | Scheduled VCSA audit |
| `run-cron-esxi.sh` | Scheduled ESXi audit |
| `run-cron-vm.sh` | Scheduled VM audit |
| `run-remediation-vcsa.sh` | Scheduled VCSA remediation (with flock locking) |
| `run-remediation-esxi.sh` | Scheduled ESXi remediation |
| `run-remediation-vm.sh` | Scheduled VM remediation |
| `run-stigman-watcher.sh` | One-shot STIG Manager upload for a specific collection |

### Configuration Locations

- `conf/global_config.yml` — vCenter targets, STIG Manager collection mappings, marking, exclusion regexes
- `conf/vcsa/`, `conf/esxi/`, `conf/vm/` — `inputs.yml`, `answers.xml` (waivers), and provider-specific settings
- `conf/.creds.json.encrypted` — AES-256 credential vault

---

## Initial OVA Bootstrap

Run these commands once on a freshly deployed VMware STIG Automation OVA:

```bash
sudo sed -i '/sslverify=/d' /etc/tdnf/tdnf.conf
sudo sed -i 's/sslverify=1/sslverify=0/g' /etc/yum.repos.d/photon.repo
sudo sed -i 's/^\[# \]*AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd
sudo tdnf clean all && sudo tdnf update -y && sudo tdnf install git -y
```

---

## Deployment

```bash
sudo mkdir -p /usr/share/stigs/orchestration_overlay
git clone https://oauth2:<TOKEN>@web.git.mil/.../vmware-stig-wrapper.git /usr/share/stigs/orchestration_overlay
cd /usr/share/stigs/orchestration_overlay

git config --global credential.helper store
git config --global user.name "STIG Automation"
git config --global user.email "your.email@army.mil"
```

> **Note**: The overlay is typically deployed to `/usr/share/stigs/orchestration_overlay`.

---

## Credential Management

All vCenter, VCSA root, and ESXi root credentials are stored in a true **AES-256 CBC encrypted vault**.

Interactive management:

```powershell
pwsh
Import-Module /usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1 -Force
Invoke-CredentialManager -FilePath "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted"
```

---

## How to Run

### 1. Scheduled Execution (Recommended)

Cron wrappers are located in `bin/` and log to `logs/*_execution_trace.log`.

```bash
# Audits
/usr/share/stigs/orchestration_overlay/bin/run-cron-vcsa.sh
/usr/share/stigs/orchestration_overlay/bin/run-cron-esxi.sh
/usr/share/stigs/orchestration_overlay/bin/run-cron-vm.sh

# Remediation
/usr/share/stigs/orchestration_overlay/bin/run-remediation-vcsa.sh
/usr/share/stigs/orchestration_overlay/bin/run-remediation-esxi.sh
/usr/share/stigs/orchestration_overlay/bin/run-remediation-vm.sh
```

### 2. Manual / Ad-Hoc Execution

**Audit Mode**

```powershell
pwsh
Import-Module /usr/share/stigs/orchestration_overlay/modules/StigOrchestration.psm1 -Force

Invoke-MultiVcsaOrchestration -OverlayRoot "/usr/share/stigs/orchestration_overlay"
Invoke-MultiEsxiOrchestration -OverlayRoot "/usr/share/stigs/orchestration_overlay"
Invoke-MultiVmOrchestration -OverlayRoot "/usr/share/stigs/orchestration_overlay"
```

**Remediation Mode**

```powershell
pwsh
Import-Module /usr/share/stigs/orchestration_overlay/modules/RemediationOrchestration.psm1 -Force

Invoke-StigRemediation -AssetType VCSA -Silent
Invoke-StigRemediation -AssetType ESXi -Silent
Invoke-StigRemediation -AssetType VM   -Silent

# Optional: Target specific asset
Invoke-StigRemediation -AssetType ESXi -TargetName "esxi01" -Silent
```

---

## Remediation Workflow (High Level)

1. **Waiver / Answer File Processing** — Open findings are checked against `answers.xml`. Waivers can auto-close items before any technical remediation.
2. **Technical Remediation** — Provider-specific fixes (PowerCLI advanced settings, Ansible playbooks for SSH/Ansible-managed items, etc.).
3. **InSpec Verification** — Fresh `cinc-auditor` run against the exact rules that were remediated.
4. **Delta Merge** — Results are merged back into the master DISA CKL (status, finding details, comments).
5. **STIG Manager Sync** — Updated CKL is copied to the collection inbox and uploaded via `stigman-watcher`.

VCSA remediation runs **sequentially** (to respect single-node SSH limits). ESXi and VM remediation run in parallel with controlled batching and thread-safe staging.

---

## Outputs & Reporting

| Output | Location | Description |
|--------|----------|-------------|
| **DISA CKL Files** | `reports/YYYYMMDD/<vCenter>/[VCSA\|ESXi\|VMs]/` | Final merged checklists ready for eMASS / STIG Manager |
| **Centralized Open Items CSVs** | `reports/Open_Items_Summary_*.csv` | Long-term historical trend data per asset class |
| **Remediation History** | `reports/Remediation_History_Master.csv` | Every automated remediation action with timestamp and method |
| **Execution Logs** | `logs/` | Structured app logs + full PowerShell transcripts |
| **Temporary Staging** | `/tmp/stig_staging/` and `/tmp/remediation_staging/` | Cleaned automatically (per-runspace isolation) |

---

## Configuration Points

- `conf/global_config.yml` — vCenter targets, enabled flags, STIG Manager collection mappings, VM exclusion regex, marking string.
- `conf/*/answers.xml` — Waiver and justification rules (per asset type).
- `conf/*/inputs.yml` — InSpec input variables.
- Provider-specific Ansible playbooks and custom InSpec profiles under `custom_profiles/`.

---

## Maintenance & Operational Notes

- Treat the base OVA as **ephemeral** — all persistent configuration and logic lives in this overlay.
- After any code change, re-import modules with `-Force` during testing.
- The remediation engine always verifies actual state after changes — this is by design for audit defensibility.
- STIG Manager collection IDs are resolved dynamically from `global_config.yml` with a safe fallback.

### Automated Cleanup Features

The system now includes built-in retention and inbox hygiene to keep the appliance healthy with minimal manual intervention:

- **STIG Manager Watcher Inbox**: After a successful upload via `run-stigman-watcher.sh`, the copied `_Remediated_*.ckl` file is automatically deleted from `stigman-watcher/inboxes/coll_<id>/`. The authoritative historical copy remains safely in the dated `/reports/` folder. The watcher history YAML file is retained (valuable for troubleshooting upload issues).
- **Reports Retention**: At the end of each remediation run (per vCenter), only the **last 5 date folders** (`YYYYMMDD`) are kept under `/reports/`. Older folders are automatically pruned. This prevents unbounded disk growth while preserving recent operational history.
- **Log Retention**: Structured daily logs (`StigOrchestrator_*.log`), full session transcripts (`Session_Transcript_*.txt`), and cron execution traces (`*_trace.log`) are automatically pruned after **14 days**. This keeps log volume manageable while still providing sufficient history for incident investigation. The long-term `Remediation_History_Master.csv` is **not** subject to this cleanup.

---

## References

- [VMware DoD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation)
- [Broadcom vSphere STIG Automation Tools](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/stig/9-0/vcf-stig-documentation/docs-automation-tools-automation-tools.html)
- STIG Manager / `stigman-watcher` documentation

---