# VMware STIG Tools Appliance Customization & Orchestration

## Overview
This repository contains the custom wrapper scripts, orchestration modules, helper libraries, and `EvaluateSTIG` answer files tailored for our VMware environment. 

By separating our customized configurations from the core VMware STIG Automation OVA, we treat the appliance as **ephemeral infrastructure**. When VMware releases a new OVA version, we simply deploy a fresh appliance, run the bootstrap commands below to prepare the OS, and pull this repository to layer our custom logic back on top.

This project automates STIG compliance checks across:
1. **vCenter Server Appliances (VCSA)** - 10 components (vCenter API, and 9 OS services like Envoy, PostgreSQL, etc.)
2. **ESXi Hosts** - Hypervisor STIG audits (API and SSH-based)
3. **Virtual Machines (VMs)** - VM guest and hardware settings audits via vCenter API

## Directory & File Structure

This repository is organized into a modular structure to ensure high maintainability, secure credential handling, and seamless execution. Below is an overview of the key files included:

### 1. Master Controllers & Orchestration
*   **`StigOrchestration.psm1`**: The master orchestration engine. Handles dynamic inventory discovery via PowerCLI, routes targets to specific workers, coordinates parallel processing, generates section summaries, and handles STIG Manager integration sync.
*   **`globalFunctions.psm1`**: Core utility library containing universally required functions for structured logging (dual-channel: App Log + Session Transcript), template matching, answer-file XML parsing, and XML checklist merging.

### 2. Platform Workers & Helper Modules
*   **`Invoke-VcsaAudit.psm1`** & **`VcsaHelpers.psm1`**: Executes VCSA STIG audits. Toggles SSH securely, verifies the `/bin/bash` root shell, runs parallel InSpec audits across all 10 VCSA sub-components, and disables SSH upon completion.
*   **`Invoke-EsxiAudit.psm1`** & **`EsxiHelpers.psm1`**: Performs audits on ESXi hosts. Handles the three-phase approach of disabling Lockdown Mode, enabling SSH, running InSpec, and restoring ESXi back to its secure locked state.
*   **`Invoke-VmAudit.psm1`** & **`VmHelpers.psm1`**: Audits VMs in parallel (batches of 40) via the vCenter API using PowerCLI to collect guest and network metadata.

### 3. Bash Cron & Execution Wrappers
*   **`run-cron-vcsa.sh`**: Scheduled cron wrapper for VCSA STIG audits.
*   **`run-cron-esxi.sh`**: Scheduled cron wrapper for ESXi STIG audits.
*   **`run-cron-vm.sh`**: Scheduled cron wrapper for VM STIG audits.
*   **`run-stigman-watcher.sh`**: Unix wrapper that triggers `stigman-watcher` to upload newly generated `.ckl` files to a STIG Manager collection inbox cleanly.

### 4. Security & Vault Configuration
*   **`CredentialManagement.psm1`**: Local secure vault using AES-256 CBC encryption. Dynamically generates an encryption key (`vault.key`) and securely manages credentials for VCSA Admin, VCSA Root, and ESXi Root without storing them in plaintext.

---

## Initial OVA Setup (Bootstrapping)
The VMware STIG appliance runs on a locked-down version of Photon OS. In heavily restricted or proxied environments, the default package manager (`tdnf`) may fail due to SSL inspection or routing rules. 

Run the following commands as `root` (or with `sudo`) on a freshly deployed OVA to bypass SSL restrictions, enable SSH TCP forwarding, and install Git.

```bash
# 1. Remove any existing global SSL verification rules in tdnf
sudo sed -i '/sslverify=/d' /etc/tdnf/tdnf.conf

# 2. Disable SSL verification specifically for the Photon repository
sudo sed -i 's/sslverify=1/sslverify=0/g' /etc/yum.repos.d/photon.repo

# 3. Configure SSH to permit TCP Forwarding (for VisualStudioCode Tunneling)
sudo sed -i 's/^\[# \]*AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config

# 4. Restart SSH Daemon to apply the configuration change
sudo systemctl restart sshd

# 5. Clean package cache, update repositories, and install Git
sudo tdnf clean all
sudo tdnf update -y
sudo tdnf install git -y
```

##  Deploying this Repository

Once Git is installed on the appliance, clone this repository into the OVA's staging directory. Note: You will need a GitLab Project/Personal Access token to authenticate.

```bash
# 1. Target directory for custom overlays
sudo mkdir -p /usr/share/stigs/custom

# 2. Clone repository using OAuth2 Token (Replace <YOUR_TOKEN_HERE>)
git clone https://oauth2:<YOUR_TOKEN_HERE>@web.git.mil/peter.j.stearns.ctr/vmware-stig-wrapper.git /usr/share/stigs/custom

# 3. Navigate to the directory
cd /usr/share/stigs/custom

# 4. Configure Git identity and credential storage
git config --global credential.helper store
git config --global user.name "OVA Automation"
git config --global user.email "peter.j.stearns.ctr@army.mil"
```

## Credential Management (Secure Vault)
This wrapper uses a true AES-256 encrypted local vault to store vCenter, VCSA root, and ESXi root passwords. **No credentials are stored in plain text or tracked in Git.**

To add, update, or remove credentials for the automation engine, run the interactive Credential Manager on the OVA:

```bash
pwsh
Import-Module /usr/share/stigs/custom/modules/CredentialManagement.psm1 -Force
Invoke-CredentialManager -FilePath "/usr/share/stigs/custom/conf/.creds.json.encrypted"
```
---

##  How to Run the Audits
### 1. Scheduled Execution (Cron)

Cron scripts are located in /usr/share/stigs/orchestration_overlay/bin/. They run headless, logging all output to their respective execution trace logs inside /usr/share/stigs/orchestration_overlay/logs/.
To execute manually:

```bash
# To run VCSA Audits
/usr/share/stigs/orchestration_overlay/bin/run-cron-vcsa.sh

# To run ESXi Audits
/usr/share/stigs/orchestration_overlay/bin/run-cron-esxi.sh

# To run VM Audits
/usr/share/stigs/orchestration_overlay/bin/run-cron-vm.sh
```
### 2. Manual CLI Execution (PowerShell)
You can manually run specific orchestration pathways by importing the master module:

```Powershell
pwsh
Import-Module /usr/share/stigs/orchestration_overlay/modules/StigOrchestration.psm1 -Force

# Run a dedicated VCSA audit
Invoke-MultiVcsaOrchestration -OverlayRoot "/usr/share/stigs/orchestration_overlay"

# Run a dedicated ESXi audit
Invoke-MultiEsxiOrchestration -OverlayRoot "/usr/share/stigs/orchestration_overlay"

# Run a dedicated VM audit
Invoke-MultiVmOrchestration -OverlayRoot "/usr/share/stigs/orchestration_overlay"
```

##  Outputs & Reporting

JSON Reports: Temporary raw files are written to /tmp/stig_staging/<target_name>.

DISA CKL Checklists: Automatically generated, merged with overlays and answers/justifications, and stored by date and vCenter in /usr/share/stigs/orchestration_overlay/reports/YYYYMMDD/<vCenter_Short_Name>/[VCSA|ESXi|VMs]/.

Centralized CSV Summary: Long-term historical data is logged to:

```
/usr/share/stigs/orchestration_overlay/reports/Open_Items_Summary_VCSA.csv

/usr/share/stigs/orchestration_overlay/reports/Open_Items_Summary_ESXi.csv

/usr/share/stigs/orchestration_overlay/reports/Open_Items_Summary_VMs.csv
```

Execution Logs: Trace logs and diagnostic transcripts are captured inside /usr/share/stigs/orchestration_overlay/logs/.

---