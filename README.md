# VMware STIG Tools Appliance Customization (Wrapper)

## Overview
This repository contains the custom wrapper scripts and `EvaluateSTIG` answer files tailored for our environment. 

By separating our customized configurations from the core VMware STIG Automation OVA, we treat the appliance as **ephemeral infrastructure**. When VMware releases a new OVA version, we simply deploy a fresh appliance, run the bootstrap commands below to prepare the OS, and pull this repository to layer our custom logic back on top.

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

## Repository Structure

/scripts/ - Contains custom bash/wrapper scripts that orchestrate the VMware tooling (inspec, powercli) using our environment variables.

/templates/ - Contains our customized EvaluateSTIG .yml and .json answer files, including documented exceptions and known-open items.