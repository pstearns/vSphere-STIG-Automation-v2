# NetApp ONTAP DSC 9.x STIG v2r4 - InSpec Automation Mapping

**STIG**: NetApp ONTAP DSC 9.x Security Technical Implementation Guide  
**Version**: 2, Release 4 (Benchmark Date: 01 Jul 2026)  
**Source Checklist**: HUAFNAC_U_NetApp_ONTAP_DSC_9-x_V2R4.ckl  
**Profile Owner**: Department of War Automation Team  
**Last Updated**: 2026-08-19  
**Total Rules Analyzed**: 29

---

## Purpose

This document provides a complete mapping of the NetApp ONTAP STIG checklist to InSpec controls. It serves as the authoritative reference for building and maintaining the `netapp` InSpec profile.

---

## Automation Feasibility Summary

| Category                    | Count | Percentage | Recommendation |
|----------------------------|-------|------------|----------------|
| ✅ Fully Automatable via SSH | 24    | 83%        | Build as standard InSpec controls |
| ⚠️ Partially Automatable     | 4     | 14%        | Use answer file or remote data source |
| ❌ Not Applicable / Manual   | 1     | 3%         | Mark as `not_applicable` or manual review |

**Overall Assessment**: Excellent candidate for automation. ~85%+ coverage is realistic with moderate effort.

---

## Detailed Rule Mapping

### Access Control (AC)

| Vuln ID   | Rule_Ver          | Rule Title                                      | ONTAP CLI Command                                      | InSpec Feasibility | Answer File Needed? | Implementation Notes |
|-----------|-------------------|-------------------------------------------------|--------------------------------------------------------|--------------------|---------------------|----------------------|
| V-246922 | NAOT-AC-000001   | Limit concurrent sessions                       | `security session limit show -interface cli`           | ✅ High            | No                  | Parse `Max-Active` for `application` category |
| V-246923 | NAOT-AC-000002   | Create session lock after 15 minutes            | `system timeout show`                                  | ✅ High            | No                  | Must be ≤ 15 minutes |
| V-246925 | NAOT-AC-000004   | Automatically audit account-enabling actions    | `cluster log-forwarding show`                          | ⚠️ Medium          | Partial             | Verify at least one remote syslog destination |
| V-246926 | NAOT-AC-000005   | Only one local "account of last resort"         | `security login show -role admin`                      | ⚠️ Medium          | **Yes**             | Designate official last-resort account |
| V-246927 | NAOT-AC-000006   | Enforce admin privileges by role                | `security login role show`                             | ✅ High            | No                  | Validate role separation |
| V-246928 | NAOT-AC-000009   | Prevent non-privileged users from privileged functions | `security login role show`                        | ✅ High            | No                  | Check capabilities of non-admin roles |
| V-246929 | NAOT-AC-000010   | 3 consecutive failed logon attempts             | `security login role config show`                      | ✅ High            | No                  | Check `passwd-lockout-after-failures` |
| V-246930 | NAOT-AC-000011   | Display DoD banner before granting access       | `system login banner show`                             | ✅ High            | No                  | Validate banner content |

### Audit and Accountability (AU)

| Vuln ID   | Rule_Ver          | Rule Title                                      | ONTAP CLI Command                                      | InSpec Feasibility | Answer File Needed? | Implementation Notes |
|-----------|-------------------|-------------------------------------------------|--------------------------------------------------------|--------------------|---------------------|----------------------|
| V-246931 | NAOT-AU-000001   | Allocate audit record storage capacity          | `df MDV*` or `volume show -fields size,used`           | ✅ High            | No                  | Check audit volume capacity |
| V-246932 | NAOT-AU-000003   | Audit guarantee enabled                         | `vserver audit show`                                   | ✅ High            | No                  | Verify `guarantee` setting |
| V-246933 | NAOT-AU-000004   | Time synchronization (NTP)                      | `cluster time-service ntp server show`                 | ✅ High            | No                  | Check NTP servers and authentication |
| V-246934 | NAOT-AU-000006   | Audit record timestamps                         | `cluster date show` + NTP config                       | ✅ High            | No                  | Validate time source |

### Configuration Management (CM)

| Vuln ID   | Rule_Ver          | Rule Title                                      | ONTAP CLI Command                                      | InSpec Feasibility | Answer File Needed? | Implementation Notes |
|-----------|-------------------|-------------------------------------------------|--------------------------------------------------------|--------------------|---------------------|----------------------|
| V-246935 | NAOT-CM-000001   | Access restrictions for configuration changes   | `security login role show`                             | ✅ High            | No                  | Role-based change control |
| V-246936 | NAOT-CM-000002   | Use multifactor authentication via auth server  | `security login show -fields authentication-method`    | ✅ High            | No                  | Check for domain / certificate methods |
| V-246937 | NAOT-CM-000007   | Perform system-level backups                    | `system configuration backup show`                     | ✅ High            | No                  | Verify backup jobs exist |
| V-246938 | NAOT-CM-000008   | Use DoD-approved PKI certificates               | `security certificate show`                            | ⚠️ Medium          | **Yes**             | Maintain approved CA list |
| V-246939 | NAOT-CM-000009   | Disable unnecessary services/protocols          | `network interface service-policy show`                | ✅ High            | No                  | Validate only required services |

### Identification and Authentication (IA)

| Vuln ID   | Rule_Ver          | Rule Title                                      | ONTAP CLI Command                                      | InSpec Feasibility | Answer File Needed? | Implementation Notes |
|-----------|-------------------|-------------------------------------------------|--------------------------------------------------------|--------------------|---------------------|----------------------|
| V-246940 | NAOT-IA-000001   | Authenticate admin before granting access       | `security login show`                                  | ✅ High            | No                  | Local + domain accounts |
| V-246941 | NAOT-IA-000002   | Use replay-resistant authentication             | `security login show -fields authentication-method`    | ✅ High            | No                  | Check for Kerberos / certificate |
| V-246942 | NAOT-IA-000003   | SNMPv3 with FIPS-validated crypto               | `snmp show`                                            | ❌ N/A             | -                   | SNMP typically disabled |
| V-246943 | NAOT-IA-000004   | Authenticate NTP server                         | `cluster time-service ntp server show -fields authentication` | ✅ High     | No                  | Verify NTP authentication |
| V-246944 | NAOT-IA-000005   | Minimum 15-character password                   | `security login role config show -fields passwd-minlength` | ✅ High     | No                  | Check `passwd-minlength >= 15` |
| V-246945 | NAOT-IA-000006   | Password complexity - special characters        | `security login role config show -fields passwd-min-special-chars` | ✅ High | No                  | Check minimum special chars |
| V-246946 | NAOT-IA-000007   | Password complexity - uppercase                 | `security login role config show -fields passwd-min-uppercase-chars` | ✅ High | No                  | Check minimum uppercase |
| V-246947 | NAOT-IA-000008   | Password complexity - lowercase                 | `security login role config show -fields passwd-min-lowercase-chars` | ✅ High | No                  | Check minimum lowercase |
| V-246948 | NAOT-IA-000009   | Password complexity - numbers                   | `security login role config show -fields passwd-min-digits` | ✅ High     | No                  | Check minimum digits |

### Maintenance (MA)

| Vuln ID   | Rule_Ver          | Rule Title                                      | ONTAP CLI Command                                      | InSpec Feasibility | Answer File Needed? | Implementation Notes |
|-----------|-------------------|-------------------------------------------------|--------------------------------------------------------|--------------------|---------------------|----------------------|
| V-246958 | NAOT-MA-000002   | Implement cryptographic mechanisms using FIPS 140-2 | `security config show` (advanced)                 | ✅ High            | No                  | Check `is-fips-enabled: true` |

### System and Communications Protection (SC)

| Vuln ID   | Rule_Ver          | Rule Title                                      | ONTAP CLI Command                                      | InSpec Feasibility | Answer File Needed? | Implementation Notes |
|-----------|-------------------|-------------------------------------------------|--------------------------------------------------------|--------------------|---------------------|----------------------|
| V-246959 | NAOT-SC-000001   | Terminate idle sessions after 10 minutes        | `system timeout show`                                  | ✅ High            | No                  | Must be ≤ 10 minutes |

### System and Information Integrity (SI)

| Vuln ID   | Rule_Ver          | Rule Title                                      | ONTAP CLI Command                                      | InSpec Feasibility | Answer File Needed? | Implementation Notes |
|-----------|-------------------|-------------------------------------------------|--------------------------------------------------------|--------------------|---------------------|----------------------|
| V-246964 | NAOT-SI-000001   | Send audit log data to central log server       | `cluster log-forwarding show`                          | ✅ High            | No                  | At least one remote destination configured |

---

## Implementation Recommendations

### High Priority Controls (Build First)
1. Password policy controls (NAOT-IA-000005 through NAOT-IA-000009)
2. FIPS mode (NAOT-MA-000002)
3. Session limits and timeouts (NAOT-AC-000001, NAOT-AC-000002, NAOT-SC-000001)
4. Remote logging (NAOT-SI-000001)
5. Banner (NAOT-AC-000011)

### Controls Requiring Answer File
- **NAOT-AC-000005** — "Account of last resort" designation
- **NAOT-CM-000008** — Approved CA list for certificate validation

### Helper Library Needed
Create `libraries/ontap_command.rb` (modeled after `powercli_command.rb` in the ESXi profile) to wrap SSH commands to ONTAP.

---

## File Naming Convention for InSpec Controls

All control files should follow this naming:
- `NAOT-AC-000001.rb`
- `NAOT-IA-000005.rb`
- etc.

This matches the `Rule_Ver` field and makes mapping trivial.

---

*This document is the single source of truth for the NetApp InSpec profile scope and implementation approach.*

**Overall Automation Potential**: Very High (~85-90%)

---

## Next Functions to Implement (Priority Order)

1. Password policy checks (length + complexity)
2. FIPS mode validation
3. Role-based access / privileged function checks
4. Logging / audit forwarding validation
5. Session timeout and concurrent session limits
6. NTP authentication status

---
*Last Updated: 2026-08-19*