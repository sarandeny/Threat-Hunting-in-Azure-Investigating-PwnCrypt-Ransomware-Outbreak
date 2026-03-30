# Threat Hunt: Zero-Day Ransomware — PwnCrypt Outbreak Investigation

> **Platform:** Microsoft Defender for Endpoint (MDE) + Azure CyberRange  
> **Analyst:** Saran  
> **Hunt Date:** March 28, 2026  
> **Severity:** 🔴 Critical — Active Ransomware Confirmed  
> **Status:** ✅ Contained — Device Isolated, Rebuild Required

---

## 📋 Table of Contents

- [Overview](#overview)
- [Scenario Background](#scenario-background)
- [Hunt Methodology](#hunt-methodology)
- [Key Findings](#key-findings)
- [Attack Chain Summary](#attack-chain-summary)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Response Actions Taken](#response-actions-taken)
- [Lessons Learned](#lessons-learned)
- [KQL Query Reference](#kql-query-reference)
- [Project Structure](#project-structure)
- [Tools & Technologies](#tools--technologies)

---

## Overview

This repository documents a **threat hunting exercise** simulating a real-world ransomware outbreak response, conducted in a live Azure CyberRange environment using **Microsoft Defender for Endpoint (MDE)** and **Kusto Query Language (KQL)**. The hunt was triggered after the CISO raised concerns following news reports of a new ransomware strain — **PwnCrypt** — actively spreading across corporate networks.

The investigation confirmed that `saranpc2` was **actively compromised** by PwnCrypt ransomware. A PowerShell script (`pwncrypt.ps1`) was executed via `cmd.exe` with `-ExecutionPolicy Bypass`, encrypting files using **AES-256** and appending a `.pwncrypt` extension. A ransom note (`decryption-instructions.txt`) was delivered to the user's Desktop, and user interaction with the encrypted files was confirmed via `notepad.exe` process events.

**Bottom Line Up Front (BLUF):** PwnCrypt ransomware was confirmed active on `saranpc2`. The full attack chain — from PowerShell execution to file encryption to ransom note delivery — was reconstructed using MDE telemetry. The device was isolated and a rebuild was initiated.

---

## Scenario Background

A new ransomware strain named **PwnCrypt** was announced in the news. Known characteristics:

- **Payload:** PowerShell-based (`pwncrypt.ps1`)
- **Encryption:** AES-256
- **Target directories:** `C:\Users\Public\Desktop` and user-accessible locations
- **File renaming pattern:** `hello.txt` → `hello.pwncrypt.txt`
- **Ransom note:** `decryption-instructions.txt` dropped to Desktop

The organisation's security posture presented significant risk factors:

- Immature security programme — no formal endpoint hardening
- No user awareness training — employees susceptible to phishing
- PowerShell unrestricted — no execution policy enforced
- No Script Block Logging — script content not captured in real time

**Hypothesis:**
> *"Given the organisation's immature security posture and lack of user training, PwnCrypt may have already reached the corporate network. Known IoCs (`.pwncrypt.*` file extension pattern) can be used to hunt for evidence of active infection."*

---

## Hunt Methodology

This investigation follows the structured **Threat Hunting Lifecycle**:

```
1. Preparation  →  2. Data Collection  →  3. Data Analysis
       ↑                                         ↓
7. Improvement  ←  6. Documentation  ←  4. Investigation
                                         ↓
                                    5. Response
```

For the full step-by-step walkthrough, see [`reports/hunt-report.md`](reports/hunt-report.md).

---

## Key Findings

| Finding | Detail |
|---|---|
| **Affected Device** | `saranpc2` |
| **Ransomware Strain** | PwnCrypt |
| **Payload** | `C:\ProgramData\pwncrypt.ps1` |
| **Execution Method** | `cmd.exe` → `powershell.exe -ExecutionPolicy Bypass` |
| **Encryption Algorithm** | AES-256 |
| **File Extension Added** | `.pwncrypt` (e.g., `hello.txt` → `hello.pwncrypt.txt`) |
| **Confirmed Encrypted Files** | Multiple — including `9165_CompanyFinancials_pwncrypt.csv` |
| **Ransom Note** | `decryption-instructions.txt` dropped to Desktop |
| **Staging Directories** | `C:\Windows\Temp` → files moved to Desktop post-encryption |
| **User Interaction Confirmed** | `notepad.exe` opened encrypted file and ransom note |
| **Execution Timestamp** | `2026-03-28T07:14:47.6594518Z` |

---

## Attack Chain Summary

```
cmd.exe
  └─→ powershell.exe -ExecutionPolicy Bypass
        └─→ pwncrypt.ps1 executes
              ├─→ Files encrypted with AES-256
              ├─→ .pwncrypt extension appended
              ├─→ Encrypted files written to C:\Windows\Temp
              ├─→ Files moved/renamed to Desktop
              └─→ decryption-instructions.txt dropped to Desktop
                    └─→ notepad.exe opens ransom note (user impact confirmed)
```

---

## MITRE ATT&CK Mapping

| TTP ID | Technique | Tactic | Observed |
|---|---|---|---|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution | `pwncrypt.ps1` run via `-ExecutionPolicy Bypass` |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution | `cmd.exe` used to launch PowerShell |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Signed Binary Proxy Execution: Rundll32 | Defense Evasion | PowerShell (signed MS binary) abused to run malicious script |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command & Control | `pwncrypt.ps1` downloaded via `Invoke-WebRequest` |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Impact | AES-256 encryption of files with `.pwncrypt` extension |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing (Potential Initial Access) | Initial Access | Likely delivery vector — not directly observed in logs |
| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence | Potential persistence mechanism — investigate further |

See [`mitre/ttp-mapping.md`](mitre/ttp-mapping.md) for full analysis.

---

## Response Actions Taken

**Containment:**
1. **Device isolated via MDE** — `saranpc2` removed from network to prevent lateral movement
2. **Network connectivity disabled** — device placed in quarantine

**Eradication:**
3. **Malicious processes terminated** — `powershell.exe` instances running `pwncrypt.ps1` killed
4. **Payload removed** — `C:\ProgramData\pwncrypt.ps1` and associated artifacts deleted
5. **Full EDR scan** — endpoint scanned for residual malicious components

**Recovery:**
6. **File restoration** — affected files restored from clean backups where available
7. **Rebuild initiated** — device reimaged as integrity could not be guaranteed
8. **Credentials reset** — impacted user credentials rotated

---

## Lessons Learned

- 🔴 **IoC-led hunting works** — knowing the `.pwncrypt.*` file pattern let us immediately pivot to confirmation in `DeviceFileEvents`
- 🔴 **Ransomware leaves a clear signature** — rapid `FileCreated` + `FileRenamed` events in a compressed timeframe is unmistakable
- 🔴 **User impact confirms execution** — `notepad.exe` opening the ransom note is a critical data point proving the attack reached its intended impact
- 🟡 **Temp directory staging** — files processed in `C:\Windows\Temp` before surfacing to Desktop is a common ransomware pattern to watch for
- 🟢 **Timestamp pivoting** — pulling process events within ±3 minutes of the first encrypted file creation pinpointed the attack chain instantly
- 🟢 **MDE telemetry survived encryption** — even though files were encrypted, MDE log data remained intact and queryable

---

## KQL Query Reference

All KQL queries used in this hunt are documented in [`queries/kql-queries.md`](queries/kql-queries.md), including:

- IoC-based file search for `.pwncrypt` extensions
- Timestamped process event pivot to identify execution chain
- Rapid file rename detection (ransomware behaviour pattern)
- Detection engineering rules for ransomware early warning

---

## Project Structure

```
📁 soc-ransomware-pwncrypt/
├── 📄 README.md                          ← You are here
├── 📁 reports/
│   └── 📄 hunt-report.md                 ← Full investigation report
├── 📁 queries/
│   └── 📄 kql-queries.md                 ← All KQL queries with explanations
├── 📁 mitre/
│   └── 📄 ttp-mapping.md                 ← MITRE ATT&CK framework mapping
├── 📁 playbooks/
│   └── 📄 ransomware-response.md         ← IR playbook for ransomware scenarios
└── 📁 assets/
    ├── 📄 timeline.md                    ← Attack timeline reconstruction
    └── 📁 screenshots/
        ├── 📄 README.md                  ← Screenshot index
        ├── 01-pwncrypt-file-events.png   ← DeviceFileEvents showing encrypted files
        ├── 02-pwncrypt-file-events-2.png ← Extended file event results
        └── 03-process-events-chain.png   ← Process chain — cmd → powershell → pwncrypt
```

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| **Microsoft Defender for Endpoint (MDE)** | Endpoint telemetry, containment, and EDR scanning |
| **Kusto Query Language (KQL)** | IoC-based hunting across File and Process events |
| **Microsoft Sentinel / MDE Portal** | SIEM/XDR query interface |
| **MITRE ATT&CK Navigator** | TTP mapping and kill chain analysis |
| **Azure CyberRange** | Lab environment for hands-on simulation |
| **PwnCrypt (`pwncrypt.ps1`)** | Simulated ransomware payload (controlled lab environment) |

---

##  Lab Disclaimer

> The ransomware activity in this investigation was generated in a **controlled lab environment** using a simulated payload (`pwncrypt.ps1`) executed via PowerShell. The initial access vector is known and does not represent a real-world intrusion method such as phishing or exploitation. All findings reflect realistic ransomware behaviour patterns observed in live MDE telemetry.

---

## About This Project

This project was completed as part of a **CyberRange ransomware response exercise** simulating a real-world SOC analyst investigation. It demonstrates:

- IoC-led threat hunting using known ransomware signatures
- File and process event correlation to reconstruct a ransomware kill chain
- MITRE ATT&CK framework application across 7 TTPs
- Full incident response lifecycle — from detection through containment and recovery
- Ransomware-specific detection engineering

> 💡 *If you're a recruiter or fellow analyst reviewing this — all queries were executed against live MDE telemetry in a sandboxed Azure environment. Findings are real.*

---

*Last updated: March 28, 2026 | Author: Saran*
