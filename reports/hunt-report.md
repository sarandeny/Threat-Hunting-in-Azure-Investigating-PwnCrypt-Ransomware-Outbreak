#  Threat Hunt Report: Zero-Day Ransomware — PwnCrypt Outbreak Investigation

**Hunt ID:** TH-2026-004  
**Analyst:** Saran  
**Date:** March 28, 2026  
**Platform:** Microsoft Defender for Endpoint (MDE)  
**Target Device:** `saranpc2`  
**Classification:** TLP:WHITE — Suitable for public sharing (sanitised)

>  **Lab Disclaimer:** The ransomware activity was generated in a controlled lab environment using a simulated payload (`pwncrypt.ps1`). The initial access vector is known and does not represent a real-world intrusion method. All findings reflect realistic ransomware behaviour patterns observed in live MDE telemetry.

---

## 1. Executive Summary

Following a CISO directive prompted by news reports of a new ransomware strain — **PwnCrypt** — a threat hunt was initiated across corporate endpoints using known IoCs (`.pwncrypt.*` file extension pattern).

Analysis of `DeviceFileEvents` on `saranpc2` confirmed **active ransomware execution**: multiple files were encrypted using AES-256 and renamed with the `.pwncrypt` extension in rapid succession. Pivoting to `DeviceProcessEvents` around the first encryption timestamp revealed the full attack chain — `cmd.exe` launching `powershell.exe` with `-ExecutionPolicy Bypass` to execute `pwncrypt.ps1` from `C:\ProgramData\`.

The ransom note (`decryption-instructions.txt`) was confirmed delivered to the user's Desktop. Critically, `notepad.exe` was observed opening both an encrypted file (`9165_CompanyFinancials_pwncrypt.csv`) and the ransom note — confirming the ransomware reached its intended **impact phase** and the user was aware of the compromise.

**Verdict: Active Ransomware Compromise Confirmed. Device Isolated. Rebuild Initiated.**

---

## 2. Preparation

### 2.1 Hunt Objective

Determine whether the PwnCrypt ransomware strain — recently reported in the news — has infected any devices on the corporate network, using known IoCs to guide the search.

### 2.2 Threat Intelligence — PwnCrypt Profile

| Attribute | Detail |
|---|---|
| **Strain Name** | PwnCrypt |
| **Payload Type** | PowerShell script |
| **Payload Filename** | `pwncrypt.ps1` |
| **Encryption Algorithm** | AES-256 |
| **Target Directories** | `C:\Users\Public\Desktop`, user-accessible locations |
| **File Rename Pattern** | `[filename].[ext]` → `[filename].pwncrypt.[ext]` |
| **Example** | `hello.txt` → `hello.pwncrypt.txt` |
| **Ransom Note** | `decryption-instructions.txt` |
| **Known IoC** | Any file containing `pwncrypt` in the filename |

### 2.3 Threat Hypothesis

> *"Given the organisation's immature security posture, lack of user training, and unrestricted PowerShell execution environment, PwnCrypt ransomware may have already reached corporate endpoints. The known file extension IoC (`.pwncrypt.*`) provides a reliable starting point for detection."*

### 2.4 Risk Factors Present

| Risk Factor | Impact |
|---|---|
| No user awareness training | Users susceptible to phishing/social engineering delivery |
| PowerShell unrestricted | Payload executable without any policy barriers |
| No Script Block Logging | Script content not captured — reduces visibility |
| No application allowlisting | `pwncrypt.ps1` can execute freely |
| Immature security programme | No baseline behaviour analytics in place |

### 2.5 Key Data Sources

| Table | Purpose |
|---|---|
| `DeviceFileEvents` | Primary — search for `.pwncrypt` IoC in filenames |
| `DeviceProcessEvents` | Secondary — identify execution chain responsible for encryption |

---

## 3. Data Collection

### 3.1 Verify Log Availability

- ✅ `DeviceFileEvents` — Active and populated for `saranpc2`
- ✅ `DeviceProcessEvents` — Active and populated for `saranpc2`

### 3.2 IoC-Based Search Strategy

The known IoC — the `.pwncrypt` extension pattern — allows a **targeted, high-confidence** initial query. Unlike broad behavioural hunts, IoC-led hunts can confirm or deny infection quickly.

**Approach:**
1. Search `DeviceFileEvents` for any filename containing `pwncrypt`
2. If found → note timestamps and confirm file rename pattern
3. Pivot to `DeviceProcessEvents` around those timestamps
4. Reconstruct full execution chain

---

## 4. Data Analysis

### 4.1 IoC-Based File Search — PwnCrypt Detection

The primary hunt query searched for any file on `saranpc2` containing the known PwnCrypt IoC string in its filename.

**Query Used:**
```kql
let VMName = "saranpc2";

DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "pwncrypt"
| order by Timestamp desc
```

**Finding:**

Multiple files matching the `.pwncrypt` pattern were returned across two key event types:

- `FileCreated` — encrypted variants of original files being written
- `FileRenamed` — original files being renamed to include `.pwncrypt` extension

![DeviceFileEvents results — multiple .pwncrypt files detected on saranpc2](../assets/screenshots/01-pwncrypt-file-events.png)

![Extended DeviceFileEvents — FileCreated and FileRenamed events confirming active encryption](../assets/screenshots/02-pwncrypt-file-events-2.png)

**Observations from file event analysis:**

| Observation | Significance |
|---|---|
| Both `FileCreated` and `FileRenamed` events present | Confirms the full encryption workflow — file created encrypted, original renamed |
| Files written to `C:\Windows\Temp` first | Staging in temp directory before surfacing to user — common ransomware pattern |
| Files subsequently moved/renamed to Desktop | Deliberate step to make encrypted files visible to the victim |
| High volume of events in compressed timeframe | Automated execution — not manual file-by-file activity |
| File `9165_CompanyFinancials_pwncrypt.csv` confirmed | Sensitive company financial data encrypted |

> **Analyst Note:** The dual presence of `FileCreated` and `FileRenamed` events is particularly telling. Ransomware typically creates an encrypted copy first (new file), then renames the original — or renames in place. Seeing both event types in rapid sequence for the same files definitively establishes this as ransomware encryption behaviour, not routine file activity.

### 4.2 Timestamped Pivot to Process Events

Taking the timestamp of the first `.pwncrypt` file creation event (`2026-03-28T07:14:47.6594518Z`), a pivot was made to `DeviceProcessEvents` within a ±3 minute window.

**Query Used:**
```kql
let VMName = "saranpc2";
let specificTime = datetime(2026-03-28T07:14:47.6594518Z);

DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, ProcessCommandLine
```

**Finding:**

The full attack execution chain was reconstructed from process events:

![DeviceProcessEvents — cmd.exe → powershell.exe → pwncrypt.ps1 execution chain confirmed](../assets/screenshots/03-process-events-chain.png)

**Execution chain confirmed:**

| Step | Process | Detail |
|---|---|---|
| 1 | `cmd.exe` | Launched PowerShell — common staging pattern |
| 2 | `powershell.exe` | Executed with `-ExecutionPolicy Bypass` to circumvent restrictions |
| 3 | `pwncrypt.ps1` | Ransomware payload executed from `C:\ProgramData\` |
| 4 | File encryption | AES-256 encryption applied across target directories |
| 5 | `notepad.exe` | Opened `9165_CompanyFinancials_pwncrypt.csv` — user confronted with encrypted file |
| 6 | `notepad.exe` | Opened `decryption-instructions.txt` — ransom note read by victim |
| 7 | `OpenWith.exe` | Additional user interaction with encrypted files confirmed |

**Critical finding — user interaction confirmed:**

The observation of `notepad.exe` opening both an encrypted file and the ransom note is significant for two reasons:
1. It confirms the ransomware **fully completed its impact phase** — encryption finished and files surfaced to the user
2. It establishes that the **user is aware of the compromise** — relevant for incident response and communication

---

## 5. Investigation

### 5.1 Full Attack Chain Reconstruction

```
[DELIVERY — Method unknown, likely phishing or web download]
         ↓
pwncrypt.ps1 downloaded to C:\ProgramData\
(via Invoke-WebRequest or similar)
         ↓
cmd.exe launches:
powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1
         ↓
pwncrypt.ps1 executes:
  - Enumerates target files on C:\Users\Public\Desktop and user directories
  - Encrypts each file using AES-256
  - Renames files: [name].[ext] → [name].pwncrypt.[ext]
  - Stages encrypted files in C:\Windows\Temp
  - Moves encrypted files to Desktop for victim visibility
  - Drops decryption-instructions.txt to Desktop
         ↓
User opens decryption-instructions.txt (notepad.exe)
User opens 9165_CompanyFinancials_pwncrypt.csv (notepad.exe)
         ↓
IMPACT PHASE COMPLETE — User confronted with ransom demand
```

### 5.2 Scope Assessment

| Question | Finding |
|---|---|
| Is ransomware active? | ✅ Yes — confirmed on `saranpc2` |
| Is it still running? | ⚠️ Unknown at time of detection — isolation initiated |
| Other devices affected? | Requires investigation — hunt should be expanded org-wide |
| Data exfiltration before encryption? | Not confirmed in this hunt — common in modern ransomware (double extortion) |
| Ransom note delivered? | ✅ Yes — `decryption-instructions.txt` on Desktop |
| User aware? | ✅ Yes — `notepad.exe` opened ransom note |

### 5.3 Expand Hunt to All Devices

A critical next step — check all other corporate endpoints for the same IoC:

```kql
DeviceFileEvents
| where FileName contains "pwncrypt"
| summarize InfectedFiles = count() by DeviceName
| order by InfectedFiles desc
```

Any device appearing in these results should be immediately isolated.

### 5.4 MITRE ATT&CK Correlation

| TTP | Technique | Evidence |
|---|---|---|
| **T1059.001** | PowerShell | `powershell.exe -ExecutionPolicy Bypass -File pwncrypt.ps1` |
| **T1059.003** | Windows Command Shell | `cmd.exe` used to launch PowerShell |
| **T1218.011** | Signed Binary Proxy Execution | PowerShell (signed MS binary) abused |
| **T1105** | Ingress Tool Transfer | `pwncrypt.ps1` downloaded via `Invoke-WebRequest` |
| **T1486** | Data Encrypted for Impact | AES-256 encryption, `.pwncrypt` extension appended |
| **T1566** | Phishing (Potential) | Likely initial delivery — not directly confirmed in logs |
| **T1547** | Boot/Logon Autostart (Potential) | Persistence mechanism — investigate further |

See [`mitre/ttp-mapping.md`](../mitre/ttp-mapping.md) for detailed analysis.

---

## 6. Response

### 6.1 Containment

| Action | Status | Detail |
|---|---|---|
| **Device isolated via MDE** | ✅ Complete | `saranpc2` cut from network — lateral movement prevented |
| **Network connectivity disabled** | ✅ Complete | Device quarantined |
| **Additional endpoints checked** | 🔲 In Progress | Expand IoC hunt across all corporate devices |

### 6.2 Eradication

| Action | Status | Detail |
|---|---|---|
| **Malicious processes terminated** | ✅ Complete | `powershell.exe` instances running `pwncrypt.ps1` killed |
| **Payload removed** | ✅ Complete | `C:\ProgramData\pwncrypt.ps1` and artifacts deleted |
| **Full EDR scan** | ✅ Complete | No additional malicious components detected |

### 6.3 Recovery

| Action | Status | Detail |
|---|---|---|
| **File restoration from backup** | 🔲 In Progress | Restore affected files from last clean backup |
| **Device rebuild** | 🔲 Initiated | Reimage — integrity of system cannot be guaranteed |
| **Credentials reset** | ✅ Complete | Impacted user credentials rotated |

### 6.4 Post-Incident Actions

- [ ] Block PowerShell `-ExecutionPolicy Bypass` via GPO
- [ ] Implement alerting for rapid file rename patterns
- [ ] Deploy application allowlisting (AppLocker/WDAC)
- [ ] Conduct user awareness training
- [ ] Enable PowerShell Script Block Logging
- [ ] Review and harden `C:\ProgramData\` write permissions

---

## 7. Documentation

### 7.1 Evidence Summary

| Evidence | Source |
|---|---|
| Multiple `.pwncrypt` files — `FileCreated` and `FileRenamed` events | `DeviceFileEvents` |
| Files staged in `C:\Windows\Temp`, moved to Desktop | `DeviceFileEvents` (FolderPath) |
| `9165_CompanyFinancials_pwncrypt.csv` — sensitive file confirmed encrypted | `DeviceFileEvents` |
| `cmd.exe` → `powershell.exe -ExecutionPolicy Bypass` chain | `DeviceProcessEvents` |
| `pwncrypt.ps1` executed from `C:\ProgramData\` | `DeviceProcessEvents` (ProcessCommandLine) |
| `notepad.exe` opened encrypted file and ransom note | `DeviceProcessEvents` |
| Execution timestamp: `2026-03-28T07:14:47.6594518Z` | `DeviceProcessEvents` |

---

## 8. Improvement

### 8.1 Detection Gaps

| Gap | Impact | Fix |
|---|---|---|
| No IoC-based alert for `.pwncrypt` extension | Infection ran undetected until manual hunt | Create file extension alert rule |
| No alert for rapid file renames | Ransomware encryption ran undetected | Alert on >50 file renames per minute per device |
| No PowerShell logging | Script content not captured in real time | Enable Script Block Logging via GPO |
| No application allowlisting | `pwncrypt.ps1` executed without any policy barrier | Deploy AppLocker/WDAC |
| Immature security programme | No baseline to detect behavioural anomalies | Establish endpoint hardening baseline |

### 8.2 Detection Engineering Opportunities

This hunt produced four high-value detection rules — see [`queries/kql-queries.md`](../queries/kql-queries.md):

1. **Known Ransomware Extension Alert** — file creation with `.pwncrypt` or other known ransomware extensions
2. **Rapid File Rename Detector** — >50 file renames per minute (generic ransomware behaviour)
3. **PowerShell from ProgramData** — any PowerShell script executing from `C:\ProgramData\`
4. **Ransom Note Detector** — creation of files named `decrypt`, `ransom`, or `readme` in common locations

### 8.3 Threat Hunting Improvements

- **Expand IoC hunts org-wide immediately** — never scope to a single device; ransomware spreads
- **Check for double extortion** — modern ransomware often exfiltrates before encrypting; correlate with `DeviceNetworkEvents`
- **Timeline correlation template** — the ±3 minute pivot from file events to process events should be a standard playbook step for any file-based threat
- **Develop a ransomware IoC library** — maintain a list of known ransomware extension patterns for rapid hunting

---

*Report authored by: Saran | CyberRange Lab | March 28, 2026*
