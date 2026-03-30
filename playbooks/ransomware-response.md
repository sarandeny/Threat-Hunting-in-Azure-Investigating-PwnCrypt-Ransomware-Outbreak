#  Incident Response Playbook
## Scenario: Active Ransomware — PwnCrypt / PowerShell-Based Encryption

**Playbook ID:** IR-PB-004  
**Version:** 1.0  
**Last Updated:** March 28, 2026  
**Classification:** TLP:WHITE

---

## Purpose

This playbook provides a structured, repeatable process for detecting, containing, and recovering from ransomware incidents — specifically those involving PowerShell-based payloads and known file extension IoCs. Designed for **Tier 1 and Tier 2 SOC analysts** using Microsoft Defender for Endpoint (MDE).

>  **Speed matters in ransomware.** Every second the ransomware runs, more files are encrypted. Containment must happen as fast as possible — but not before evidence is preserved.

---

## Trigger Conditions

Initiate this playbook when **any of the following** are true:

- [ ] A user reports files are encrypted or inaccessible
- [ ] A user reports seeing a ransom note
- [ ] A detection rule fires for known ransomware file extensions
- [ ] MDE alert fires for mass file rename or create events
- [ ] Detection rule fires for `powershell.exe -ExecutionPolicy Bypass` from a suspicious path
- [ ] CISO/management directive following threat intelligence about a new ransomware strain

---

## Severity Classification

| Severity | Criteria |
|---|---|
| 🔴 **Critical** | Active encryption confirmed — ransomware currently running |
| 🔴 **Critical** | Encryption complete — ransom note delivered, files inaccessible |
| 🟠 **High** | Ransomware payload on disk — not yet confirmed executing |
| 🟡 **Medium** | IoC match on a device — not yet confirmed as active infection |

**This hunt:** 🔴 Critical — Active encryption confirmed, ransom note delivered, user impact confirmed.

---

## ⚡ Immediate Priority: Contain Before Investigating

Unlike most incidents, ransomware requires **containment first**. Every minute of delay = more encrypted files. However, you still need to preserve enough evidence to understand the scope.

**30-Second Triage — Answer These Questions First:**
1. Is ransomware currently running? (Check for active `powershell.exe` processes)
2. Is it on one device or multiple?
3. Is the ransom note already delivered? (Impact complete = less urgency to contain *immediately* vs. ongoing = maximum urgency)

---

## Phase 1: Detection & Rapid Triage

**Target time: Under 10 minutes**

### Step 1.1 — IoC-Based Sweep

If a ransomware strain is known, use the IoC immediately:

```kql
// Replace "pwncrypt" with the known strain's extension IoC
DeviceFileEvents
| where FileName contains "pwncrypt"
| summarize InfectedFiles = count(), FirstSeen = min(Timestamp) by DeviceName
| order by InfectedFiles desc
```

- [ ] Which devices are infected?
- [ ] How many files are encrypted?
- [ ] When did encryption begin? (`FirstSeen`)
- [ ] Is it spreading? (Multiple devices = network-level response required)

### Step 1.2 — Check if Ransomware Is Still Running

```kql
DeviceProcessEvents
| where DeviceName == "<INFECTED_DEVICE>"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any("pwncrypt", "Bypass", "encrypt")
| where Timestamp > ago(10m)
```

- [ ] If active processes found → **Isolate device immediately**
- [ ] If no recent processes → Encryption may be complete — still isolate, but less urgency

### Step 1.3 — Confirm Ransomware Extension Pattern

```kql
DeviceFileEvents
| where DeviceName == "<INFECTED_DEVICE>"
| where FileName contains "pwncrypt"
| where ActionType in ("FileCreated", "FileRenamed")
| project Timestamp, ActionType, FileName, FolderPath
| order by Timestamp asc
```

- [ ] Both `FileCreated` and `FileRenamed` events present? → Encryption workflow confirmed
- [ ] Note the earliest timestamp — this is when the attack started

---

## Phase 2: Containment

**Target time: Within 15 minutes of detection**

### Step 2.1 — Isolate All Infected Devices

**Via MDE Portal (for each infected device):**
1. Navigate to the device page
2. **Device actions** → **Isolate device**
3. Select **Full isolation**
4. Document isolation time

**Why isolation is critical:**
- Stops active encryption immediately
- Prevents lateral movement to other network shares and devices
- Prevents C2 communication (some ransomware exfiltrates data or receives new encryption keys)
- MDE telemetry and Live Response remain available post-isolation

### Step 2.2 — Identify Shared Network Resources

Ransomware frequently targets mapped network drives and shared folders:

```kql
DeviceFileEvents
| where DeviceName == "<INFECTED_DEVICE>"
| where FileName contains "pwncrypt"
| where FolderPath startswith "\\\\"  // UNC paths = network shares
| summarize count() by FolderPath
```

- [ ] Any network share paths in results? → Those shares may also be encrypted
- [ ] Identify all devices with access to those shares → potential additional victims

### Step 2.3 — Terminate Malicious Processes (via Live Response)

If ransomware is still running, terminate via MDE Live Response:

```
# In MDE Live Response console:
processes
# Identify powershell.exe PID running the ransomware script
kill <PID>
```

---

## Phase 3: Evidence Collection

**Do this in parallel with containment — before any remediation**

### Step 3.1 — Capture Full Attack Chain

```kql
// Full process chain around ransomware execution
let EncryptionStart = datetime(YYYY-MM-DDTHH:MM:SSZ);

DeviceProcessEvents
| where DeviceName == "<INFECTED_DEVICE>"
| where Timestamp between ((EncryptionStart - 5m) .. (EncryptionStart + 5m))
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

### Step 3.2 — Document All Encrypted Files

```kql
DeviceFileEvents
| where DeviceName == "<INFECTED_DEVICE>"
| where FileName contains "pwncrypt"
| project Timestamp, ActionType, FileName, FolderPath, SHA1
| order by Timestamp asc
```

Export this — it's your list of files that need restoration from backup.

### Step 3.3 — Check for Data Exfiltration (Double Extortion Check)

```kql
let EncryptionStart = datetime(YYYY-MM-DDTHH:MM:SSZ);

DeviceNetworkEvents
| where DeviceName == "<INFECTED_DEVICE>"
| where Timestamp between ((EncryptionStart - 60m) .. EncryptionStart)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort
```

- [ ] Any outbound connections to cloud storage or unknown IPs before encryption started?
- [ ] If yes → double extortion likely → notify legal immediately

### Step 3.4 — Check for Persistence Mechanisms

```kql
DeviceRegistryEvents
| where DeviceName == "<INFECTED_DEVICE>"
| where RegistryKey has_any("CurrentVersion\\Run", "CurrentVersion\\RunOnce", "Winlogon")
| where Timestamp > datetime(<BEFORE_INFECTION_TIME>)
| order by Timestamp desc
```

- [ ] Any new registry autostart keys? → Persistence installed → must be removed before recovery

---

## Phase 4: Eradication

**Only after containment and evidence collection**

### Step 4.1 — Remove Ransomware Payload

Via MDE Live Response or direct device access:

```powershell
# Remove ransomware script
Remove-Item "C:\ProgramData\pwncrypt.ps1" -Force

# Check for additional dropped files
Get-ChildItem "C:\ProgramData\" | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-1) }

# Remove ransom note (optional — preserve as evidence first)
Remove-Item "$env:USERPROFILE\Desktop\decryption-instructions.txt"
```

### Step 4.2 — Full EDR Scan

Run a full MDE antivirus scan:
- MDE Portal → Device page → **Run antivirus scan** → Full scan
- Document the result

### Step 4.3 — Remove Persistence (if found)

If registry persistence was found in Step 3.4:

```powershell
# Example — remove autostart registry key
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "<MALICIOUS_KEY>"
```

---

## Phase 5: Recovery

### Step 5.1 — Restore Files from Backup

- [ ] Identify the last clean backup (before `FirstSeen` timestamp from Step 1.1)
- [ ] Restore encrypted files from backup to a clean system
- [ ] Verify restored file integrity before returning to production

### Step 5.2 — Rebuild Decision Matrix

| Condition | Decision |
|---|---|
| Malware scan clean + no persistence found + short infection window | Consider restore from backup + reimaging optional |
| Persistence mechanism found | **Reimage required** — persistence survives file restoration |
| Encryption complete + ransom note delivered | **Reimage recommended** — system integrity compromised |
| Double extortion suspected | **Reimage required** — notify legal before recovery |

**This hunt:** Reimage initiated — integrity of `saranpc2` could not be guaranteed.

### Step 5.3 — Reset Credentials

- [ ] Reset password for the impacted user account
- [ ] Rotate any service accounts or API keys that were accessible from the infected device
- [ ] Revoke and re-issue any certificates stored on the device

---

## Phase 6: Post-Incident Hardening

### Immediate Hardening Actions

| Action | Tool | Priority |
|---|---|---|
| Enable PowerShell Script Block Logging | GPO | 🔴 Immediate |
| Alert on known ransomware extensions | Sentinel/MDE Custom Detection | 🔴 Immediate |
| Alert on rapid file rename events | Sentinel/MDE Custom Detection | 🔴 Immediate |
| Restrict `C:\ProgramData\` script execution | AppLocker/WDAC | 🟠 High |
| Deploy Constrained Language Mode (PowerShell) | GPO | 🟠 High |
| Verify backup integrity and test restoration | Backup system | 🟠 High |
| User awareness training — phishing | HR / Security Training | 🟠 High |
| Network segmentation — limit share access | Network team | 🟡 Medium |

### Backup Strategy Review

After any ransomware incident, review the backup strategy:

| Question | Best Practice |
|---|---|
| Are backups offline/air-gapped? | Yes — ransomware can encrypt mounted backup drives |
| How often are backups taken? | Daily minimum for sensitive systems |
| Are backups tested (restoration drill)? | Quarterly minimum |
| Are backups immutable? | Yes — use WORM storage or cloud immutable storage |
| Is there a clean baseline snapshot? | Yes — critical for rapid rebuild |

---

## Escalation Path

```
Tier 1 SOC Analyst
    ↓ (ransomware confirmed)
Tier 2 SOC / Incident Commander
    ↓ (multiple devices or exfiltration suspected)
CISO
    ↓ (customer/employee data encrypted or exfiltrated)
Legal / Compliance
    ↓ (regulatory breach threshold met — GDPR, HIPAA, etc.)
External notification (regulators, affected individuals)
```

---

## Ransomware-Specific Communication Template

**For communicating to management during active incident:**

```
RANSOMWARE INCIDENT — STATUS UPDATE
====================================
Time: _______________
Analyst: _______________

SITUATION:
PwnCrypt ransomware confirmed active on [DEVICE(S)].
Encryption began at [TIMESTAMP].
[X] files confirmed encrypted.
Ransom note [confirmed/not yet confirmed].

CONTAINMENT:
[X] device(s) isolated via MDE.
Ransomware [still running / confirmed stopped].

RECOVERY OPTIONS:
Backup available: [Yes — last clean backup: DATE / No]
Rebuild required: [Yes / Pending assessment]

SPREAD RISK:
[Other devices at risk / No lateral movement detected]

NEXT UPDATE: [Time]
```

---

*Playbook authored by: Saran | CyberRange Lab | March 28, 2026*  
*Review cycle: Quarterly — ransomware techniques evolve rapidly*
