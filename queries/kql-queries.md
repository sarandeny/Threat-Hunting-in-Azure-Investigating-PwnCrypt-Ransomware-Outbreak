#  KQL Query Reference — PwnCrypt Ransomware Threat Hunt

> All queries were executed in **Microsoft Defender for Endpoint (MDE)**  
> Platform: MDE Advanced Hunting / Microsoft Sentinel  
> Hunt Date: March 28, 2026

---

## Table of Contents

1. [IoC-Based File Search — PwnCrypt Detection](#1-ioc-based-file-search--pwncrypt-detection)
2. [Confirm Encryption Pattern — FileCreated and FileRenamed](#2-confirm-encryption-pattern--filecreated-and-filerenamed)
3. [Timestamped Pivot to Process Events](#3-timestamped-pivot-to-process-events)
4. [Expand Hunt — Check All Devices for Infection](#4-expand-hunt--check-all-devices-for-infection)
5. [Check for Double Extortion — Network Exfiltration Before Encryption](#5-check-for-double-extortion--network-exfiltration-before-encryption)
6. [Ransom Note Detection](#6-ransom-note-detection)
7. [Bonus: Detection Engineering Queries](#7-bonus-detection-engineering-queries)

---

## 1. IoC-Based File Search — PwnCrypt Detection

**Purpose:** Use the known PwnCrypt IoC — the `.pwncrypt` filename pattern — to immediately determine if any device is infected.

```kql
let VMName = "saranpc2";

DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "pwncrypt"
| order by Timestamp desc
```

**Why this works:**
Ransomware strains are typically identified publicly with their file extension IoC. When threat intelligence confirms a pattern like `.pwncrypt.*`, you can search for that string directly in `DeviceFileEvents` — no complex behavioural query needed. This is one of the fastest, most reliable detection methods available.

**What to look for:**
- Any results at all = **infection confirmed** on that device
- `ActionType == "FileCreated"` — encrypted file written to disk
- `ActionType == "FileRenamed"` — original file renamed to include `.pwncrypt`
- The combination of both = complete ransomware encryption workflow confirmed
- `FolderPath` — which directories were targeted?
- Note the earliest `Timestamp` — this is when encryption began

**Result (this hunt):**
Multiple `.pwncrypt` files confirmed on `saranpc2` — infection confirmed. Earliest timestamp: `2026-03-28T07:14:47.6594518Z`.

---

**Broader version — check specific file types targeted:**

```kql
let VMName = "saranpc2";

DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "pwncrypt"
| summarize 
    FileCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by ActionType, FolderPath
| order by FirstSeen asc
```

> 💡 **SOC Tip:** The `FirstSeen` timestamp from this query gives you the exact moment ransomware began encrypting. Everything else — the responsible process, the delivery method — happened *before* this time. Use it as your pivot point.

---

## 2. Confirm Encryption Pattern — FileCreated and FileRenamed

**Purpose:** Confirm the ransomware encryption workflow by verifying that both `FileCreated` and `FileRenamed` events exist for the same files — the hallmark of ransomware operation.

```kql
let VMName = "saranpc2";

DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "pwncrypt"
| where ActionType in ("FileCreated", "FileRenamed")
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Understanding the ransomware file operation pattern:**

```
Step 1: Ransomware reads original file (hello.txt)
Step 2: Encrypts content with AES-256
Step 3: FileCreated — writes encrypted content as hello.pwncrypt.txt
Step 4: FileRenamed — renames hello.txt → hello.pwncrypt.txt (or deletes original)
```

Seeing both `FileCreated` and `FileRenamed` events is a **definitive ransomware signature** — it proves the transformation from original to encrypted file occurred on this device.

**Result (this hunt):**
Both event types confirmed. High volume of events in compressed timeframe confirms automated execution — not manual activity.

---

## 3. Timestamped Pivot to Process Events

**Purpose:** Using the timestamp of the first encryption event, pivot to `DeviceProcessEvents` to identify the execution chain responsible for launching the ransomware.

```kql
let VMName = "saranpc2";
let specificTime = datetime(2026-03-28T07:14:47.6594518Z);

DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, ProcessCommandLine
```

**Why ±3 minutes for ransomware (vs ±1 minute for other hunts):**
Ransomware scripts often have a brief delay between launch and the first file encryption event — they may enumerate the filesystem, install dependencies, or check for sandbox indicators first. A wider ±3 minute window ensures the launch event is captured.

**What to look for in the results:**
- `cmd.exe` launching `powershell.exe` — common staging pattern
- `-ExecutionPolicy Bypass` — deliberate security control circumvention
- Script path in `C:\ProgramData\`, `C:\Temp\`, or `%APPDATA%` — non-standard locations
- `notepad.exe` or other user applications opening `.pwncrypt` files — confirms impact phase

**Result (this hunt):**

| Timestamp | Process | Detail |
|---|---|---|
| T-seconds | `cmd.exe` | Launched PowerShell |
| T | `powershell.exe` | `-ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1` |
| T+seconds | File encryption begins | `.pwncrypt` files created |
| T+minutes | `notepad.exe` | Opened `9165_CompanyFinancials_pwncrypt.csv` |
| T+minutes | `notepad.exe` | Opened `decryption-instructions.txt` (ransom note) |
| T+minutes | `OpenWith.exe` | Additional user interaction with encrypted files |

---

## 4. Expand Hunt — Check All Devices for Infection

**Purpose:** Ransomware rarely stops at one device. This query checks the entire environment for any device showing PwnCrypt infection signs.

```kql
// Check ALL devices for PwnCrypt infection
DeviceFileEvents
| where FileName contains "pwncrypt"
| summarize 
    InfectedFiles = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName
| order by InfectedFiles desc
```

**What to look for:**
- Any device appearing in results = **infected** — isolate immediately
- `InfectedFiles` count — higher = more advanced infection or longer running
- `FirstSeen` — which device was infected first? (potential patient zero)
- Spread pattern — are devices infected sequentially? (lateral movement)

**Generic version — adapt for any ransomware strain:**

```kql
// Replace "pwncrypt" with any known ransomware extension IoC
let RansomwareExtension = "pwncrypt"; // e.g., "locky", "wannacry", "ryuk"

DeviceFileEvents
| where FileName contains RansomwareExtension
| summarize InfectedFiles = count() by DeviceName
| order by InfectedFiles desc
```

---

## 5. Check for Double Extortion — Network Exfiltration Before Encryption

**Purpose:** Modern ransomware groups often exfiltrate data *before* encrypting — known as "double extortion." This query checks for suspicious outbound connections around the time of ransomware execution.

```kql
let VMName = "saranpc2";
let RansomwareTime = datetime(2026-03-28T07:14:47.6594518Z);

DeviceNetworkEvents
| where DeviceName == VMName
| where Timestamp between ((RansomwareTime - 30m) .. RansomwareTime)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (443, 80, 8080, 8443)
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by Timestamp desc
```

**What to look for:**
- Outbound connections from `powershell.exe` to unusual external destinations
- Cloud storage endpoints (Blob, S3, Mega, etc.) — data staging
- Large data transfers shortly before encryption begins
- Connections to known ransomware C2 infrastructure (check with threat intel)

**Result (this hunt):**
Not checked in initial hunt — recommended as a follow-up step in all ransomware investigations.

---

## 6. Ransom Note Detection

**Purpose:** Detect ransomware ransom notes being dropped to the filesystem — an indicator that the ransomware has completed its encryption phase.

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName has_any(
    "decrypt", "ransom", "readme", "restore",
    "how_to", "instructions", "recovery", "help_decrypt"
)
| where FileName endswith ".txt" or FileName endswith ".html" or FileName endswith ".hta"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

**Result (this hunt):**
`decryption-instructions.txt` confirmed created on `saranpc2` Desktop — ransom note delivery confirmed, impact phase complete.

---

## 7. Bonus: Detection Engineering Queries

These queries should be deployed as **scheduled detection rules** in Microsoft Sentinel or MDE Custom Detections to catch ransomware proactively.

### 7.1 — Known Ransomware Extension Alert

```kql
// Alert: File creation with known ransomware extensions
let KnownRansomwareExtensions = dynamic([
    "pwncrypt", "locky", "zepto", "cerber", "cryptolocker",
    "wannacry", "ryuk", "revil", "lockbit", "blackcat",
    "darkside", "conti", "hive", "alphv"
]);

DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName has_any(KnownRansomwareExtensions)
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

> **Severity:** Critical  
> **Recommended action:** Isolate device immediately — ransomware is actively encrypting

---

### 7.2 — Rapid File Rename Detector (Generic Ransomware Behaviour)

```kql
// Alert: High volume of file renames in short window — ransomware behaviour
DeviceFileEvents
| where ActionType == "FileRenamed"
| summarize RenameCount = count() by DeviceName, bin(Timestamp, 1m)
| where RenameCount > 50
| project Timestamp, DeviceName, RenameCount
| order by RenameCount desc
```

> **Severity:** Critical  
> **Note:** Threshold of 50 renames/minute may need tuning based on environment baseline  
> **Recommended action:** Check `FileName` values in the spike window for ransomware extension patterns

---

### 7.3 — PowerShell Script Executing from ProgramData

```kql
// Alert: PowerShell running scripts from C:\ProgramData\ — common ransomware/malware staging
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "C:\\ProgramData\\"
| where ProcessCommandLine has "-ExecutionPolicy Bypass"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

> **Severity:** High  
> **Recommended action:** Investigate immediately — `C:\ProgramData\` + Bypass is a strong malware indicator

---

### 7.4 — Ransom Note File Creation Alert

```kql
// Alert: Ransom note dropped to filesystem
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName has_any("decrypt", "ransom", "restore_files", "how_to_decrypt", "recovery")
| where FileName endswith ".txt" or FileName endswith ".html" or FileName endswith ".hta"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

> **Severity:** Critical  
> **Note:** If this fires, encryption has already completed — focus on containment and recovery

---

### 7.5 — Combined Ransomware Kill Chain Detector

```kql
// Detect: PowerShell execution → file encryption → rename chain within 10 minutes
let SuspectProcesses =
    DeviceProcessEvents
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has "-ExecutionPolicy Bypass"
    | project DeviceName, LaunchTime = Timestamp;

DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| join kind=inner SuspectProcesses on DeviceName
| where Timestamp between (LaunchTime .. LaunchTime + 10m)
| summarize EncryptedFiles = count() by DeviceName, LaunchTime
| where EncryptedFiles > 10
| order by EncryptedFiles desc
```

> **Severity:** Critical  
> **Note:** This correlates PowerShell bypass execution with subsequent rapid file operations — high confidence ransomware indicator

---

## Quick Reference: Key KQL Concepts Used in This Hunt

| Concept | Example |
|---|---|
| IoC string search | `where FileName contains "pwncrypt"` |
| Multiple ActionType filter | `where ActionType in ("FileCreated", "FileRenamed")` |
| Timestamp pivot | `between ((specificTime - 3m) .. (specificTime + 3m))` |
| Org-wide device check | Remove `DeviceName` filter, add `summarize by DeviceName` |
| `has_any()` with list | Match multiple ransom note keywords in one filter |
| `bin(Timestamp, 1m)` | Group events into 1-minute buckets to detect spikes |
| `let` for variables | Define `specificTime` once, reuse in query |
| Cross-table join | `join kind=inner` to correlate process and file events |

---

*Queries authored by: Saran | CyberRange Lab | March 28, 2026*
