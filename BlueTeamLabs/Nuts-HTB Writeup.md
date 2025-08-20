---

# HackTheBox DFIR Case Study – *Nuts*

## Introduction

This case study documents my forensic investigation into the *Nuts* challenge on HackTheBox. The scenario simulates a software supply chain attack where a malicious NuGet package was introduced into a deployment environment. The investigation was performed using provided KAPE output, and in keeping with best IR practices, I tracked all collected artifacts in the **CrowdStrike IR Tracker** spreadsheet for evidence management and timeline correlation.

The investigation goal was to reconstruct attacker actions, identify malicious artifacts, and determine the malware family and persistence mechanisms used.

---

## Tools & Methodology

To investigate this case, I employed a mix of forensic parsing, log review, and timeline correlation techniques:

* **KAPE Output Review** – provided base evidence.
* **Eric Zimmerman’s Tools** – MFTECmd, PECmd, and Timeline Explorer for MFT, USN Journal, and Prefetch analysis.
* **PowerShell (Import-Csv, filtering, parsing)** – used extensively to query forensic data exports.
* **Defender Operational Logs (MPLogs)** – identified quarantined malware and hashes.
* **Browser History & PS History Analysis** – traced user actions and downloads.

I approached each question with a methodology-first mindset:

* If I needed *user activity* → I turned to **PS history** and **browser logs**.
* If I needed *file timestamps* → I leaned on **MFT/USN journal** parsing with MFTECmd and PowerShell queries.
* If I needed *execution evidence* → I checked **Prefetch artifacts**.
* If I needed *detections or quarantines* → I searched **Defender logs/MPLogs**.

---

## Investigation & Findings

### Initial Access – Malicious Package Installation

My first thought was that if Alex integrated a package, I’d likely see it in the **PowerShell command history**. I navigated directly to:

```
C:\Evidence\Nuts\Nuts\C\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

From there, I confirmed the command used:

```powershell
nuget install PublishIgnor -Version 1.0.11-beta
```

<img width="1684" height="349" alt="Screenshot 2025-08-20 020816" src="https://github.com/user-attachments/assets/b17edf53-4965-4c53-821f-9ae9f3dffa47" />

Since I wasn’t familiar with this specific package, I quickly researched NuGet on Microsoft’s documentation. NuGet is a .NET package manager widely trusted by developers. This told me the attacker abused **developer trust** by introducing a trojanized package.

<img width="876" height="269" alt="image" src="https://github.com/user-attachments/assets/84a9b2c3-d678-4fc3-aebe-c87c40744076" />

---

### Malicious Package Download Source

Next, I needed to identify where the package came from. Knowing browsers keep track of download history, I pivoted to:

```
C:\Evidence\Nuts\Nuts\C\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\History
```

I queried it with:

```powershell
Get-Content -Path History | Select-String -Pattern "http"
```

That surfaced:

* **URL:** `https://www.nuget.org/packages/PublishIgnor/`

<img width="1350" height="29" alt="image" src="https://github.com/user-attachments/assets/2b31bd94-ee9c-4556-bf26-b0f6b55a438b" />

Comparing the name to the legitimate package (**PublishIgnore**) immediately signaled a **typosquatting attack**.

<img width="1146" height="161" alt="image" src="https://github.com/user-attachments/assets/a10361f4-b78e-4503-a556-e77b8a5abcdf" />

---

### Threat Actor Attribution

Still in browser logs, I noticed the publisher name repeated. This was a clue to attribution:

* **Publisher:** `a1l4m`

<img width="509" height="30" alt="image" src="https://github.com/user-attachments/assets/94070d6b-62e5-4e87-b5a0-b4ef936a0643" />

---

### Package Download Timestamp

For timing, I knew the **MFT (\$MFT)** would be my best bet since it tracks file creation. Using MFTECmd output, I filtered with PowerShell:

```powershell
Import-Csv '.\MFTECmd_$MFT_Output.csv' | Where-Object { $_.FileName -like "*publish*" } | Sort-Object { $_.Created0x10 }
```

That revealed:

* **Timestamp (UTC):** `2024-03-19 18:41:56`

<img width="1442" height="314" alt="image" src="https://github.com/user-attachments/assets/38bbdf68-1e13-4c22-ba8d-9432f23f6675" />

<img width="896" height="677" alt="image" src="https://github.com/user-attachments/assets/59b42c09-ea6b-4adf-b476-0c55962c51a5" />

---

### Execution & Malicious Code

At this point, I suspected the package contained a hidden script. Using **MFT navigation in EZ tools**, I drilled into:

```
C:\Users\Administrator\PublishIgnor.1.0.11-beta\tools\init.ps1
```

<img width="1904" height="512" alt="image" src="https://github.com/user-attachments/assets/78a385a8-7de4-4f58-80ec-722f418bccd1" />

Reading the script (`Get-Content init.ps1`) confirmed malicious behavior.

<img width="1410" height="377" alt="image" src="https://github.com/user-attachments/assets/a95ade42-7f3d-4a89-86fd-15f8c3743aef" />

**init.ps1 Summary:**

* Disabled Defender real-time monitoring.
* Created a persistence directory.
* Pulled `uninstall.exe` from attacker infrastructure (`http://54.93.81.220:8000/uninstall.exe`).
* Executed the binary.

---

### Defense Evasion

The specific command logged matched what I expected from tampering attempts:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

<img width="698" height="40" alt="image" src="https://github.com/user-attachments/assets/c5a9e263-536a-4454-927c-6f1441c8e601" />

Despite this, Defender still recorded the detection.



---

### Payload Analysis

To confirm what was downloaded, I dug into **MPLogs**, since quarantined files often leave traces there. Searching for `uninstall.exe` gave me:

* **SHA1:** `57b7acf278968eaa53920603c62afd8b305f98bb`
* **Framework Detected:** *Sliver* C2

<img width="1840" height="288" alt="image" src="https://github.com/user-attachments/assets/89503250-25be-4be9-8d78-ce44738154d9" />

Execution evidence came from Prefetch (Using PECmd):
<img width="1017" height="80" alt="image" src="https://github.com/user-attachments/assets/8f946d4b-bef7-4b6c-85c1-adb4299aa88b" />

<img width="1267" height="251" alt="image" src="https://github.com/user-attachments/assets/63afc4cd-d89d-44f2-8ccd-18d1f17a3153" />


* `2024-03-19 19:23:36` UTC

Detection evidence from Defender logs:

* `2024-03-19 19:33:32` UTC


<img width="1492" height="794" alt="image" src="https://github.com/user-attachments/assets/a6a482d3-c367-4eb8-bf78-0d98263318cd" />

---

### Post-Exploitation Activity

Checking Prefetch again, I sorted for suspicious executables. The first enumeration activity was:

* **Process:** `whoami.exe`

<img width="1118" height="60" alt="image" src="https://github.com/user-attachments/assets/ed461b0e-6817-4dc3-8bbf-68f2e8a994a1" />
<img width="337" height="38" alt="image" src="https://github.com/user-attachments/assets/f2ae5bc1-9a9b-4ae3-94b2-29c9d47a3ced" />


Persistence was established through a scheduled task. I recursively listed `C:\Windows\System32\Tasks`:

* **Task:** `MicrosoftSystemDailyUpdates`
* **Creation Time:** `2024-03-19 19:24:05`

<img width="1439" height="393" alt="image" src="https://github.com/user-attachments/assets/9bfa2613-e10d-4898-bd53-cde2f9e664fe" />
<img width="1162" height="34" alt="image" src="https://github.com/user-attachments/assets/d9f8a77c-22a4-4643-8e1c-ce07b020b4e2" />


---

### Anti-Forensics & File Renaming

For the anti-forensics portion, I pivoted to the **USN Journal** because rename events are clearly logged. Using:

```powershell
Import-Csv '.\MFTECmd_$J_Output.csv' | Where-Object { $_.UpdateReasons -like "Rename*" }
```

I discovered the attacker renamed the payload:

* **Original:** `file.exe`
* **Renamed:** `Updater.exe`
* **Timestamp:** `2024-03-19 19:30:04` UTC

<img width="1892" height="273" alt="image" src="https://github.com/user-attachments/assets/435b8c52-0b52-4a6a-a720-de371a98b185" />
<img width="1901" height="71" alt="image" src="https://github.com/user-attachments/assets/4a29b80c-05ae-498f-8fbe-ecd9aa8edc88" />
<img width="191" height="76" alt="image" src="https://github.com/user-attachments/assets/7bf2405d-665a-4e01-b742-fe658ffa69e6" />
<img width="1526" height="982" alt="image" src="https://github.com/user-attachments/assets/b12d9586-0a6c-4983-8e16-a0bea2e7c888" />


**Malware Family Identified:** *Impala* – associated with renamed binaries that act as loaders for persistence.
<img width="1100" height="525" alt="image" src="https://github.com/user-attachments/assets/451db45f-2fde-4489-beea-a238fe13eb3a" />

---

## Summary of Attack Chain

1. **Initial Access** – Trojanized NuGet package (`PublishIgnor`) introduced via **typosquatting**.
2. **Execution** – Package script (`init.ps1`) disabled Defender and downloaded `uninstall.exe`.
3. **Payload Delivery** – Retrieved from attacker server at `54.93.81.220:8000`.
4. **Persistence** – Scheduled task `MicrosoftSystemDailyUpdates` created.
5. **Defense Evasion** – Defender protections disabled, but not fully.
6. **Post-Exploitation** – Recon started (`whoami.exe`) after Sliver C2 connection.
7. **Anti-Forensics** – File renamed (`file.exe` → `Updater.exe`).
8. **Malware Family** – Linked to *Impala*.

---

## Conclusion

This lab highlights how **software supply chain compromises** can be staged via legitimate developer ecosystems (NuGet). The attacker leveraged **typosquatting**, **malicious scripts**, and **Defender evasion** to establish persistence and control over the system.

Even with attempted anti-forensics, artifacts in **PS history, browser logs, MFT, Prefetch, Defender logs, and the USN journal** allowed a complete reconstruction of attacker activity.

**Key Lessons Learned:**

* Developer ecosystems remain high-value targets.
* Even partially disabled defenses can generate valuable telemetry.
* Timeline building across multiple artifacts (PS history → MFT → Prefetch → USN) provides a full picture.

---

⚡ *Investigation performed by Maxwell Skinner as part of DFIR practice on HackTheBox (Nuts challenge).*

---









