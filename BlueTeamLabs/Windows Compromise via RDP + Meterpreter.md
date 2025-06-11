# 🕵️‍♂️ Incident Response Investigation: Windows Compromise via RDP + Meterpreter

## 🎯 Objective

This investigation simulates a real-world Windows workstation compromise involving an attack against internet-facing Remote Desktop Protocol (RDP), followed by the deployment of Meterpreter for post-exploitation. Using `Security.evtx` and `System.evtx` logs extracted from the compromised host, I applied DeepBlueCLI, PowerShell, and Event Viewer to trace attacker activity, persistence mechanisms, and privilege escalation techniques.

---

## 🔧 Tools Used

- `DeepBlueCLI` (PowerShell-based log analysis)
- `PowerShell` (manual filtering and analysis)
- `Event Viewer` (manual inspection of event records)
- `Security.evtx` and `System.evtx` logs from `Desktop\Investigation\` folder

---

## 📝 Investigation Results

### 🔍 Q1: Which user account ran GoogleUpdate.exe?
**Answer:** `Mike Smith`  
**Method:**  
Using `DeepBlue.ps1`, I scanned the `Security.evtx` log for Event ID `4688` and filtered command-line execution entries. The user `Mike Smith` was identified as having executed `GoogleUpdate.exe`, a suspicious binary in this context.

![Screenshot 2025-06-11 093657](https://github.com/user-attachments/assets/f2810e06-353d-4104-8084-2d8b22a7ac9c)

![Screenshot 2025-06-11 093828](https://github.com/user-attachments/assets/e365f648-9252-4287-a165-720ac73e1b5b)

---

### 🔍 Q2: At what time is there likely evidence of Meterpreter activity?
**Answer:** `4/10/2021 10:48:14 AM`  
**Method:**  
DeepBlueCLI flagged suspicious command-line usage involving named pipes (`|`) and `cmd.exe`, which often indicates process communication for privilege escalation. This timestamp correlates with classic Meterpreter behavior (e.g., `getsystem` execution).

![Screenshot 2025-06-11 093917](https://github.com/user-attachments/assets/b2149506-6afe-42b1-bb51-516e82bd903c)

---

### 🔍 Q3: What is the name of the suspicious service created?
**Answer:** `rztbzn`  
**Method:**  
Using DeepBlueCLI against the `System.evtx` log, I identified the creation of a service with a randomized name, `rztbzn`, consistent with tactics used by malware or post-exploitation frameworks to establish persistence.

![Screenshot 2025-06-11 093917](https://github.com/user-attachments/assets/5509adf3-a653-4b7b-b536-237726ca92ec)

---

### 🔍 Q4: What malicious executable was downloaded and used to gain a Meterpreter reverse shell?
**Answer:** `serviceupdate.exe`  
**User:** `Mike Smith`  
**Method:**  
By filtering Event ID `4688` in `Security.evtx` between `10:30 AM – 10:50 AM` on April 10, I found the executable `serviceupdate.exe` was launched from the Downloads folder. This is consistent with a user-initiated execution of a reverse shell payload.

![Screenshot 2025-06-11 085446](https://github.com/user-attachments/assets/66370060-789e-4b92-9f40-c7d17dd42069)

![Screenshot 2025-06-11 085532](https://github.com/user-attachments/assets/e89dcc98-1396-486f-afd0-8a937b2816cc)


---

### 🔍 Q5: What was the command line used to create the persistence account?
**Answer:** `net user ServiceAct /add`  
**Method:**  
Reviewing Event ID `4688` between `11:25 AM – 11:40 AM`, I identified the use of the `net user` command to create a new local account named `ServiceAct`. This technique is commonly used to ensure attacker persistence.

![Screenshot 2025-06-11 090754](https://github.com/user-attachments/assets/abc19bfa-d61c-4a59-9ecf-1a398d969add)

![Screenshot 2025-06-11 090842](https://github.com/user-attachments/assets/83087e33-5e85-4f9f-a7c6-899559b12792)

---

### 🔍 Q6: What two local groups was this new account added to?
**Answer:** `Administrators`, `Remote Desktop Users`  
**Method:**  
Searching for Event ID `4732` (user added to local group) with keyword `ServiceAct` revealed that the new account was added to both the `Administrators` group and the `Remote Desktop Users` group, enabling full system control and remote access.

![Screenshot 2025-06-11 092813](https://github.com/user-attachments/assets/a69edac2-df09-43c9-a656-85123ceaa1cd)
![Screenshot 2025-06-11 092848](https://github.com/user-attachments/assets/423f2d92-eabb-4956-92c4-46aef428e34f)
![Screenshot 2025-06-11 092900](https://github.com/user-attachments/assets/ac89008d-cfea-4437-af09-df475cc809c0)


---

## 🧠 Incident Summary

The compromised Windows system was targeted via an exposed RDP service. The attacker successfully authenticated (possibly via brute force or stolen credentials) and then executed a staged payload (`serviceupdate.exe`) to gain a **Meterpreter reverse shell** around **10:48 AM**. 

Using `cmd.exe`, the adversary created a new persistence user `ServiceAct` via `net user` and escalated its access by adding it to privileged groups (`Administrators`, `Remote Desktop Users`) between **11:25–11:40 AM**. A suspicious service `rztbzn` was also created to maintain post-exploitation control.

These tactics align with a standard **MITRE ATT&CK** flow:
- **Initial Access:** Brute-force RDP (T1110.001)
- **Execution:** `serviceupdate.exe` (T1059.003)
- **Privilege Escalation:** `getsystem`, named pipes (T1068)
- **Persistence:** Local account + service creation (T1136, T1543.003)
- **Defense Evasion:** Use of living-off-the-land binaries (`net.exe`, `cmd.exe`)

---

## 🧩 Key Skills Demonstrated

- 🔍 Log analysis with `DeepBlueCLI`
- 💻 Manual `4688`, `4732` event parsing in PowerShell
- 🛡️ Detection of common attacker TTPs (privilege escalation, persistence)
- 🧠 Applied thinking based on MITRE ATT&CK mapping
