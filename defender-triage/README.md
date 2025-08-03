# 🛡️ Defender Triage

This folder contains real-world phishing investigations and incident triage work conducted using **Microsoft Defender XDR**. Each case follows a structured incident response process aligned with the **NIST 800-61** lifecycle, using **KQL**, email telemetry, and external reputation tools.

## 🔧 Tools & Techniques Used

- **Microsoft Defender Email & Collaboration** – Alert triage and mailbox scoping
- **KQL Queries** – Hunting across `EmailEvents`, `UrlClickEvents`, `EmailUrlInfo`, `SigninLogs`
- **Microsoft Header Analyzer** – Parsing and mapping message routing behavior
- **OSINT Sources** – VirusTotal, AbuseIPDB, WHOIS for IP and domain reputation
- **Sandbox Testing** – Manual URL interaction in safe environments to observe behavior
- **Compliance Actions** – Blocking IPs/domains, purging messages, user follow-up

---

📁 Case Studies in This Folder

**phishing-dolese-cam.md**  
*Summary*: Investigated phishing message impersonating an invoice from a .cam domain  
*Key Indicators*:  
- IP flagged in VirusTotal/AbuseIPDB  
- Domain used urgency and deception  
- URL masqueraded as OneDrive, redirected to credential harvesting login page  
*Actions Taken*:  
- Full header analysis, IP/domain block, KQL triage to confirm single-user exposure  
- Sandbox tested phishing flow and documented infrastructure  
*NIST Phase Alignment*:  
Detection, Analysis, Containment, Lessons Learned  

---

**incident-mfa-bypass-takedown.md**  
*Summary*: Tracked down a multi-user compromise stemming from MFA token theft via phishing proxy  
*Key Indicators*:  
- Foreign successful sign-ins marked "MFA satisfied"  
- Pivotable IP addresses linked to multiple accounts  
- Azure CLI abuse post-compromise  
*Actions Taken*:  
- KQL pivot across sign-ins, email events, and Azure activity logs  
- Identified phishing domain (`9pz[.]org`) and sandboxed links  
- Disabled accounts, blocked IPs/domains, reset credentials and MFA  
- Verified no privilege escalation or persistence  
*NIST Phase Alignment*:  
Detection, Analysis, Containment, Eradication, Recovery, Lessons Learned


## 🔍 NIST Lifecycle in Action

All investigations here follow:

1. **Detection & Analysis**  
   - Identify sender, content, routing, reputation  
   - Scope email and URL reach using KQL  
   - Confirm threat using sandbox and OSINT  

2. **Containment & Recovery**  
   - Block IOC artifacts (IPs, domains, URLs)  
   - Purge email from inboxes  
   - Validate user exposure and reset accounts if needed  

3. **Post-Incident**  
   - Reflect on detection gaps, update rules, and improve awareness  
   - Feed new indicators back into Defender policies

---

## 👨‍💻 Why This Matters

This section is not just a case archive — it's proof of structured triage, fast decision-making, and professional blue team methodology. It shows how Microsoft Defender and good investigative instincts can be combined to defend users, contain threats, and improve response maturity over time.

---

## 🚀 Coming Soon

- Additional phishing campaigns
- Business Email Compromise (BEC) investigations
- KQL query packs for automation and detection engineering
