Certainly! Here’s a polished **GitHub-ready Markdown report** for your phishing investigation that highlights your role creating the playbook, walks through the lifecycle, and shows professional-level detail and clarity:


# Phishing Incident Response Report  
### Credential Harvesting Attempt via `dolese.cam`

**Prepared by:** Maxwell Skinner – Cybersecurity Intern & Playbook Author  
**Date:** June 3, 2025



## Overview

This report details a phishing investigation conducted using a custom phishing incident response playbook I developed, aligned with NIST 800-61 and integrated with Microsoft Defender XDR. The playbook enabled rapid detection, analysis, and containment of a credential harvesting attack targeting a single user.



## Incident Summary

- **Target:** One employee received a suspicious email impersonating an invoice from the domain `redacted.cam`.
- **Payload:** The email included a "View on OneDrive" link that redirected to a malicious Google Docs page designed to steal Microsoft credentials.
- **Attack Method:** Credential harvesting via a spoofed Microsoft login page.


## Investigation Process

### 1. Preparation & Detection

Using the playbook's predefined KQL queries in Microsoft Defender:


EmailEvents
| where SenderFromAddress == "redacted@dolese.cam"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, NetworkMessageId


* Isolated the email metadata to identify recipients and message details.
* Extracted full email headers using Microsoft’s Email Header Analyzer to document sender IP and path.

### 2. Analysis

* **Sender IP:** `23.redacted.218.redacted`

  * Flagged for multiple abuses (phishing, spoofing, spam) on VirusTotal and AbuseIPDB.
* **Sender Domain:** `redacted.cam`

  * Previously reported for phishing activity.
* **Link Inspection:**

  * The "OneDrive" link was actually a Google Docs URL.
  * Sandbox analysis confirmed it redirected users to a convincing but fake Microsoft login page for credential capture.
* **User Impact:**

  * Confirmed only one recipient got the email.
  * No evidence of account compromise or unauthorized sign-ins after the event.

### 3. Containment & Mitigation

* Blocked the domain `redacted.cam` and IP `23.redacted.218.redacted` using Microsoft Defender email filters.
* Purged the phishing email from the affected user's mailbox via the Microsoft Compliance Center.
* Documented all malicious IPs, domains, URLs, and file hashes for future threat intelligence.
* Provided phishing awareness guidance to the reporting employee.

### 4. Lessons Learned

* The playbook standardized the investigation, enabling fast and thorough response.
* Future enhancements include automated domain reputation checks and expanded detection for uncommon TLDs.
* User training remains critical to reduce risk from social engineering.

---

## Tools & Techniques Used

* Microsoft Defender XDR & KQL queries (customized in the playbook)
* Microsoft Email Header Analyzer
* VirusTotal & AbuseIPDB for IP/domain reputation
* Isolated sandbox environment for URL behavior analysis
* Microsoft Compliance Center for email remediation



## Conclusion

This investigation confirmed a high-confidence phishing attempt leveraging a spoofed Microsoft credential harvest. The incident was contained with no further impact, thanks to a robust detection and response process powered by the playbook I developed.


## Sample KQL Queries




**Email Metadata Query:**

EmailEvents
| where SenderFromAddress == "redacted@dolese.cam"
| project Timestamp, RecipientEmailAddress, Subject


**URL Extraction:**
EmailEvents 
| where SenderFromAddress == "redacted" 
| project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, 
Subject 
| join kind=inner ( 
EmailUrlInfo 
| project NetworkMessageId, Url 
) on NetworkMessageId 

**Attatchment Extraction:**
EmailEvents 
| where SenderFromAddress == "redacted" 
| project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, 
Subject 
| join kind=inner ( 
EmailAttachmentInfo 
| project NetworkMessageId, FileName, FileType, SHA256 
) on NetworkMessageId

**User Click And Impact Tracking:**
EmailAttachmentInfo
| where Timestamp >= ago(7d)
| where FileName endswith ".doc" or FileName endswith ".pdf" or FileName endswith ".exe"
| where SenderFromAddress !startswith "redacted"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, FileName, SHA256

EmailEvents
| where SenderFromAddress == "redacted@dolese.cam"
| project Timestamp, RecipientEmailAddress, Subject, NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where Url contains "docs.google.com"
    | project NetworkMessageId, ClickTimestamp = Timestamp, UserId, Url, DeviceName, Application
) on NetworkMessageId


![Access the PDF](https://github.com/user-attachments/assets/9f9308cf-3498-4449-9542-ec4818b655c2)




*Maxwell Skinner – Cybersecurity Intern*


