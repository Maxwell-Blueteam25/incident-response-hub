
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


// Email Metadata Query
EmailEvents
| where SenderFromAddress == "redacted@dolese.cam"
| project Timestamp, RecipientEmailAddress, Subject

// URL Extraction
EmailEvents 
| where SenderFromAddress == "redacted" 
| project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject 
| join kind=inner ( 
    EmailUrlInfo 
    | project NetworkMessageId, Url 
) on NetworkMessageId

// Attachment Extraction
EmailEvents 
| where SenderFromAddress == "redacted" 
| project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject 
| join kind=inner ( 
    EmailAttachmentInfo 
    | project NetworkMessageId, FileName, FileType, SHA256 
) on NetworkMessageId

// User Click and Impact Tracking - Attachments
EmailAttachmentInfo
| where Timestamp >= ago(7d)
| where FileName endswith ".doc" or FileName endswith ".pdf" or FileName endswith ".exe"
| where SenderFromAddress !startswith "redacted"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, FileName, SHA256

// User Click and Impact Tracking - URL Clicks
EmailEvents
| where SenderFromAddress == "redacted@dolese.cam"
| project Timestamp, RecipientEmailAddress, Subject, NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where Url contains "docs.google.com"
    | project NetworkMessageId, ClickTimestamp = Timestamp, UserId, Url, DeviceName, Application
) on NetworkMessageId


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

**Evidence and Screenshots:**

![Access the PDF](https://github.com/user-attachments/assets/9f9308cf-3498-4449-9542-ec4818b655c2)

![Credential Capture Page](https://github.com/user-attachments/assets/f6cf6dbb-90bc-4fcc-aafd-29f8b71c8e5d)

![CredentialCapture Reputation](https://github.com/user-attachments/assets/ae88a7b4-eba0-49e7-aa4b-b002d1c824aa)

![dolese cam reputation](https://github.com/user-attachments/assets/9594871e-0141-4a55-b2d9-88e81c8fc4ab)


![SenderIP Spoofing and Spam1](https://github.com/user-attachments/assets/1bd31eb8-0a41-4642-a0d7-b71420aa3e82)

![SenderIP Abusive1](https://github.com/user-attachments/assets/86e55c3c-ddfe-48ae-b645-2feb2be394fa)

*Maxwell Skinner – Cybersecurity Intern*


