
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

## 1. 🛠 Preparation & Detection

### Tools & Techniques Used:
- Microsoft Defender XDR with custom KQL queries  
- Microsoft Header Analyzer  
- VirusTotal & AbuseIPDB (OSINT)  
- Browser-based sandbox environment  

### Initial Query to Identify Targeted Emails:
EmailEvents  
| where SenderFromAddress == "redacted@dolese.cam"  
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, NetworkMessageId

This allowed us to:  
- Identify the recipient (only 1 user targeted)  
- Extract metadata needed to pivot across email, URL, and attachment datasets  
- Correlate the message using NetworkMessageId  

### Header Analysis:
Parsed the full message headers using Microsoft’s analyzer to extract:  
- Return-Path mismatch (spoofing indicator)  
- Sender IP: 23.redacted.218.redacted  
- Flagged on VirusTotal and AbuseIPDB with 29+ abuse reports  
- Missing/invalid SPF, DKIM, DMARC  
- Suspicious received path with multiple unexpected relays  

## 2. 🔍 In-Depth Analysis

### Domain & IP Reputation:
- The .cam domain had prior phishing history  
- The specific sender IP had a high confidence score for abuse  

### URL Inspection:
Queried the EmailUrlInfo and UrlClickEvents tables:

EmailEvents  
| where SenderFromAddress == "redacted"  
| join kind=inner (  
    EmailUrlInfo  
    | project NetworkMessageId, Url  
) on NetworkMessageId

Result:  
- The "OneDrive" link pointed to docs.google.com, which redirected to a spoofed Microsoft login page  
- Sandbox testing revealed the document included a “Request Access” button triggering the credential capture redirect  

### Impact Scope:
UrlClickEvents  
| where Url contains "docs.google.com"  
| project Timestamp, UserId, Url

Only one user interacted with the link.  
No evidence of:  
- Credential reuse or session hijacking  
- Anomalous sign-ins or token abuse (SigninLogs queried)  
- Lateral movement or OAuth app abuse  

## 3. 🔒 Containment & Mitigation

### Immediate Actions:
- Domain/IP Blocked: Configured Microsoft Defender policies to block dolese.cam and 23.redacted.218.redacted  
- Email Purged: Used Microsoft Compliance Center tools to remove the message from the user’s mailbox  

### Threat Artifacts Logged:
- IP address  
- Domain  
- Spoofed URL path  
- SHA256 hashes (if any)  
- All indicators documented and archived in internal TI collection  

### User Engagement:
- The user was notified and provided phishing awareness guidance  
- Incident used as a training opportunity in team sync  

## 4. 🧠 Lessons Learned

✅ Strengths  
- Rapid triage through standardized playbook  
- KQL streamlined scoping, impact validation  
- Effective sandboxing validated end-stage phishing  

🔧 Improvements  
- Add auto-scoring for unusual TLDs (e.g., .cam, .zip, .mov)  
- Integrate domain/IP reputation APIs for faster context  
- Improve user training on link hovering and URL inspection  


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

**Evidence and Screenshots:**

![Access the PDF](https://github.com/user-attachments/assets/9f9308cf-3498-4449-9542-ec4818b655c2)

![Credential Capture Page](https://github.com/user-attachments/assets/f6cf6dbb-90bc-4fcc-aafd-29f8b71c8e5d)

![CredentialCapture Reputation](https://github.com/user-attachments/assets/ae88a7b4-eba0-49e7-aa4b-b002d1c824aa)

![dolese cam reputation](https://github.com/user-attachments/assets/9594871e-0141-4a55-b2d9-88e81c8fc4ab)


![SenderIP Spoofing and Spam1](https://github.com/user-attachments/assets/1bd31eb8-0a41-4642-a0d7-b71420aa3e82)

![SenderIP Abusive1](https://github.com/user-attachments/assets/86e55c3c-ddfe-48ae-b645-2feb2be394fa)

*Maxwell Skinner – Cybersecurity Intern*


