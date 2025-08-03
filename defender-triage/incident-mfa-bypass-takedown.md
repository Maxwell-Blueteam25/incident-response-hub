# 🛡️ Incident Response Case Study: MFA Bypass, Credential Phishing, and Azure CLI Abuse

In a recent incident response engagement, I was brought in after a user was unexpectedly locked out of their Microsoft 365 account. They were unsure how it happened—and couldn’t get back in. Here's how I unraveled the compromise, identified lateral movement, and eradicated the threat.

---

## 🧩 Step 1: Sign-In Anomalies & Initial Clues

I started by reviewing the user’s sign-in logs using Kusto Query Language (KQL):

```
SigninLogs
| where UserPrincipalName == "user@company.com"
| project TimeGenerated, IPAddress, Location, Status, MFAResult, AppDisplayName
```
Findings:

1. Numerous failed sign-ins from foreign countries: Russia, Germany, Vietnam, and more.
2. Two successful sign-ins from unexpected locations.
3. MFA marked as "satisfied", even though the user denied access.

Conclusion: This looked like a case of session hijacking via a phishing proxy (e.g., Evilginx, Modlishka), where the attacker captured a valid session token or MFA cookie.

## Step 2: Phishing Email Discovery & Domain Hunting
I pivoted into email investigation to trace the potential entry point:

```
EmailEvents
| where SenderFromDomain endswith ".org" or endswith ".top" or endswith ".xyz"
| summarize TotalEmails=count() by SenderFromDomain
```
One domain stood out: 9pz[.]org

I expanded the search:
```
EmailEvents
| where SenderFromDomain == "9pz.org"
| project RecipientEmailAddress, InternetMessageId, Subject, DeliveryStatus, Urls
```
I found:

Emails that made it past filtering.

Links leading to phishing pages (sandboxed and confirmed to be credential capture kits).

One user clicked the link and was later compromised from a new IP address in Germany (DE).

## Step 3: Lateral Movement via IP Pivoting
That same DE IP address was used to access another account. I ran:

```
SigninLogs
| where IPAddress == "<DE_IP>"
| summarize UsersAffected=make_set(UserPrincipalName), AppsAccessed=make_set(AppDisplayName)
```
What surfaced:
- Another user compromised.
- A third account that was authenticated to Azure CLI from the same foreign IP.
- This attacker was pivoting internally.

## Step 4: Azure CLI Abuse Investigation
I pulled Azure Activity Logs to see what they were doing via CLI:

```
AzureActivity
| where CallerIpAddress == "<DE_IP>"
| project TimeGenerated, Caller, OperationName, ActivityStatus, ResourceGroup, Category
```

## Discovered activities:
1. Enumerating users, groups, and roles.
2. Attempted role assignments.
3. Probing service principals.
Fortunately, no successful privilege escalations or persistence mechanisms were observed.

## Step 5: Containment & Eradication
I implemented full containment and cleanup:

✅ Disabled all affected user accounts.

✅ Reset passwords and re-registered MFA for all impacted users.

✅ Collected and blocked all IOCs:

Foreign IPs (DE, VN, RU)

#### 9pz[.]org

## All phishing URLs

✅ Quarantined similar emails across the tenant.

✅ Verified via sandbox: phishing link was credential-harvesting.

✅ Confirmed attacker had not modified Azure resources or roles.

✅ Ran log reviews for other suspicious activities using:

```
AuditLogs
| where Identity in~ ("user1@company.com", "user2@company.com", "user3@company.com")
| summarize EventsByUser=count() by Identity, ActivityDisplayName
```
## Lessons Learned
- MFA is not bulletproof—especially against real-time phishing proxies.
- Session token theft is increasingly common in Microsoft 365 breaches.
- Azure CLI access is a major red flag for post-exploitation behavior.

KQL and Sentinel are powerful tools for identity-based attack investigations.

Being able to pivot from identity > email > IP > CLI > lateral movement is essential.
