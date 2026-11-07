---


---

[← Home](/)

## Incident Overview
### Executive Summary
 
**Incident:** AiTM Credential Phishing (EvilProxy/Evilginx-class)  
**Affected Host:** `corp-wks-7712` (User: `alicia.rodriguez`)  
**Timeline:** 12 Apr 2026 08:31–08:59 UTC (~28 minutes)  
**Confidence:** High

On 12 Apr 2026, a user received a spear-phishing email from a spoofed Microsoft sender (`support@login.microsoftonline.in.net`) directing them to a credential harvesting site mimicking Microsoft's login portal. The attack leveraged a three-hop 302 redirect chain through lookalike domains to intercept and relay the live Microsoft OAuth flow. Credentials and session tokens were captured, then replayed 26 minutes later from Amsterdam against Office 365 with MFA bypass. The attacker subsequently enumerated mailbox contents via Microsoft Graph. This is a classic AiTM (adversary-in-the-middle) campaign targeting cloud credentials; the second domain (`integralsm.cl`) suggests parallel targeting of additional users.

### Initial Information

- Affected user: alicia.rodriguez (workstation corp-wks-7712)
- Two phishing emails were delivered to her mailbox from external senders
- At least one email contained a link to a lookalike login page
- Multiple suspicious domains and IPs have been flagged by our threat intel feeds
- Azure AD sign-in logs show anomalous activity for Alicia's account

---

## Investigation

### Workflow / Steps

None taken at time

### Tools Used
- Online SIEM

---

## Findings

### Timeline

| **Time (UTC)**  | **Host**        | **Event**                                                                                                                                                                                                                | **Source**        |
| --------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------- |
| 12/4/26 8:31:07 | N/A             | Email delivered: from=`support@login.microsoftonline.in.net` to=`alicia.rodriguez@corp.local` subject="Action Required: Verify Your Account" verdict=suspicious link_url=`https://absoluteprintgroup.com/documents/view` | Email Gateway Log |
| 8:31:55         | `corp-wks-7712` | Email read: user=alicia.rodriguez msgid=BBNkAHR4 subject="Action Required: Verify Your Account" client=Outlook-Desktop link_clicked=true                                                                                 | Email O365 Logs   |
| 8:31:07         | `corp-wks-7712` | DNS query: `login.microsoftonline.in.net` -> `162.19.196.13` (A record) by msedge.exe                                                                                                                                    | Windows Sysmon    |
| 8:32:06         | `corp-wks-7712` | DNS query: absoluteprintgroup.com -> `45.142.212.61` (A record) by msedge.exe                                                                                                                                            | Windows Sysmon    |
| 8:32:07         | `corp-wks-7712` | Network connection: msedge.exe -> `45.142.212.61:443` (`absoluteprintgroup.com`) - TLS 1.2 - HTTP 302 redirect to `login.microsoftonline.in.net`                                                                         | Windows Sysmon    |
| 8:32:08         | `corp-wks-7712` | Network connection: msedge.exe -> `162.19.196.13:443` (`login.microsoftonline.in.net`) - TLS 1.2 - HTTP 302 redirect                                                                                                     | Windows Sysmon    |
| 8:32:11         | `corp-wks-7712` | Network connection: msedge.exe -> `163.5.221.110:443` (`auth.microsoftonline.in.net`) - TLS 1.2 - credential form rendered                                                                                               | Windows Sysmon    |
| 8:32:44         | `corp-wks-7712` | Network connection: msedge.exe -> `163.5.221.110:443 `(`auth.microsoftonline.in.net`) - POST /auth/token - form submission detected                                                                                      | Windows Sysmon    |
| 8:35:12         | N/A             | Email delivered: from=`noreply@integralsm.cl` to=`bob.wilson@corp.local` subject="Document Shared: Q2 Financial Report" verdict=suspicious link_url=`https://integralsm.cl/share/doc/view`                               | Email Gateway Log |
| 8:58:40         | N/A             | Sign-in success: user=alicia.rodriguez app=Office 365 Exchange Online ip=`163.5.221.110` location=Amsterdam,NL device=Linux mfa=none(existing session token replayed)                                                    | Azure AD Logs     |
| 8:59:12         | N/A             | Microsoft Graph access: user=alicia.rodriguez ip=`163.5.221.110` device=Linux operation=List messages (mailbox enumeration)                                                                                              | Azure AD Logs     |
| 9:05:47         | `corp-wks-8821` | DNS query: `integralsm.cl` -> `163.5.169.67` (A record) by msedge.exe                                                                                                                                                    | Windows Sysmon    |

**Note**:
 - Timestamp anomaly - The DNS query for `login.microsoftonline.in.net` is logged at 8:31:07, before the email is read at 8:31:55. This is likely a cause of log ingestion.

### Attack Chain Summary

**Phase 1 — Delivery**

- 08:31:07 — Phishing email delivered to `alicia.rodriguez@corp.local` from `support@login.microsoftonline.in.net`, subject "Action Required: Verify Your Account"; gateway verdict `suspicious` but not blocked
- Payload link pointed to a third-party redirector (`absoluteprintgroup.com/documents/view`), keeping the credential-harvesting hostname out of the email body
- 08:35:12 —  Identical second lure delivered to `bob.wilson@corp.local` from `noreply@integralsm.cl`, subject "Document Shared: Q2 Financial Report" —  parallel targeting

**Phase 2 — User Interaction**

- 08:31:55 — Victim opens the email in Outlook Desktop and clicks the link (48 seconds after delivery)
- 09:05:47 — `corp-wks-8821` resolves `integralsm.cl`; no click or submission follows — unresolved.

**Phase 3 — Redirect Chain**

- 08:32:06 — DNS resolution of `absoluteprintgroup.com` → 45.142.212.61
- 08:32:07 — HTTP 302 redirect issued to `login.microsoftonline.in.net`
- 08:32:08 — DNS/TLS to 162.19.196.13; second HTTP 302 issued
- 08:32:11 — Landing on `auth.microsoftonline.in.net` (`163.5.221.110`); fake Microsoft credential form renders
- Three-hop structure segments redirector, landing page, and capture host across three IPs.

**Phase 4 — Credential and Session Capture**

- 08:32:44 — `POST /auth/token` submitted; kit acts as reverse proxy to genuine Microsoft auth, capturing credentials & session material
- Path naming mimics a real OAuth token endpoint.

**Phase 5 — Token Replay**

- 08:58:40 — Successful Exchange Online sign-in as `alicia.rodriguez` from **163.5.221.110** — the same IP that hosted the phishing form
- Session attributes: `device=Linux` (victim runs Windows), `location=Amsterdam,NL`, `mfa=none (existing session token replayed)`
- MFA was not defeated — it was bypassed by inheriting the victim's already-authenticated session

---

## Response

### Recommended Actions / Containment Response

1. Immediately revokes sessions and reset Alicia's password
2. Isolated both affected hosts pending further inspection
3. Added known IP addresses to firewall blocklist
4. Company wide email re the infection and advice about how to avoid

### Containment Priorities

| **Action**                                                                                                       | **Timeframe** |
| ---------------------------------------------------------------------------------------------------------------- | ------------- |
| Revoke all active sessions for `alicia.rodriguez`; force re-authentication with MFA                              | Immediate     |
| Block all four domains and three IPs at DNS/proxy/firewall                                                       | Immediate     |
| Audit mailbox rules, OAuth consents, delegate permissions, and MFA method registrations for the affected account | Immediate     |
| Hunt for `integralsm.cl` activity across the estate; check `bob.wilson` status                                   | <1 hour       |
| Review Entra sign-in logs for any other logins from `163.5.221.110` or Amsterdam-based anomalies                 | <1 hour       |
| Reset `alicia.rodriguez` password; require MFA re-enrollment from known-good device                              | <4 hours      |
| Preserve evidence: email headers, full mailbox export, browser history, and session token metadata               | <4 hours      |
| Add detection rules below to SIEM/SOAR; baseline normal M365 sign-in patterns                                    | 24–72h        |

---

## Detection & Threat Intelligence

### MITRE ATT&CK Mapping

| **MITRE ATT&CK ID** | **Technique Name**                                        | **Related Event**                                                                                                                                                                                                             |
| ------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T1583.001           | Acquire Infrastructure: Domains                           | 12/4 8:31:07 — Attacker-registered lookalike domains `login.microsoftonline.in.net` and `auth.microsoftonline.in.net` impersonating Microsoft's genuine login/auth endpoints                                                  |
| T1585.002           | Establish Accounts: Email Accounts                        | 8:31:07 / 8:35:12 — Sender accounts `support@login.microsoftonline.in.net` and `noreply@integralsm.cl` used to deliver the lures                                                                                              |
| T1608.005           | Stage Capabilities: Link Target                           | 8:31:07 — Phishing link target staged at `https://absoluteprintgroup.com/documents/view`                                                                                                                                      |
| T1584.004           | Compromise Infrastructure: Server                         | 8:32:06–8:32:07 — `absoluteprintgroup.com` (45.142.212.61) issues HTTP 302 redirect into the phishing chain _(inferred: legitimate site repurposed as redirector)_                                                            |
| T1566.002           | Phishing: Spearphishing Link                              | 8:31:07 — Suspicious email to `alicia.rodriguez` ("Action Required: Verify Your Account"); 8:35:12 — second lure to `bob.wilson` ("Document Shared: Q2 Financial Report")                                                     |
| T1204.001           | User Execution: Malicious Link                            | 8:31:55 — `alicia.rodriguez` clicks the link from Outlook Desktop (`link_clicked=true`); 9:05:47 — `msedge.exe` on `corp-wks-8821` resolves `integralsm.cl`                                                                   |
| T1557               | Adversary-in-the-Middle                                   | 8:32:07–8:32:44 — Three-hop 302 redirect chain (`absoluteprintgroup.com` → `login.microsoftonline.in.net` → `auth.microsoftonline.in.net`) consistent with a reverse-proxy phishing kit relaying the live Microsoft auth flow |
| T1056.003           | Input Capture: Web Portal Capture                         | 8:32:11–8:32:44 — Fake credential form rendered at `auth.microsoftonline.in.net` (163.5.221.110); `POST /auth/token` captures the submitted credentials                                                                       |
| T1539               | Steal Web Session Cookie                                  | 8:32:44 (implied) — Session token harvested during the proxied authentication exchange, held for later replay                                                                                                                 |
| T1550.004           | Use Alternate Authentication Material: Web Session Cookie | 8:58:40 — Sign-in success with `mfa=none (existing session token replayed)`, device=Linux, location=Amsterdam NL                                                                                                              |
| T1078.004           | Valid Accounts: Cloud Accounts                            | 8:58:40 — Successful Office 365 Exchange Online sign-in using the stolen session material from 163.5.221.110                                                                                                                  |
| T1114.002           | Email Collection: Remote Email Collection                 | 8:59:12 — Microsoft Graph `List messages` operation against the mailbox (enumeration)                                                                                                                                         |

### Indicators of Compromise (IOCs)

|Category|IOC|Context|
|---|---|---|
|**Domains**|`login.microsoftonline.in.net`|Phishing endpoint (MS lookalike)|
|**Domains**|`auth.microsoftonline.in.net`|Phishing credential form host|
|**Domains**|`absoluteprintgroup.com`|Initial redirector|
|**Domains**|`integralsm.cl`|Secondary campaign domain|
|**IPs**|`162.19.196.13`|`login.microsoftonline.in.net` resolver|
|**IPs**|`45.142.212.61`|`absoluteprintgroup.com`|
|**IPs**|`163.5.221.110`|Phishing host + C2 source (appears in sign-in logs)|
|**IPs**|`163.5.169.67`|`integralsm.cl` resolver|
|**Email**|`support@login.microsoftonline.in.net`|Spoofed sender|
|**Email**|`noreply@integralsm.cl`|Secondary sender|
|**Email Subject**|"Action Required: Verify Your Account"|Primary lure subject|
|**Email Subject**|"Document Shared: Q2 Financial Report"|Secondary lure subject|
|**Sign-in IP**|`163.5.221.110`|Source of token-replay sign-in (Amsterdam NL)|
|**Sign-in Anomaly**|Device=Linux, Location=NL, MFA=none|Stolen session characteristics|

---

## Lessons Learned

**Quick Hunt Procedure for Future Cases:**

1. Extract all external IPs from phishing domain DNS resolutions
2. Query identity logs for any sign-ins from those same IPs
3. If match found → confirm compromise, pivot to affected accounts



## Appendix

### Open Questions

None recorded at time


### Images / Files

Nil for this investigation


