---

---

[← Home](/)

## Incident Overview
### Executive Summary

**Incident:**   QR Code Phishing Incident
**Affected Host(s):**  corp-wks-7720

On 13 April 2026, employee Sarah Jenkins (`corp-wks-7720`) received a credential phishing email spoofed to appear as an internal IT security notification about MFA enrolment. The email contained an  QR code, bypassing traditional URL-based detection, and was delivered to her inbox at 08:42 UTC.

Because she scanned the QR code with her personal phone on guest Wi-Fi, the attack bypassed corporate endpoint defences. The QR redirected to an Adversary-in-the-Middle (AitM) phishing site behind a typo-squatted domain (`amphen0l-fci.com`, zero-for-zero substitution) with a valid Let's Encrypt certificate.

At 09:01 UTC, the victim submitted her username, password, and — critically — **approved a real-time MFA push notification**, meaning the phishing site successfully relayed the full authentication challenge. The attacker obtained the resulting session cookie, giving them token-based access independent of her password or MFA factors.

Within ~13 minutes the attacker pivoted to the Microsoft Graph API, exhibited impossible-travel behaviour (Amsterdam → Frankfurt sign-in), enumerated 47 emails in 30 seconds, created a hidden-persistence inbox forwarding rule to an external ProtonMail address, and exfiltrated sensitive engineering documents including infrastructure diagrams and VPN configuration guides.


### Initial Information

- Around 47 employees received an email titled "Action Required: MFA Enrollment" claiming to be from the IT department. The email body contained a QR code instead of any link text.
- At least 3 users scanned the QR code on their phones. One account is confirmed compromised: sarah.jenkins (workstation corp-wks-7720).
- Shortly after the scan, Azure AD flagged a suspicious sign-in for sarah.jenkins, followed by Microsoft Graph API activity (mailbox access and SharePoint downloads).

---
## Investigation

### Workflow / Steps

None taken at time.


### Tools Used

- Online SIEM

---
## Findings

### Timeline

**Host:** `corp-wks-102` | **IP Address**: `10.0.1.135`

| **Time (UTC)**      | **Event**                                                                                                                                                                                                                                                                                                                                                                                                                                                     | **Source**        |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| 13/04/2026 08:42:14 | [[Email header]] analysis: Received: from mail.m365-mfa-enroll.com (`162.19.196.13`) by email-gw-01. HELO=mail.m365-mfa-enroll.com. Envelope-From=`bounce-4a82f@m365-mfa-enroll.com`. Header-From=`it-security@corp-notifications.com` (spoofed).                                                                                                                                                                                                             | Email Gateway Log |
| 8:42:14             | Reverse DNS lookup: `162.19.196.13` -> `mail.m365-mfa-enroll.com`. PTR record confirmed. Hosting provider: OVH SAS (FR). Domain registered 2026-03-28 (16 days ago).                                                                                                                                                                                                                                                                                          | Email Gateway Log |
| 8:42:15             | X-Mailer header: QRPhish-Builder v2.1. X-Campaign-ID: camp-2026-04-mfa. Custom headers indicate automated phishing platform hosted on `m365-mfa-enroll.com`.                                                                                                                                                                                                                                                                                                  | Email Gateway Log |
| 8:42:15             | Inbound email delivered: From=`it-security@corp-notifications.com` To=`sarah.jenkins@corp.local`'Subject='Action Required: MFA Enrollment - Scan QR Code' Attachments=0 Images=1 (inline QR code)                                                                                                                                                                                                                                                             | Email Gateway Log |
| 8:42:16             | QR code detected in email body. Decoded URL: `https://176.111.219.85/r?token=aHR0cHM6Ly9vbmxpbmUuYW1waGVuMGwtZmNpLmNvbS9sb2dpbg==&ref=mfa-enrollment`. URL reputation: Unknown (not in blocklist).                                                                                                                                                                                                                                                            | Email Gateway Log |
| 8:42:17             | SPF check: FAIL - sending IP `162.19.196.13` is not authorized by the message's envelope-from (return-path) domain, which is the domain SPF actually validates. SPF does NOT check the visible Header-From (`it-security@corp-notifications.com`) - that display domain is spoofed and outside SPF's scope. DKIM: NONE. DMARC: FAIL (Header-From corp-notifications.com not aligned with the authenticated envelope domain; policy=none) - message delivered. | Email Gateway Log |
| 8:43:30             | Message trace: MessageId=`<qr-phish-20260413@corp-notifications.com>` delivered to `sarah.jenkins@corp.local` inbox. SCL=1 (low confidence spam).                                                                                                                                                                                                                                                                                                             | O365 Logs         |
| 8:50:00             | DNS query: corp-wks-7720 resolved `m365-mfa-enroll.com` -> `162.19.196.13`. Query triggered by Outlook link preview for sender domain investigation.                                                                                                                                                                                                                                                                                                          | IDS Logs          |
| 8:52:10             | IDS Alert: HTTP redirect chain detected. Initial request to `176.111.219.85:443` returned 302 redirect to `online.amphen0l-fci.com`. Source: sarah.jenkins's phone on the corporate guest Wi-Fi (guest traffic traverses the perimeter IDS). TLS SNI mismatch with IP-only URL.                                                                                                                                                                               | IDS Logs          |
| 8:52:11             | DNS query logged: `online.amphen0l-fci.com` queried from an external source (mobile device, not on corporate DNS).                                                                                                                                                                                                                                                                                                                                            | IDS Logs          |
| 8:58:20             | TLS connection established: external client -> `185.234.72.19:443` (`online.amphen0l-fci.com`). Certificate CN=`online.amphen0l-fci.com`, Issuer=Let's Encrypt, Valid.                                                                                                                                                                                                                                                                                        | IDS Logs          |
| 8:58:22             | HTTP GET /login detected to `185.234.72.19`. Response: 200 OK, Content-Type=text/html. Page title: 'Sign in to your account - Microsoft 365'. Page fingerprint matches known AitM phishing kit (Evilginx2 variant).                                                                                                                                                                                                                                           | IDS Logs          |
| 9:01:44             | Credential submission detected: POST /api/auth/login to `185.234.72.19` (`online.amphen0l-fci.com`). Form fields: `username=sarah.jenkins@corp.local`, password=`[REDACTED]`, mfa_token=`[REDACTED]`. AitM proxy relaying to login.microsoftonline.com.                                                                                                                                                                                                       | IDS Logs          |
| 9:01:47             | Sign-in succeeded: `sarah.jenkins@corp.local.` MFA satisfied (push notification approved). IP=`185.234.72.19`. Location: Amsterdam, NL. Client=Browser (Chrome/Mobile). Risk=none (first assessment).                                                                                                                                                                                                                                                         | Azure AD Logs     |
| 9:02:05             | Sign-in succeeded: `sarah.jenkins@corp.local`. Token refresh. IP=`185.234.72.19`. Session persisted via stolen session cookie. Application=Microsoft Office 365.                                                                                                                                                                                                                                                                                              | Azure AD Logs     |
| 9:02:30             | HTTP GET /auth/complete to `185.234.72.19`. Response: 302 redirect to `https://www.microsoft.com` (post-phishing landing to reduce suspicion).                                                                                                                                                                                                                                                                                                                | IDS Logs          |
| 9:05:30             | EDR telemetry: corp-wks-7720 (sarah.jenkins). Process=outlook.exe accessed email message with embedded QR code image (image/png, 2.4 KB). No executable content detected in image.                                                                                                                                                                                                                                                                            | EDR Log           |
| 9:10:33             | Sign-in succeeded: `sarah.jenkins@corp.local`. IP=`185.234.72.40`. Location: Frankfurt, DE. Client=Browser. Application=Microsoft Graph API. Risk=medium (atypical travel: Amsterdam to Frankfurt in 9 minutes, impossible travel).                                                                                                                                                                                                                           | Azure AD Logs     |
| 9:11:05             | Graph API access: `sarah.jenkins@corp.local` from `185.234.72.40`. Scope=Mail.Read, Mail.ReadWrite, Files.Read.All. 47 emails read in 30 seconds (automated enumeration pattern).                                                                                                                                                                                                                                                                             | Azure AD Logs     |
| 9:12:15             | Graph API access: `sarah.jenkins@corp.local` from `185.234.72.40`. Inbox rule created: 'Forward All' - auto-forward all incoming mail to external address `sjenkins-backup@protonmail.com`.                                                                                                                                                                                                                                                                   | Azure AD Logs     |
| 9:14:22             | Graph API access: `sarah.jenkins@corp.local` from `185.234.72.40`. SharePoint file download: /sites/Engineering/Shared Documents/Infrastructure-Diagram-2026.pdf, /sites/Engineering/Shared Documents/VPN-Config-Guide.docx. 2 files (4.2 MB total).                                                                                                                                                                                                          | Azure AD Logs     |
|                     |                                                                                                                                                                                                                                                                                                                                                                                                                                                               |                   |


---
## Response 

### Recommended Actions / Containment Response

1. Kill / revoke active sessions and reset password and MFA re-registration.
2. Delete the Mailbox rules created by the malicious actor
3. Added known IPs to blocklist
4. Company-wide email giving advice.
5. Notify legal/regulatory bodies as required

---
## Detection & Threat Intelligence

### MITRE ATT&CK Mapping

| ATT&CK Technique                                           | ID                | Evidence in Timeline                                                                                                                                             |
| ---------------------------------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Resource Development → Acquire Infrastructure: Domains** | T1583.001         | Attackers registered `m365-mfa-enroll.com` 16 days before the campaign (2026-03-28), hosted on OVH                                                               |
| **Resource Development → Acquire Infrastructure: Server**  | T1583.004         | AitM phishing infrastructure at `176.111.219.85` and `185.234.72.19/.40`                                                                                         |
| **Resource Development → Obtain Capabilities**             | T1588.003/005     | QRPhish-Builder v2.1 phishing kit + Evilginx2 AitM proxy, revealed in `X-Mailer` header                                                                          |
| **Resource Development → Impersonation**                   | T1656             | Typosquatting `amphen0l-fci.com` (zero substituted for "o"), `corp-notifications.com` lookalike domain                                                           |
| **Initial Access → Phishing: Spearphishing Link**          | T1566.002         | QR code embedded in email — a quishing variant where the QR hides the malicious URL from scanners and moves the click onto mobile                                |
| **Defense Evasion → Masquerading**                         | T1036.007/008     | Spoofed Header-From `it-security@corp-notifications.com`; legitimate-looking subject and Microsoft-styled landing page; valid TLS cert to evade browser warnings |
| **Credential Access → Adversary-in-the-Middle**            | T1557.002         | Evilginx2 proxy relayed credentials AND the live MFA push approval to `login.microsoftonline.com`                                                                |
| **Credential Access → Steal Web Session Cookie**           | T1539 / T1550.004 | AitM harvested the authenticated session; subsequent "Token refresh" and Graph API access used the stolen session without re-authentication                      |
| **Discovery** (Cloud)                                      | T1526 / T1087     | Graph API Mail.Read enumeration — 47 emails read in 30 seconds (automated mailbox triage)                                                                        |
| **Collection → Email Collection: Email Forwarding Rule**   | T1114.003         | "'Forward All' inbox rule → `sjenkins-backup@protonmail.com`"                                                                                                    |
| **Collection → Data from Information Repositories**        | T1213             | SharePoint downloads: `/sites/Engineering/.../Infrastructure-Diagram-2026.pdf`, `VPN-Config-Guide.docx`                                                          |
| **Exfiltration** (over web service)                        | T1567             | Files downloaded through the legitimate Graph API/session — blends in with normal cloud traffic                                                                  |
| **Persistence** (via valid accounts/rules)                 | T1098.001 / T1137 | Session cookie persistence + inbox rule surviving independent of credentials                                                                                     |


---
## Lessons Learned

- Watch for the multiple targets. Be prepared to open a number of lines of enquiry / investigation. 

---
## Key Takeaways

1. **MFA is not sufficient against AitM.** The push notification was genuinely approved — the victim authenticated, just to the wrong proxy. Consider phishing-resistant MFA (FIDO2/passkeys) which Evilginx-style proxies cannot relay.
2. **QR codes defeat URL inspection.** The malicious URL existed only as an image and was decoded on a personal device outside corporate controls. Conditional Access / device-compliance policies would have blocked the attacker's sign-ins (unmanaged device, impossible travel) far more reliably than email filtering.
3. **Session tokens were the crown jewels**, not passwords. Even a password reset after the fact leaves the stolen session and the forwarding rule intact — both need explicit revocation/removal.

---
## Appendix

### Open Questions

- There is a significant time delay between the initial infection and the upload of credentials. It has yet to be confirmed that no lateral movement was performed.
- Assumed notification of relevant regulatory bodies was performed.
