---

---

[← Home](/)

## Incident Overview

Date Performed: 8/11/26

### Executive Summary

**Incident:** Finance Mailbox Takeover at MegaCorp Logistics
**Affected Host:**   
**Timeline:** 
**Confidence:** 

**How did it happen?**
An SVG invoice attachment with an embedded script led the user to an adversary-in-the-middle (AiTM) phishing page. She submitted credentials and MFA, which the attacker captured — then stole her session cookies, giving full account access despite MFA.

**What they did** 
Replayed the stolen session from another IP, registered their own MFA method for persistence, read 48 emails via direct mailbox access, and set a hidden inbox rule forwarding all future mail externally while deleting the originals.

**Recommendations**
- Autonomous action on impossible-travel alerts and multi-login / session ID use. Such as immediate reset of session token and password. 
- Implement phishing-resistant MFA (passkeys/FIDO2 or Conditional Access with compliant-device requirements)
- Enforce token binding / continuous access evaluation so stolen session cookies die quickly
- Block script-bearing  attachments at the mail gateway.
### Initial Information

Date - 20/4/25
A finance analyst at MegaCorp Logistics reported that colleagues were receiving replies to messages she never sent, and her account was disabled while the investigation runs. You have the SIEM feed and the endpoint XDR telemetry for the workstation estate and the mail platform, covering the week around the report. Reconstruct what happened: which host produced the endpoint evidence, what its browser reached, how the account was taken over, and what was left behind on the mail platform so the containment plan is complete.

___
## Investigation 

### Workflow / Steps
| **Time**            | **Action**                                                                                                                                                                                                                           |
| --- | --- |
| 8/11/26 <br>1113hrs | Review of SIEM data. Data contains network, xdr, defender, DNS information.   Attempting to identify malicious actions. Identified affected host - `corps-wks-082`. Observed a suspicious created file at 10:19:40 - `phantomjs.exe` |
| 1126hrs             | Pivoted to review all actions on this host within SIEM data. Identified invoice.svg downloaded at 9:05 and following executable of phantomjs.exe 10:19.                                                                              |
| 1133hrs             | Reviewed XDR information and observed invoice.svg activated at 10:15 which then used browser to navigate to external website.                                                                                                        |
| 1933hrs             | Reviewed detected behaviours within the XDR feed. Added to timeline.                                                                                                                                                                 |
| 1938hrs             | Identified simultaneous logins for account  `amanda.garcia@megacorp.com` using the same session ID.                                                                                                                                  |
| 9/11/26 1035hrs     | Identified access and download of mailbox items belonging to amanda.garcia.                                                                                                                                                          |
| 1045hrs             | Identified new mailbox rule for amanda.garcia established the day after.                                                                                                                                                             |

### Tools Used
- SIEM
- XDR
- Threat Intel

---
## Findings
### Timeline

| **Time (UTC)**    | **Host**        | **Event**                                                                                                                                                                   | **Source**          |
| --- | --- | --- | --- |
| 20/4/25 9:05:00   | `corps-wks-082` | File created: C:\Users\amanda.garcia\Downloads\invoice.svg by OUTLOOK.EXE (PID 6120)                                                                                        | Sysmon Event ID 11  |
| 9:05:00           | `corps-wks-082` | An SVG attachment carrying an embedded script element was delivered to amanda.garcia@megacorp.com.                                                                          | Detected Behaviours |
| 10:15:22          | `corps-wks-082` | "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument C:\Users\amanda.garcia\Downloads\invoice.svg                                               | XDR Process Tree    |
| 10:15:23          | `corps-wks-082` | A browser navigated from a local file to an external host (ywnjb.com) on corp-wks-082                                                                                       | XDR Timeline        |
| 10:16:05          | `corps-wks-082` | A browser session to 207.35.10.251 carried request bodies with an unusually high U+FFA0 filler ratio on corp-wks-082                                                        | XDR Timeline        |
| 10:16:05          | `corps-wks-082` | A browser session from the finance workstation to 207.35.10.251 carried request bodies with an unusually high U+FFA0 filler-character ratio.                                | Detected Behaviours |
| 10:18:45          | `corps-wks-082` | A sign-in for`amanda.garcia@megacorp.com` completed from 207.35.10.251 through the relay; SessionId 2f0a7c4e-91b3-4d68-a2c5-8e7f013db942                                    | XDR Timeline        |
| 10:18:45          | `corps-wks-082` | A browser cookie store file was written under the user Temp folder by the headless automation binary shortly after the sign-in completed.                                   | Detected Behaviours |
| 10:19:39          | `corps-wks-082` | A headless automation binary started from the user Temp folder under the browser process on corp-wks-082                                                                    | XDR Timeline        |
| 10:19:40          | `corps-wks-082` | File created: C:\Users\amanda.garcia\AppData\Local\Temp\session_cookies.dat by phantomjs.exe (PID 1004)                                                                     | Sysmon Event ID 11  |
| 10:19:40          | `corps-wks-082` | A browser cookie store file was written under the user Temp folder by the headless automation binary on corp-wks-082                                                        | XDR Timeline        |
| 10:20:12          | `corps-wks-082` | Defender for Endpoint: unsigned binary phantomjs.exe written to C:\Users\amanda.garcia\AppData\Local\Temp\ and executed by msedge.exe                                       | sec-edr             |
| 10:21:30          | `corps-wks-082` | A sign-in for `amanda.garcia@megacorp.com` succeeded from `142.49.148.88` on the same SessionId 2f0a7c4e-91b3-4d68-a2c5-8e7f013db942 minutes after a Boston-network sign-in | XDR Timeline        |
| 10:21:30          | `corps-wks-082` | Two sign-ins for the same account carried one SessionId from 207.35.10.251 and from 142.49.148.88.                                                                          | Detected Behaviours |
| 10:24:58          |                 | A new multifactor method was registered for amanda.garcia@megacorp.com from 207.35.10.251                                                                                   | XDR Timeline        |
| 10:34:18          |                 | A non-interactive session from 45.227.255.101 read mailbox items for amanda.garcia@megacorp.com on srv-az-mail-01                                                           | XDR Timeline        |
| 10:34:18          |                 | 48 mailbox items were read for the compromised account by a non-interactive EWS session from 45.227.255.101.                                                                | Detected Behaviours |
| 21/04/26 14:00:00 |                 | An inbox rule was created on the compromised mailbox with a ForwardTo target outside the tenant and DeleteMessage set.                                                      | Detected Behaviours |



### Attack Chain Summary

- **09:05** — Malicious invoice.svg (with embedded script) arrives via Outlook
- **10:15** — User opens it in Edge; redirects to attacker site (`ywnjb.com` / `207.35.10.25`1)
- **10:16–10:18** — Victim signs in on the AiTM phishing relay (U+FFA0 filler = evasion fingerprint); MFA defeated because it passed through the proxy
- **10:19–10:20** — Headless phantomjs.exe drops and steals session cookies from the browser
- **10:21** — Stolen session replayed from a new IP (`142.49.148.88`), same SessionId
- **10:24** — Attacker registers a new MFA method → persistent access
- **10:34** — Mailbox read via EWS from a third IP (`45.227.255.101`); 48 items accessed
- **Next day** — Hidden inbox rule: forward externally + delete originals → covert ongoing surveillance

---

## Response

### Recommended Actions / Containment Response
 - Autonomous action on impossible-travel alerts and multi-login / session ID use. Such as immediate reset of session token and password. 
- Implement phishing-resistant MFA (passkeys/FIDO2 or Conditional Access with compliant-device requirements)
- Enforce token binding / continuous access evaluation so stolen session cookies die quickly
- Block script-bearing  attachments at the mail gateway.


---

## Detection & Threat Intelligence

### MITRE ATT&CK Mapping

|**MITRE ATT&CK ID**|**Technique Name**|**Related Event**|
|---|---|---|
|T1027|Obfuscated Files or Information|U+FFA0 filler evades traffic inspection|
|T1078.004|Valid Accounts: Cloud Accounts|Access with compromised identity|
|T1098.005|Account Manipulation: Device Registration|Rogue MFA method registered|
|T1114.002|Email Collection: Remote Email Collection|Mailbox read via EWS (non-interactive)|
|T1114.003|Email Forwarding Rule|Forward-to-external + delete inbox rule|
|T1185|Browser Session Hijacking|Cookies hijacked during live session|
|T1204.001|User Execution: Malicious File|User opens the file|
|T1539|Steal Web Session Cookie|phantomjs steals session cookies|
|T1550.004|Use Alternate Authentication Material: Web Session Cookie|Stolen cookie replayed from new IP|
|T1557|Adversary-in-the-Middle|AiTM relay captures creds + MFA|
|T1566.001|Spearphishing Attachment|SVG invoice delivered via Outlook|
|T1566.002|Spearphishing Link|Script redirects to attacker site (redirect phase)|


---
## Lessons Learned

1. When reviewing the incident on a number of different sources, it was helpful to flag anything that I found of interest, pull it together into a timeline and review it. Seeing it like that helped understand the bigger picture and the actions of the attacker.
2. Another inbox rule. With any mailbox breach, always review for that! I didn't pick it up until the end. 


---
## Appendix

### Open Questions

Nil


### Images / Files

Nil for this investigation


