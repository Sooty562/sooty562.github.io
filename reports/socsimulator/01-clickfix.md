---
layout: default
title: ClickFix Supply-Chain Compromise
---

## Executive Summary

**Incident:** ClickFix Supply-Chain Compromise  
**Affected Host:** 10.0.1.135 (User: anita.garcia)  
**Timeline:** 3 May 2025 – 5 May 2025 (approximately 47-hour attack window)  
**Confidence:** High

On 3 May 2025 at 11:05 UTC, a user navigating to a compromised site (`eemmbryequo.shop`) was exposed to a ClickFix attack — a social engineering campaign masquerading as a human verification check. The malicious webpage exploited the browser to write a command to the Windows clipboard without user consent. Approximately 7 seconds later, the user interacted with the Run dialog and pasted the payload, launching PowerShell which downloaded secondary malware stages to disk.

Within minutes, the attacker achieved execution via LOLBin abuse (`regasm.exe` loading a masqueraded DLL), established persistence through a registry run key disguised as `ChromeUpdater`, and deployed a credential-stealing binary. By the following day (4 May 01:59 UTC), the malware had accessed Chrome's local credential store. On 5 May, the stealer initiated outbound HTTPS communication to an external command-and-control server using a spoofed SNI (`graph.microsoft.com`) to evade detection.

This incident demonstrates a complete kill chain from initial access through exfiltration. No evidence of lateral movement or additional host compromise was identified in the provided telemetry, though the credential theft necessitates assumption of breach for the affected user account. Immediate containment and credential rotation are required.

**Attack Chain Summary**

- Anita Garcia visited eemmbryequo.shop (45.147.230.19), which displayed a fake CAPTCHA page.
- The page staged a malicious PowerShell command on her machine and told her to press Win+R, paste, and Enter (ClickFix).
- PowerShell fetched the downloader and dropped l6E.exe from promptcraft.online; mshta.exe then ran it, and regasm.exe loaded an unsigned library out of the user's Temp folder into the .NET runtime.
- cleanuploader.exe read Chrome's Login Data (saved credentials) and exfiltrated it to the external address identified, disguised with a spoofed graph.microsoft.com TLS SNI.
---
## Initial Information

### What We Know So Far

- Date - 3/5/25
- Affected user: anita.garcia (workstation corp-wks-102, IP 10.0.1.135)
- She visited eemmbryequo.shop, which displayed a fake CAPTCHA page
- The page instructed her to press Win+R, paste, and hit Enter
- A PowerShell command was executed, downloading a payload from promptcraft.online
- Multiple suspicious processes have been detected by our XDR agent

---
## Timeline

Table 1 - **Host:** `corp-wks-102` | **IP Address**: `10.0.1.135`

| **Time (UTC)**  | **Event**                                                                                                                                                                                    | **Source**           |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
|                 |                                                                                                                                                                                              |                      |
| 3/5/25 11:05:40 | Navigation: msedge.exe -> `https://eemmbryequo[.]shop/` (page presented a 'Verify You Are Human' check)                                                                                      | XDR Browser Monitor  |
| 11:05:40        | Network connection: msedge.exe -> `45.147.230[.]19:443` (`eemmbryequo[.]shop`)                                                                                                               | Windows Sysmon       |
| 11:05:44        | Script from eemmbryequo.shop called navigator.clipboard.writeText and placed 174 bytes into the Windows clipboard; no user copy action preceded it                                           | XDR Browser Monitor  |
| 11:06:12        | Process created: powershell.exe (parent explorer.exe, launched from the Run dialog by the logged-on user)                                                                                    | XDR Browser Monitor  |
| 11:06:15        | Network connection: powershell.exe -> `185.91.69[.]119:443` (`promptcraft[.]online`) - payload download                                                                                      | Windows Sysmon       |
| 11:06:18        | `ALLOW \| 10.0.1.135:50112 -> 185.91.69[.]119:443 \| app=ssl \| url=promptcraft.online/l6E.exe`                                                                                              | Palo Alto FW Log     |
| 11:08:30        | Network connection: msedge.exe -> `185.91.69[.]119:443` (`promptcraft[.]online`)                                                                                                             | Windows Sysmon       |
| 11:10:45        | File created: C:\Users\anita.garcia\Downloads\l6E.exe (unsigned executable downloaded via PowerShell)                                                                                        | XDR File Monitor     |
| 11:11:58        | File created: C:\Users\anita.garcia\AppData\Local\Temp\Microsoft.Runtime.dll (DLL loaded by regasm.exe, unsigned)                                                                            | XDR File Monitor     |
| 11:12:10        | File created: C:\Users\anita.garcia\AppData\Local\Temp\cleanuploader.exe (credential stealer dropped by regasm.exe, unsigned)                                                                | XDR File Monitor     |
| 11:12:20        | Registry value set: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ChromeUpdater = C:\Users\anita.garcia\AppData\Local\Temp\cleanuploader.exe (autostart persistence; parent regasm.exe) | XDR Registry Monitor |
| 4/5/25 01:59:59 | File accessed: C:\Users\anita.garcia\AppData\Local\Google\Chrome\User Data\Default\Login Data (Chrome credential store read by cleanuploader.exe)                                            | XDR File Monitor     |
| 5/5/25 10:29:05 | Network connection: cleanuploader.exe -> `185.147.124[.]40:443` (graph.microsoft.com)                                                                                                        | Windows Sysmon       |
| 10:30:00        | `ALLOW \| 10.0.1.135:50788 -> 185.147.124[.]40:443 \| app=ssl \| sni=graph.microsoft.com`                                                                                                    | Palo Alto FW Log     |



## Technical Analysis

This ClickFix attack chained browser-to-shell execution with LOLBin abuse. A malicious webpage poisoned the clipboard via `navigator.clipboard.writeText`, then the user pasted into Run dialog, spawning `powershell.exe` from `explorer.exe`. PowerShell downloaded `l6E.exe` from `promptcraft.online` (`185.91.69.119`), which loaded a masqueraded DLL (`Microsoft.Runtime.dll`) via `regasm.exe` to execute `cleanuploader.exe`. The stealer persisted via HKCU Run key (`ChromeUpdater`), accessed Chrome's `Login Data`, and exfiltrated via HTTPS to `185.147.124.40` using spoofed SNI `graph.microsoft.com`. Total dwell time: ~47 hours. Credential theft confirmed; account compromise assumed.

## Response Actions

1. Isolated `corp-wks-102` from the network
2. Killed processes running related
3. Deleted extension, files and dlls
4. Reset registry key to stop persistence
5. Add firewall entries to block identified IP addresses
6. Kill any sessions for user
7. Reset/rotate all credentials/certificates for user.

## MITRE ATT&CK Mapping

| **MITRE ATT&CK ID** | **Technique Name**                                               | **Related Event**                                                                                                                                                                                                                                                     |
| ------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T1566.002           | Phishing: Spearphishing Link                                     | 3/5 11:05:40 — User navigates to `eemmbryequo.shop` presenting a fake "Verify You Are Human" CAPTCHA page (ClickFix lure)                                                                                                                                             |
| T1204.001           | User Execution: Malicious Link                                   | 3/5 11:05:40 — User interacts with the fake CAPTCHA, triggering the lure sequence                                                                                                                                                                                     |
| T1115               | Clipboard Data _(adversary-modified clipboard as lure delivery)_ | 3/5 11:05:44 — Script on `eemmbryequo.shop` writes 174 bytes to the clipboard with no user copy action (clipboard poisoning to stage the malicious command for paste)                                                                                                 |
| T1204.002           | User Execution: Malicious File                                   | 3/5 11:06:12 — User executes content staged via the poisoned clipboard through the Run dialog (paste-and-run behavior characteristic of ClickFix)                                                                                                                     |
| T1059.001           | Command and Scripting Interpreter: PowerShell                    | 3/5 11:06:12 — `powershell.exe` spawned from `explorer.exe` via the Run dialog                                                                                                                                                                                        |
| T1105               | Ingress Tool Transfer                                            | 3/5 11:06:15 / 11:10:45 — `powershell.exe` downloads `l6E.exe` from `promptcraft.online` (185.91.69.119:443), saved to `anita.garcia\Downloads`                                                                                                                       |
| T1036.005           | Masquerading: Match Legitimate Name or Location                  | 3/5 11:11:58 — Unsigned file named `Microsoft.Runtime.dll` dropped in Temp to impersonate a legitimate Microsoft runtime library                                                                                                                                      |
| T1218.009           | System Binary Proxy Execution: Regsvcs/RegAsm                    | 3/5 11:11:58 — `regasm.exe` loads the unsigned `Microsoft.Runtime.dll` (LOLBin abuse to execute the DLL)                                                                                                                                                              |
| T1547.001           | Registry Run Keys / Startup Folder                               | 3/5 11:12:20 — `HKCU\...\CurrentVersion\Run\ChromeUpdater` set to `cleanuploader.exe` for autostart persistence (parent: regasm.exe)                                                                                                                                  |
| T1555.003           | Credentials from Password Stores: Credentials from Web Browsers  | 4/5 01:59:59 — `cleanuploader.exe` reads Chrome's `Login Data` credential store (likely also T1539 STEAL WEB SESSION COOKIE territory if cookies were harvested — worth confirming from the tool's behavior)                                                          |
| T1071.001           | Application Layer Protocol: Web Protocols                        | 5/5 10:29:05 — `cleanuploader.exe` makes outbound HTTPS connections to 185.147.124.40 with `sni=graph.microsoft.com`                                                                                                                                                  |
| T1041               | Exfiltration Over C2 Channel _(probable)_                        | 5/5 10:29:05 — Post-theft SSL session to `graph.microsoft.com` from the credential stealer; if it's using stolen tokens/cookies against Graph API for exfil or mail access, also consider T1550.001 (Use Alternate Authentication Material: Application Access Token) |


## Indicators of Compromise

### Domains & URLs

|IOC|Type|Context|
|---|---|---|
|`eemmbryequo.shop`|Domain|Initial lure/CAPTCHA page|
|`promptcraft.online`|Domain|Payload download server|
|`promptcraft.online/l6E.exe`|URL|Primary malicious executable|
|`graph.microsoft.com`|Spoofed SNI|C2 channel (IP does not belong to Microsoft)|

### IP Addresses

|IOC|Type|Context|
|---|---|---|
|`45.147.230.19`|IPv4|eemmbryequo.shop resolver|
|`185.91.69.119`|IPv4|promptcraft.online payload server|
|`185.147.124.40`|IPv4|C2/exfiltration endpoint (spoofed Microsoft SNI)|

### File Artifacts

| IOC                     | Path                                                                             | Hash    | Context                       |
| ----------------------- | -------------------------------------------------------------------------------- | ------- | ----------------------------- |
| `l6E.exe`               | `C:\Users\anita.garcia\Downloads\l6E.exe`                                        | Unknown | Stage 1 executable (unsigned) |
| `Microsoft.Runtime.dll` | `C:\Users\anita.garcia\AppData\Local\Temp\Microsoft.Runtime.dll`                 | Unknown | Masqueraded DLL (unsigned)    |
| `cleanuploader.exe`     | `C:\Users\anita.garcia\AppData\Local\Temp\cleanuploader.exe`                     | Unknown | Credential stealer (unsigned) |
| `Login Data`            | `C:\Users\anita.garcia\AppData\Local\Google\Chrome\User Data\Default\Login Data` | N/A     | Accessed credential database  |

### Registry Artifacts

|IOC|Key|Value|Context|
|---|---|---|---|
|Persistence|`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`|`ChromeUpdater = C:\Users\anita.garcia\AppData\Local\Temp\cleanuploader.exe`|Autostart mechanism|

### Process Indicators

|IOC|Parent Process|Context|
|---|---|---|
|`powershell.exe`|`explorer.exe` (via Run dialog)|Malicious command execution|
|`regasm.exe`|N/A|LOLBin proxy execution|
|`cleanuploader.exe`|`regasm.exe`|Dropper/stealer process|

### Network Indicators

|IOC|Port|Protocol|Context|
|---|---|---|---|
|Any outbound to the above IPs|443|HTTPS/TLS|All C2 and payload traffic|

### Behavioural Indicators

|IOC|Description|
|---|---|
|Clipboard write without user action|`navigator.clipboard.writeText` from web page (T1115 variant)|
|Unsigned executables in Temp/Downloads|Multiple files marked unsigned in telemetry|
|SNI mismatch|Connection to 185.147.124.40 advertising `graph.microsoft.com`|
|Legitimate binary proxy execution|`regasm.exe` loading unsigned third-party DLL|


## Recommendations


Rules:
```yaml
title: Browser Process Spawning Command Interpreter
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\msedge.exe'
      - '\chrome.exe'
      - '\firefox.exe'
      - '\brave.exe'
  selection_child:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\mshta.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\curl.exe'
      - '\bitsadmin.exe'
  condition: selection_parent and selection_child
level: high
falsepositives:
  - Enterprise browser extensions or management agents with unusual architecture
  - Some legacy line-of-business web apps launching helper utilities
```

## Open Questions

- There is a significant time delay between the initial infection and the upload of credentials. It has yet to be confirmed that no lateral movement was performed.
- Assumed notification of relevant regulatory bodies was performed.

## Containment


**Immediate (first 60 minutes)**

1. **Network-isolate 10.0.1.135.** Do not power it off — volatile evidence (running `cleanuploader.exe`, clipboard contents, process handles on Chrome's `Login Data`) lives in memory. Isolate at the EDR/switch level so you retain forensic access.
2. **Block the infrastructure at the perimeter.** Add `eemmbryequo.shop`, `promptcraft.online`, `45.147.230.19`, `185.91.69.119`, and `185.147.124.40` to DNS sinkhole, proxy deny-list, and firewall egress rules. Note that `185.147.124.40` should be blocked **by IP**, not by SNI — the `graph.microsoft.com` SNI is spoofed and any SNI-based rule will miss it.
3. **Treat the user's credentials as compromised.** Assume every secret in Chrome's `Login Data` store — passwords, cookies, session tokens — is in adversary hands. Force a password reset for `anita.garcia` from a _different, known-clean_ device, then revoke all active sessions and refresh tokens.
4. **Review Entra ID / Microsoft 365 sign-in logs** for the account, filtered to the 4–5 May window and looking specifically for anomalous source IPs, impossible-travel, new MFA method registrations, new inbox rules, and OAuth application consents. Given the Graph-oriented C2, token replay against Microsoft 365 is the highest-value follow-on scenario.
5. **Check whether the account had privileged or SSO-broad access.** If yes, escalate to a broader identity incident and notify the identity team immediately.

**Short-term (24 hours)**

6. **Hunt for the same IOCs estate-wide** — proxy/DNS logs for the two domains and three IPs, EDR telemetry for the three filenames, and the registry value name `ChromeUpdater`. ClickFix campaigns are typically delivered to many users simultaneously; the first report is rarely the only victim.
7. **Preserve evidence before remediation** — memory image, `$MFT`/USN journal, Sysmon and PowerShell operational logs, browser history and download records, and the quarantine copies of all three binaries. Get hashes computed on the recovered samples and add them to the IOC table (they're currently marked unknown).
8. **Notify affected parties** per your regulatory and contractual obligations if the credential store contained business or customer accounts.
9. **Interview the user** briefly: confirm whether they recall pasting into the Run dialog, and check whether they reused the exposed passwords elsewhere.

**Recovery**

10. **Rebuild rather than clean.** With a credential stealer, a persistent Run key, and a masqueraded DLL having executed, a wipe-and-reimage is faster and more defensible than surgical removal. Reimage, patch, then re-enrol in EDR before returning to the network.
11. **Re-authenticate everything** on the rebuilt host: MFA re-registration, new device certificates, and fresh tokens only.

## Appendix
