---

---

[← Back to Home](/)

## Executive Summary

**Date Completed:** 15/11/2026

Over eight days, an attacker gained access to an employee's workstation after a file was downloaded and run. This file allowed the attackers access where the stole cloud credentials, dumped all the Azure directory information and took control of Kubernetes cluster secrets. 

**What went wrong**
- An employee was tricked into downloading and running an unsigned file. No controls stopped it.
- Privileged accounts and a 'break-glass' admin account were used with triggering alarms or requiring MFA.
- Security email alerts were being hidden by a malicious inbox rule.

**What went right**
- The telemetry existed and worked. XDR, Sysmon, firewall logs all captured a near full attack chain (as below)
- We have identified all affected hosts and systems involved due to the visibility.

**Recommendations**
1. Application allow-listing - block unsigned applications/executables from running. eg Airlock Digital
2. Require mandatory MFA for all admin accounts and tighter monitoring of those.
3. Segment networks so workstations cannot reach production and cluster APIs directly.
4. Restrict outbound internet traffic to approved destinations.


### Timeline

| **Time (UTC)**    | **Host**        | **Event**      | **Source**                          |
| --- | --- | --- | --- |
| 6/10/25 08:15:03  | `corp-wks-8821` | An unsigned Downloads binary resolved a public blob-storage hostname (`finance-backups.blob.core.windows.net`) and reached 217.44.76.238                                                                                                                                          | XDR                                 |
| 6/10/25 08:15:03  | `corp-wks-8821` | File created: C:\Users\marcus.aurelius\Downloads\goblob.exe by chrome.exe (PID 30012)                                                                                                                                                                                             | Microsoft-Windows-Sysmon            |
| 7/10/25 10:46:01  | `corp-wks-8821` | A PowerShell session requested an OAuth access token for application b830a68f-3489-4a83-b291-cf3107b1a456 against the Microsoft Graph resource                                                                                                                                    | XDR                                 |
| 12:17:32          | `corp-wks-8821` | The workstation was locked. Account: marcus.aurelius                                                                                                                                                                                                                              | Microsoft-Windows-Security-Auditing |
| 12:53:20          | `corp-wks-8821` | kubectl.exe (kubectl) started by explorer.exe as ACME-CORP\marcus.aurelius                                                                                                                                                                                                        | XDR                                 |
| 13:12:10          | `corp-wks-8821` | The workstation was unlocked. Account: marcus.aurelius                                                                                                                                                                                                                            | Microsoft-Windows-Security-Auditing |
| 8/10/25 01:37:19  | `corp-wks-8821` | A Microsoft Graph directory-enumeration run under the dev_ops_automation service account redirected its output to a file on disk                                                                                                                                                  | XDR                                 |
| 8/10/25 01:37:19  | `corp-wks-8821` | Process Create: C:\Users\marcus.aurelius\Downloads\AzureHound.exe (PID 30024, parent cmd.exe 30020, user ACME-CORP\dev_ops_automation)                                                                                                                                            | Microsoft-Windows-Sysmon            |
| 8/10/25 01:37:19  | `corp-wks-8821` | A new process has been created. Image: C:\Windows\System32\cmd.exe<br>`cmd.exe /c AzureHound.exe -u dev_ops_automation@acme-corp.cloud --collect all > /tmp/graph_objects.json`<br>                                                                                               | Microsoft-Windows-Security-Auditing |
| 8/10/25 01:37:19  | `corp-wks-8821` | File created: `/tmp/graph_objects.json` by cmd.exe (PID 30020)                                                                                                                                                                                                                    | Microsoft-Windows-Sysmon            |
| 8/10/25 01:37:20  | `corp-wks-8821` | Process Create: C:\Users\marcus.aurelius\Downloads\AzureHound.exe (PID 30024, parent cmd.exe 30020, user ACME-CORP\dev_ops_automation)<br>`AzureHound.exe -u dev_ops_automation@acme-corp.cloud --collect all`                                                                    | Microsoft-Windows-Sysmon            |
| 8/10/25 01:37:20  | `corp-wks-8821` | File created: /tmp/compromised_tokens.txt by cmd.exe (PID 30020)                                                                                                                                                                                                                  | Microsoft-Windows-Sysmon            |
| 2:09:53           | `corp-wks-8821` | Network connection: powershell.exe (PID 30016) 10.0.1.134:51720 -> 185.220.101.35:443 (-)                                                                                                                                                                                         | Microsoft-Windows-Sysmon            |
| 2:09:53           | `corp-wks-8821` | 10.0.1.134:63886 → 185.220.101.35:443 (Allow-Outbound-HTTPS-Any)                                                                                                                                                                                                                  | Firewall Log                        |
| 2:09:53           | `corp-wks-8821` | Non-interactive sign-in activityAzureActiveDirectory. Agent: python-requests/2.31.0<br>MFA: not used.                                                                                                                                                                             | AzureAD logs                        |
| 3:14:40           | `corp-wks-8821` | New-InboxRuleExchange:<br>  "Parameters": [<br>    {<br>      "Name": "Name",<br>      "Value": ".."<br>    },<br>    {<br>      "Name": "MoveToFolder",<br>      "Value": "RSS Subscriptions"<br>    },<br>    {<br>      "Name": "From",<br>      "Value": "security@"<br>    } | Exchange logs                       |
| 22:02:53          |                 | NetworkSecurityGroupFlowLog<br>An inbound flow reached srv-app-prod-01 from an internal source that does not match its normal traffic profile.<br>IP: `10.0.1.134`                                                                                                                | Cloud logs                          |
| 9/10/25 10:59:53  | `corp-jmp-0269` | admin.breakglass login used                                                                                                                                                                                                                                                       | AzureAD logs                        |
| 10/10/25 20:45:58 | `corp-wks-8821` | Process Create: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID 29056, parent explorer.exe 29040, user ACME-CORP\marcus.aurelius)                                                                                                                                  | Microsoft-Windows-Sysmon            |
| 10/10/25 20:46:21 | `corp-wks-8821` | A new process has been created. Image: C:\Windows\System32\cmd.exe                                                                                                                                                                                                                | Windows Security Log                |
| 10/10/25 20:46:21 | `corp-wks-8821` | A process running under an interactive user account wrote Kubernetes cluster material to a local temporary directory                                                                                                                                                              | XDR                                 |
| 10/10/25 20:46:21 | `corp-wks-8821` | Process Create: C:\Windows\System32\cmd.exe (PID 29060, parent powershell.exe 29056, user ACME-CORP\marcus.aurelius)                                                                                                                                                              | Microsoft-Windows-Sysmon            |
| 10/10/25 20:46:21 | `corp-wks-8821` | A new process has been created. Image: C:\Windows\System32\cmd.exe <br>`cmd.exe /c kubectl get secrets --all-namespaces -o yaml > /tmp/etcd_secrets.txt`                                                                                                                          | Microsoft-Windows-Security-Auditing |
| 10/10/25 20:46:21 | `corp-wks-8821` | File created: /tmp/etcd_secrets.txt by cmd.exe (PID 29060)                                                                                                                                                                                                                        | Microsoft-Windows-Sysmon            |
| 10/10/25 20:46:21 | `corp-wks-8821` | Network connection: kubectl.exe (PID 29064) 10.0.1.134:52904 -> 10.0.2.143:6443 (-)                                                                                                                                                                                               | Microsoft-Windows-Sysmon            |
| 12/10/25 22:10:51 | `corp-wks-8821` | Process Create: C:\Windows\System32\cmd.exe (PID 28060, parent powershell.exe 28056, user ACME-CORP\marcus.aurelius)<br>`cmd.exe /c curl -s http://srv-app-prod-01/.env -o C:\Users\marcus.aurelius\AppData\Local\Temp\.env`                                                      | Microsoft-Windows-Sysmon            |
| 14/10/25 04:30:05 | `corp-wks-8821` | Network connection: kubectl.exe (PID 27020) 10.0.0.6:54780 -> 10.0.2.143:6443 (k8s-node-primary-01)                                                                                                                                                                               | Microsoft-Windows-Sysmon            |

---

## Investigation 
### Initial Information

Nine days of telemetry from a cloud-first Azure estate: Entra ID sign-ins, Windows endpoints, a Kubernetes cluster, an Azure Function and the storage accounts behind them all report into one SIEM. Something inside that window does not fit the shape the estate normally has. Work the SIEM, XDR, firewall and cloud panels together, pin each observation to a host and a principal you can name, and rebuild the sequence from the records themselves.

### Workflow / Steps

| **Time** | **Action** |
| --- | --- |
| 10/11/26 1500hrs | Review of SIEM and XDR data. Review of process tree of infected endpoint `corp-wks-8821`. |
| 1603hrs              | Review of Cloud logs including AzureAD and Exchange. Identified new mailbox rules and out-of-hours log ins that were successful. Identified use of python and admin.breakglass |
| 15/11/26 1300hrs     | Review of SIEM data to identify process and executable behind |
| 1330hrs              | Review of telemetry shows user `Marcus.Aurelius` (M.A) regularly logging and being present between 0630hrs and 1800hrs. 1 script routinely performed and regularly obtaining weather information. <br>On 7/10/25 - M.A logged off at 1217hrs and logged back on again at 1312hrs. Between this time explorer.exe created a kubectl.exe process - a Kubernetes CommandLine tool. The following morning at 0134hrs, user logged on in uncharacteristic manner. |

### Tools Used
- SIEM
	- Firewall logs
	- Network logs
	- EDR logs
	- Azure / Cloud logs

---

## Findings

### Attack Chain Summary

- 6/10 — Initial Access: Marcus downloads unsigned `goblob.exe` from `finance-backups.blob.core.windows.net` via Chrome; executes it.
- 6/10 — Reconnaissance: goblob probes Azure blob storage.
- 7/10 — Cloud Access: PowerShell obtains OAuth token for app `b830a68f…` via Microsoft Graph; kubectl run as marcus.aurelius.
- 7–8/10 — Credential Access & Discovery: AzureHound + Graph directory enumeration under `dev_ops_automation`; tokens saved to `/tmp/compromised_tokens.txt`.
- 8/10 — C2 & Persistence: PowerShell beacons to 185.220.101.35 (Tor); Entra sign-in via stolen token, no MFA; inbox rule hides `security@` mail.
- 8–9/10 — Lateral Movement: Anomalous inbound flow to srv-app-prod-01; breakglass account login on corp-jmp-0269.
- 10/10 — Collection: `kubectl get secrets --all-namespaces` dumped to `/tmp/etcd_secrets.txt`.
- 12/10 — Credential Access: `.env` file pulled from srv-app-prod-01 over HTTP.
- 14/10 — Continued Access: kubectl to API server from new source IP 10.0.0.6.

---
## Containment Response

Immediate
- Network restriction of infected hosts.
- Revocation of all sessions and passwords for users affected.
- Removal of installed software associated with malware.
- Removal of email forwarding rule
- Firewall rule re malicious IPs / known Tor exit nodes

Next
- Mandatory MFA for all admins (if not everyone)
- Review of firewall rules.

Long-term
- Block unsigned applications/binaries from user directories.
- Alert on Tor exits
- Training for staff involved re phishing / downloading of unknown files.


---

## Detection & Threat Intelligence

### MITRE ATT&CK Mapping

| **MITRE ATT&CK ID** | **Technique Name**                        | **Related Event**                                      |
| --- | --- | --- |
| T1021               | Remote Services                           | Inbound flow from corp-wks-8821 to srv-app-prod-01     |
| T1041               | Exfiltration Over C2 Channel              | Tor HTTPS session during token staging __              |
| T1059.001           | PowerShell                                | Token request (7/10), kubectl chain (10/10)            |
| T1059.003           | Windows Command Shell                     | `cmd.exe /c kubectl`, `cmd.exe /c curl`                |
| T1069.002           | Permission Groups Discovery: Cloud Groups | AzureHound enumeration                                 |
| T1071.001           | Web Protocols                             | HTTPS to 185.220.101.35, blob storage fetch            |
| T1074.001           | Local Data Staging                        | `/tmp/compromised_tokens.txt`, `/tmp/etcd_secrets.txt` |
| T1078.001           | Default Accounts                          | `dev_ops_automation` misuse                            |
| T1078.004           | Cloud Accounts                            | Breakglass login, Entra token replay                   |
| T1090.003           | Proxy: Tor                                | Connection to 185.220.101.35                           |
| T1105               | Ingress Tool Transfer                     | Payload from `finance-backups.blob.core.windows.net`   |
| T1114.002           | Email: Inbox Rules                        | New-InboxRule on `security@` mail                      |
| T1190               | Exploit Public-Facing Application         | Inbound flow to srv-app-prod-01                        |
| T1204.002           | User Execution: Malicious File            | goblob.exe downloaded and run                          |
| T1528               | Steal Application Access Token            | OAuth token requests, identity crossover               |
| T1552.001           | Credentials in Files                      | `/tmp/compromised_tokens.txt`, `.env` retrieval        |
| T1552.007           | Container API                             | `kubectl get secrets --all-namespaces`                 |
| T1564.008           | Hide Artifacts: Email Hiding Rules        | Rule moves security mail to RSS Subscriptions          |
| T1566.002           | Spearphishing Link                        | Finance-themed download lure _(inferred)_              |
| T1580               | Cloud Infrastructure Discovery            | Graph directory enumeration                            |
| T1583.008           | Acquire Infrastructure: Cloud Storage     | `finance-backups` storage account                      |
| T1613               | Container and Resource Discovery          | kubectl reconnaissance                                 |
| T1619               | Cloud Storage Object Discovery            | goblob blob enumeration                                |
| T1213               | Data from Information Repositories        | `.env` pulled from prod server                         |

---
## Lessons Learned

- Spend more time initially reviewing. Keep to the basics first. Review the pattern of behaviour and then look for outliers. The logging on in the morning and off in the evening was generally consistent. Then all of a sudden - 1am!
- Open the events and review them carefully. At the start of this investigation, I missed cmd line prompts which were obviously malicious.



---
## Appendix


### Images

Nil for this investigation
