---

---

[← Back to Home](/)


**Date completed:** 10/10/2026
## Case Overview

**Summary**
The SOC team has identified suspicious activity on a web server within the company's intranet. To better understand the situation, they have captured network traffic for analysis. The PCAP file may contain evidence of malicious activities that led to the compromise of the Apache Tomcat web server.

### Objective
Analyse the PCAP file to understand the scope of the attack.


### Evidence Provided

| Filename        | SHA256 Hash                                                      |
| --- | --- |
| Web server.pcap | 9a8dbb2ec468166ff541f8f307544a5ceb07ce702f36d36fd8ae964bcb53f716 |

### Tools Used
- [[Wireshark]]


---
# Initial Assessment

## Initial Indicators
Upon loading the file immediately there are SMB tree connect requests with $IPC which raises suspicions. 

End point statistics show most of the packets are between 10.0.0.112 and 14.0.0.120 with each having around 20,000 packets each. The next closest being 1,460 packets. 

SMB2 packets start with a significant number of TCP packets and then SSH packets. Protocol hierarchy confirms this.

___


---
# Challenge Answers

## Question 1
Given the suspicious activity detected on the web server, the PCAP file reveals a series of requests across various ports, indicating potential scanning behavior. Can you identify the source IP address responsible for initiating these requests on our server?

**Answer:**
14.0.0.120

**Method:**
I found multiple red lined packets with RST which indicates TCP Resets. All of them were for different ports from the same port from that IP. 

## Question 2
Based on the identified IP address associated with the attacker, can you identify the country from which the attacker's activities originated?

**Answer:**
China

**Method:**
IP Lookup - Whatismyip.com

## Question 3
From the PCAP file, multiple open ports were detected as a result of the attacker's active scan. Which of these ports provides access to the web server admin panel?

**Answer:**
8080

**Method:**
I went to the bottom of the RST flags and searched HTTP entries and observed one with /admin.

I should have run a search for "admin". Always worth looking at anything found with that.

## Question 4
Following the discovery of open ports on our server, it appears that the attacker attempted to enumerate and uncover directories and files on our web server. Which tools can you identify from the analysis that assisted the attacker in this enumeration process?

**Answer:**
Gobuster

**Method:**
Gobuster is a known enumeration tool and the name can be observed in the user-id. 

## Question 5
After enumerating directories on our web server, the attacker made numerous requests to identify administrative interfaces. Which directory related to the admin panel did the attacker uncover? (Provide the path including the leading slash, e.g. /path)

**Answer:**
/manager

**Method:**
I filtered all the HTTP responses of success from the victim IP. Scrolling through found '/manager'

`ip.src == 10.0.0.112 && (http.response.code == 200 || http.response.code == 301 || http.response.code == 302)`
OR
`ip.dst == 14.0.0.120 && http.response.code == 200 && (http.request.uri contains "/admin" || http.request.uri contains "/login" || http.request.uri contains "/config" || http.request.uri contains "/manager")`

## Question 6
After accessing the admin panel, the attacker brute-forced the login. What credentials did the attacker successfully use? (Provide them in username:password format)

**Answer:**
`admin:tomcat`

**Method:**
So I did some filtering and was searching for admin but didn't think of 'credentials'. anyway, the filter i used revealed one packet which had the result.

`ip.src == 14.0.0.120 && http.request.method == "POST" && http.request.uri contains "manager"`

## Question 7
Once inside the admin panel, the attacker attempted to upload a file with the intent of establishing a reverse shell. Can you identify the name of this malicious file from the captured data?

**Answer:**
`JXQOZY.war`

**Method:**
Was in the same packet as before. Came to my attention as the name was "DeployWar". 

## Question 8
After the attacker established a reverse shell on our server, the payload connects back to the attacker's machine. From the analysis, what is the callback destination in `IP:port` format?

**Answer:**
14.0.0.120:443

**Method:**
Filter Wireshark traffic using `ip.src == 14.0.0.120 && tcp.flags == 0x012`. Follow the TCP stream of the reverse-shell traffic; the `/dev/tcp/<ip>/<port>` redirection reveals the callback IP address and port.

Had to use a hint with this one. AI stated re the filter:
When you filtered for `ip.src == 14.0.0.120 && tcp.flags == 0x012`, you found:

- **The attacker (14.0.0.120)** responding with SYN-ACK (0x012)
- **Meaning the victim initiated the connection** ← **PROOF OF REVERSE SHELL!**


---
# Investigation Log

| Step | Tool          | Command / Action                      | Purpose                          | Findings                           |
| ---- | --- | --- | --- | --- |
| 1.   | [[HashCalc]]  | Hash web server.pcap                  | Obtain SHA256 value              | As per evidence supplied value     |
| 2.   | [[Wireshark]] | Import .pcap file                     | Begin investigation              | Success                            |
| 3    | Wireshark     | Review of RST flags                   | Q2 Looking for scanning of ports | Multiple starting from packet 1097 |
| 4    | Wireshark     | Identification of admin port.         | Q3                               | 8080                               |
| 5    | Wireshark     | Identification of tool used           | Q4                               | GoBuster                           |
| 6    | Wireshark     | Identification of admin panel         | Q5                               | /manager                           |
| 7    | Wireshark     | Identification of username & password | Q6                               | admin:tomcat                       |
| 8    | Wireshark     | Identification of payload             | Q7                               | JXQOZY.war                         |
| 9    |               |                                       |                                  |                                    |

---
# Lessons Learned

- again, take your time and take notes. Complete all the required fields here in this investigation report.
