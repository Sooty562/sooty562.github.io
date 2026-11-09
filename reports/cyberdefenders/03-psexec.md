---

---

[← Home](/)

**Date Completed:** 9/10/2026

## Case Overview

**Summary**
An alert from the Intrusion Detection System (IDS) flagged suspicious lateral movement activity involving PsExec. This indicates potential unauthorized access and movement across the network. As a SOC Analyst, your task is to investigate the provided PCAP file to trace the attacker’s activities. 

### Objective
Identify their entry point, the machines targeted, the extent of the breach, and any critical indicators that reveal their tactics and objectives within the compromised environment.

### Evidence Provided
- 1 x PCAP file

### Tools Used
- Wireshark

---
# Evidence Collected

| ID    | Evidence Type      | Value | Significance                                                                                        |
| --- | --- | --- | --- |
| 131   | Wireshark Packet   |       | Shows attacker IP address accessing on Sales-PC.                                                    |
| 132   | Wireshark Packet   |       | Shows account name that attacker managed to used.                                                   |
| 138   | Wireshark Packet   |       | SMB2 Tree connect request to `\\10.0.0.133\$ADMIN` which was successful in following packet 139     |
| 144   | Wireshark Packet   |       | Create file request of PSEXESVC.exe which was successful.                                           |
| 238   | Reassembled Packet |       | PSEXESVC.exe reassembled in this packet. Packet 240 shows successful response from target machine.  |
| 38514 | Negotiated request |       | On 10.0.0.130, attacker attempted to setup a session on 10.0.0.131 with a hostname of marketing-pc. |

---
# Challenge Answers

## Question 1
To effectively trace the attacker's activities within our network, can you identify the IP address of the machine from which the attacker initially gained access?

**Answer:**
10.0.0.130

**Method:**
Just observed the amount of connections and also the PsExec file. Most of the conversations within Wireshark stats were between 10.0.0.130 and 10.0.0.133

## Question 2
To fully understand the extent of the breach, can you determine the machine's hostname to which the attacker first pivoted?

**Answer:**
sales-pc

**Method:**
This was difficult and I needed help. I should spend more time trying to find it and maybe asking AI for help as to where I could find the answers. But I had to follow on from the initial connection and I was looking near the right place but it was prior to "HR-PC". 

## Question 3
Knowing the username of the account the attacker used for authentication will give us insights into the extent of the breach. What is the username utilized by the attacker for authentication?

**Answer:**
ssales

**Method:**
This was in the next packet after Q2. 

## Question 4
After figuring out how the attacker moved within our network, we need to know what they did on the target machine. What's the name of the service executable the attacker set up on the target?

**Answer:**
PSEXESVC.exe

**Method:**
Following on from the access and username in Q3, there was several tree requests including one to $ADMIN which shows privileged access has been obtained. After that, the attacker requested create file permission and created the file there.

## Question 5
We need to know how the attacker installed the service on the compromised machine to understand the attacker's lateral movement tactics. This can help identify other affected systems. Which network share was used by [[PsExec]] to install the service on the target machine?

**Answer:**
ADMIN$

**Method:**
Reviewed the installation via TCP of the file. Packet 238 shows the completed, reassembled file and within the Tree ID is `\\10.0.0.133\ADMIN$`

## Question 6
We must identify the network share used to communicate between the two machines. Which network share did PsExec use for communication?

**Answer:**
IPC$

**Method:**
Continuing reading and found packet 438 had reassembled the same file but was in IPC$. and was performed by PsExe. 

## Question 7
Now that we have a clearer picture of the attacker's activities on the compromised machine, it's important to identify any further lateral movement. What is the hostname of the second machine the attacker targeted to pivot within our network?

**Answer:**
marketing-pc

**Method:**
As it says 'second machine', I searched for another IP address with the source being .130. I found a negotiated request to 10.0.0.131. packet 38514 is similar to the Q2 and revealed marketing-pc. 


---
# Lessons Learned

- slow down. Do each question and fill out the details and investigation log. 
