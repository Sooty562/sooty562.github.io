---

---

[← Home](/)

## Case Overview

**Summary**
You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore renowned for its vast selection of literature. BookWorld prides itself on providing a seamless and secure shopping experience for book enthusiasts around the globe. Recently, you've been tasked with reinforcing the company's cybersecurity posture, monitoring network traffic, and ensuring that the digital environment remains safe from threats.  

Late one evening, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. This anomaly raises concerns about the integrity of BookWorld's customer data and internal systems, prompting an immediate and thorough investigation.  

As the lead analyst in this case, you are required to analyze the network traffic to uncover the nature of the suspicious activity. 

### Objective
Your objectives include identifying the attack vector, assessing the scope of any potential data breach, and determining if the attacker gained further access to BookWorld's internal systems.


### Evidence Provided
- 1 x pcap file


### Tools Used
- [[Wireshark]]


---
# Initial Assessment

## Initial Indicators
Large amount of GET requests from a single IP. User-agent of gobuster. IP address of 111.224.250.131

## Investigation Hypotheses

1. Attacker used gobuster to enumerate directories and hidden content on websites.


---
# Evidence Collected
Note - should have the ID No. from Wireshark here to help identify specific packet/evidence.

| ID  | Evidence Type                      | Value  | Significance                                                                |
| --- | ---------------------------------- | ------ | --------------------------------------------------------------------------- |
| 1.  | 111.224.250.131                    | High   | IP Address of attacker                                                      |
| 2.  | SQLi attempts                      | Medium | Number of attempts by the attacker                                          |
| 3.  | HTTP Response with email addresses | High   | Attacker managed to enumerate customer data in the SQL database 'customers' |
| 4.  | GoBuster enumeration               | Medium | attacker's enumeration of the folders/files to identify what exists         |
| 5.  | Login                              | High   | Login to the admin account with admin password from the attacking IP        |
| 6.  | PHP Upload                         | High   | PHP script uploaded by attacker.                                            |
___

---
# Challenge Answers

## Question 1
By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?
**Answer:**
111.224.250.131
**Method:**
As per initial assessment, observed a large number of GET requests, each for a common file or folder name that might be found on a website. In alphabetical order so appears to be scripted. User-agent of 'gobuster'
## Question 2
If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?
**Answer:**
Shijiazhuang
**Method:**
IP lookup of the IP address in google reveals this city in China.
## Question 3
Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. This knowledge is critical for finding the appropriate patch or workaround to close the security gap and prevent future exploitation. Can you provide the vulnerable PHP script name?
**Answer:**
`search.php`
**Method:**
Filtered to `ip.addr == 111.224.250.131 && http.request.method == "GET"` which showed all the requests and identified a slow progression of abuse of the `search.php` function.
## Question 4
Establishing the timeline of an attack, starting from the initial exploitation attempt, what is the complete request URI of the first SQLi attempt by the attacker?
**Answer:**
/search.php?search=book%20and%201=1;%20--%20- HTTP/1.1 

/search.php?search=book and 1=1; -- -

**Method:**
This was a bit harder and had to use AI. Special characters can't be transmitted safely in URLs, so they're replaced with `%XX` hexadecimal codes. Simply used the filter already and found the first SQLi attempt. Decoded using AI. Right answer.
## Question 5
Can you provide the complete request URI that was used to read the web server's available databases?
**Answer:**
`/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -`

**Method:**
Needed a lot of help with this one. AI got the decoding wrong. So should use the python script that I found. 
## Question 6
Assessing the impact of the breach and data access is crucial, including the potential harm to the organization's reputation. What's the table name containing the website users data?
**Answer:**
customers
**Method:**
I found the databases within a response to a SQL query. `bookworld_db` I then `ctrl+f` to search for any string of that. I found another GET request search a table called `bookworld_db.customers` which results in a number of email addresses returned when I viewed the HTTP stream.
## Question 7
The website directories hidden from the public could serve as an unauthorized access point or contain sensitive functionalities not intended for public access. Can you provide the name of the directory discovered by the attacker?
**Answer:**
/admin/
**Method:**
Filtered all the `not found` out of the results and searched for 'found'. Followed the HTTP stream which showed the directory. 
## Question 8
Knowing which credentials were used allows us to determine the extent of account compromise. What are the credentials used by the attacker for logging in?
**Answer:**
`admin:admin123!`
**Method:**
Filtered to the attacker's IP address and filter to `POST` requests which are usually used for logging in among other things.
`ip.addr == 111.224.250.131 && http.request.method == "POST"`
There were 5 results with the last one being different which suggests maybe the previous one was successful. The 2nd last one had the answer.
## Question 9
We need to determine if the attacker gained further access or control of our web server. What's the name of the malicious script uploaded by the attacker?
**Answer:**
/admin/uploads/NVri2vhp.php
**Method:**
After identifying the above, I filtered for HTTP protocols. Observed an uploads folder not far on and saw the PHP script in there. 

---
# Investigation Log
Should do hash checks often.

| Step | Tool          | Command / Action                            | Purpose                              | Findings                                                          |
| --- | --- | --- | --- | --- |
| 1.   | [[Wireshark]] | Opened pcap file supplied                   | To review contents                   | Significant number of GET requests for files/folders              |
| 2.   | Wireshark     | Review of contents                          | Identification of potential evidence | Identified IP address: 111.224.250.131 and user-agent of gobuster |
| 3    | Wireshark     | `ip.addr == `                               | Narrow down                          | Filter succeeded                                                  |
| 4    | Wireshark     | Review of GET requests                      | observed large amount                | gobuster was enumerating the files / folders it could find.       |
| 5    | Brave         | IP Lookup                                   | Q2                                   | Shijiazhuang                                                      |
| 6    | Wireshark     | Additional filter for all GET requests      | Q3                                   | shows abuse of search.php                                         |
| 7    | Wireshark     | Searched for first SQLi attempt             | Q4                                   | `/search.php?search=book and 1=1; -- -`                           |
| 8    | Wireshark     | Continued reviewing potential SQLi attempts | Q5                                   | identified encoded answer as above                                |
| 9    | Wireshark     | As per Q7 method                            | Q7                                   | /admin/                                                           |
| 10   | Wireshark     | As per Q8                                   | Q8                                   | `admin:admin123!`                                                 |
| 11   | Wireshark     | As per Q9                                   | Q9                                   | /admin/uploads/NVri2vhp.php                                       |

---
# Lessons Learned
- don't trust AI to do even simple decoding/translation
