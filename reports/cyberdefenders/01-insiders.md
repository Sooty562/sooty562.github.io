---

---

[← Home](/)

## Case Overview

**Summary**

After Karen started working for 'TAAUSAI,' she began doing illegal activities inside the company. 'TAAUSAI' hired you as a soc analyst to kick off an investigation on this case.

You acquired a disk image and found that Karen uses Linux OS on her machine. 

### Objective

Identify tools and commands - the methodology - that Karen used to perform the illegal activities.

### Evidence Provided
- 1 x AD1 file - Image File


### Tools Used
- [[FTK Imager]]


---
# Initial Assessment

## Initial Indicators

Quick review of file structure within [[FTK Imager]] showed several interesting things of note. 
Use of:
- Kali
- Mimikatz
- Metasploit


## Investigation Hypotheses

1. Used Kali to intimidate another worker
2. extracted data using mimikatz


---
# Evidence Collected

| ID | Evidence Type | Significance | Date/Time of File |
|---|---|---|---|
| 1 | Distro - Kali | Shows means. Tool commonly used by hackers. OS | n/a |
| 2 | Karen’s Checklist | Shows motive | 19/3/22 0418hrs |
| 3 | Bash History | Shows commands used | n/a |
| 4 | Mimikatz download | Tool used to extract data | 19/3/22 0304hrs |
| 5 | myfirsthack folder | Number of scripts within the folder showing progressively better scripting skills | 19/3/22 0400hrs to 0414hrs |
| 6 | metasploit history file | shows commands used within metasploit framework. | 19/3/22 0535hrs |
| 7 | auth.log | shows Karenhacker obtaining su for user ‘postgres’ | 19/3/22 1126hrs |


___
# Challenge Answers

## Question 1
What distro?

**Answer:** 
Kali

**Method:**
sys logs within `/var/log/installer` 
also within 'boot' folder shows several kali files

## Question 2
What is the MD5 hash of the Apache **access.log** file?

**Answer:**
d41d8cd98f00b204e9800998ecf8427e

**Method:**
Found the access.log within the Apache2 file in /var/log/apache2/
exported to CSV and opened that. Had MD5 and SHA1 hash.

## Question 3
It is suspected that a credential dumping tool was downloaded. What is the name of the downloaded file?

**Answer:**
Mimikatz_trunk.zip

**Method:**
Located in the `root/downloads/` folder

## Question 4
A super-secret file was created. What is the absolute path to this file?

**Answer:**
/root/Desktop/SuperSecretFile.txt

**Method:**
Search through of the [[bash history]] which is located in the root or `usr` folder. 

## Question 5
What program used the file **didyouthinkwedmakeiteasy.jpg** during its execution?

**Answer:**
`binwalk`

**Method:**
located within the [[bash history]]. Same as above

## Question 6
What is the third goal from the checklist Karen created?

**Answer:**
Profit

**Method:**
Located text file on desktop with 3 goals. 

## Question 7
How many times was Apache run?

**Answer:**
0

**Method:**
Review of `var/log/apache2/` folder shows the logs. All logs are 0kbs and have no contents which suggests either not used or has been tampered with. Lack of corroborating info regarding the tampering leaves the result as0

## Question 8
This machine was used to launch an attack on another. Which file contains the evidence for this?

**Answer:**
irZLAohL.jpeg

**Method:**
Review of root directory had already revealed the jpeg file. The picture shows an image of a CLI with the directory being "Bob". The application being execution is AlphaSOC Network Flight Simulator which is used by pentesters. It is a legitimate tool used to recreate malicious network traffic. 

## Question 9
It is believed that Karen was taunting a fellow computer expert through a bash script within the Documents directory. Who was the expert that Karen was taunting?

**Answer:**
Young

**Method:**
Only 1 folder in the documents folder of `root` called `myfirsthack`. Several bash scripts in there however one had a line saying "I can bash script too Young".

## Question 10
A user executed the **su** command to gain root access multiple times at 11:26. Who was the user?

**Answer:**
postgres

**Method:**
Review of `/var/logs/auth.log`. Scrolled down to find the relevant timeframe within [[auth.log]]
Numerous lines say this:
`Mar 20 11:26:22 KarenHacker su[4101]: Successful su for postgres by root`
`Mar 20 11:26:22 KarenHacker su[4074]: pam_unix(su:session): session opened for user postgres by (uid=0)`

## Question 11
Based on the bash history, what is the current working directory?

**Answer:**
/root/Documents/myfirsthack/

**Method:**
Just reviewed the back history file. The last cd command showed it to be `../Documents/myfirsthack`


---
# Investigation Log

| No. | Date/Time       | Tool | Command / Action                              | Purpose                | Findings                                                          |
| --- | --------------- | ---- | --------------------------------------------- | ---------------------- | ----------------------------------------------------------------- |
| 1.  | 7/10/26         | FTK  | Imported image file "firsthack.ad1"           | Commence investigation |                                                                   |
| 2.  | 7/10/26 1810hrs | FTK  | Review of imported file.                      | Quick review & Q1      | Identified distro as Kali                                         |
| 3   | 7/10/26         | FTK  | Review of Apache file and exportation of hash | Q2                     | d41d8cd98f00b204 e9800998ecf8427e<br>                             |
| 4   | 7/10/26         | FTK  | Review of Downloads folder                    | Q3                     | mimikatz_trunk.zip                                                |
| 5   | 7/10/26         | FTK  | Review of bash history file                   | Q4, Q5                 | location of super secret file and program used to create jpg file |
| 6   | 7/10/26         | FTK  | Review of Desktop files                       | Q6                     | Karen's checklist                                                 |
| 7   | 8/10/26 1900hrs | FTK  | Review of `var/logs/apache2`                  | Q7                     | Found that the log files had 0kb suggesting no use of apache      |
| 8   | 8/10/26 1905hrs | FTK  | Review of logs and boot folder for evidence   | Q8                     | found .jpeg file that showed evidence of malicious action         |
| 9   | 8/10/26 1910hrs | FTK  | Documents folder                              | Q9                     | found a dir `myfirsthack` which contained several bash scripts    |
| 10  | 8/10/26 2020hrs | FTK  | `/var/log/auth.log`                           | Q10                    | review of log file found the answer.                              |
| 11  | 8/10/26 2030hrs | FTK  | Review of bash history file                   | Q11                    | last `cd` command                                                 |

---
# Lessons Learned
- I searched harder than I needed to. Often I had found the answer or the correct file but I assumed it was something harder to find. 
- Take your time.
