---
title: Boogyman 2 Lab
date: 2026-01-28 18:00:00
categories: [TryHackMe, Lab]
tags: [Log Analysis, Linux]
---

# Boogeyman 2

## Introduction

This lab is a continuation of Boogeyman 1 and sees the attacker performing a spearphishing scam that we must analyse. 

### Scenario
Maxine, a Human Resource Specialist working for Quick Logistics LLC, received an application from one of the open positions in the company. Unbeknownst to her, the attached resume was malicious and compromised her workstation. The security team was able to flag some suspicious commands executed on the workstation of Maxine, which prompted the investigation. Given this, you are tasked to analyse and assess the impact of the compromise.


## Spear Phishing Human Recourses

### What email was used to send the phishing email?

Observing the email header and attached files reveals the answer to the first few questions.

![alt text](<../assets/images/Posts/Boogeyman2-Lab/Screenshot 2026-01-27 151312.png>)

**Answer:** westaylor23@outlook.com

### What is the email of the victim employee?

**Answer:** maxine.beck@quicklogisticsorg.onmicrosoft.com

### What is the name of the attached malicious document?

**Answer:** Resume_WesleyTaylor.doc

### What is the MD5 hash of the malicious attachment?

![alt text](<../assets/images/Posts/Boogeyman2-Lab/Screenshot 2026-01-27 152549.png>)

**Answer:** 52c4384a0b9e248b95804352ebec6c5b

### What URL is used to download the stage 2 payload based on the document's macro?

Inserting the hash into virustotal.com reveals the payload url of the virus. 

![alt text](<../assets/images/Posts/Boogeyman2-Lab/Screenshot 2026-01-27 152558.png>)

**Answer:** https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png

### What is the name of the process that executed the newly downloaded stage 2 payload?

We can use the tool olevba to analyse the document with the following command:
```
olevba Resume_WesleyTaylor.doc
```

![alt text](<../assets/images/Posts/Boogeyman2-Lab/Screenshot 2026-01-27 153852.png>)

**Answer:** wscript.exe

### What is the full file path of the malicious stage 2 payload?

**Answer:** C:\ProgramData\update.js

### What is the PID of the process that executed the stage 2 payload?

Using the tool volatility we can analyse the memory for the process id of the stage 2 payload using the following command.

```
vol -f WKSTN-2961.raw.windows.pstree
```

![alt text](<../assets/images/Posts/Boogeyman2-Lab/Screenshot 2026-01-27 154601.png>)

**Answer:** 4260

### What is the parent PID of the process that executed the stage 2 payload?

**Answer:** 1124

### What URL is used to download the malicious binary executed by the stage 2 payload?

Know that it is likely from the boogeyman group we can grep search for their keyword to find a binary relating to them. 

```
strings WKSTN-2961.raw | grep boogeyman
```

![alt text](<../assets/images/Posts/Boogeyman2-Lab/Screenshot 2026-01-27 155443.png>)

**Answer:** https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe

### What is the PID of the malicious process used to establish the C2 connection?

We can scan using the PID for wscript.exe knowing that they are likely connected in execution to find the pid used to establish the connection with updater.exe

```
vol -f WKSTN-2961.raw windows.pstree | grep 4260
```

**Answer:** 6216

### What is the full file path of the malicious process used to establish the C2 connection?

we can now search for updater.exe to find the C2 connection:

```
vol -f WKSTN-2961.raw windows.cmdline | grep updater.exe
```

**Answer:** C:\Windows\Tasks\updater.exe

### What is the IP address and port of the C2 connection initiated by the malicious binary? (Format: IP address:port)

**Answer:** 128.199.95.189:8080

### What is the full file path of the malicious email attachment based on the memory dump?

We can use volatility to search for the location of the Resume malware. 

![alt text](<../assets/images/Posts/Boogeyman2-Lab/Screenshot 2026-01-27 164329.png>)

**Answer:** C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc

### The attacker implanted a scheduled task right after establishing the c2 callback. What is the full command used by the attacker to maintain persistent access?

Maintaining access would likely require access to background execution which means we should check in schtasks for anything suspicious. 

```
strings WKSTN-2961.raw | grep "schtasks"
```

![alt text](<../assets/images/Posts/Boogeyman2-Lab/Screenshot 2026-01-27 165042.png>)

**Answer:** schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'
