---
title: Boogyman 3 Lab
date: 2026-01-29 18:00:00
categories: [TryHackMe, Lab]
tags: [Log Analysis, Linux]
---

# Boogeyman 3

## Introduction

This lab is a continuation of the Boogeyman series of labs for Tryhackme and sees the attacker finish there phishing attempt by targeting the CEO of the company, Evan Hutchinson.

### Scenario
Without tripping any security defences of Quick Logistics LLC, the Boogeyman was able to compromise one of the employees and stayed in the dark, waiting for the right moment to continue the attack. Using this initial email access, the threat actors attempted to expand the impact by targeting the CEO, Evan Hutchinson. The email appeared questionable, but Evan still opened the attachment despite the scepticism. After opening the attached document and seeing that nothing happened, Evan reported the phishing email to the security team. 

## The Chaos Inside

### What is the PID of the process that executed the initial stage 1 payload?

Filter winlogbeat logs with the payload name as the keyword

```
ProjectFinancialSummary_Q3.pdf
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-27 204005.png>)

**Answer:** 6392

### The stage 1 payload attempted to implant a file to another location. What is the full command-line value of this execution?

Now filter for the pid found previously.

```
process.parent.pid: 6392
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-27 204611.png>)

**Answer:** "C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat

### The implanted file was eventually used and executed by the stage 1 payload. What is the full command-line value of this execution?

```
process.parent.pid: 6392 and review.dat
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-27 205103.png>)

**Answer:** "C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer

### The stage 1 payload established a persistence mechanism. What is the name of the scheduled task created by the malicious script?

We can look for signs of persistence through searching for scheduled tasks. We can combine this with the knowledge that it is attempting to run the rundll32.exe utility:

```
"rundll32" and "ScheduledTask"
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-27 205336.png>)

**Answer:** Review

### The execution of the implanted file inside the machine has initiated a potential C2 connection. What is the IP and port used by this connection? (format: IP:port)

```
process.name: "powershell.exe" and event.provider: "Microsoft-Windows-Sysmon"
```

With this command we can then search for the most common port and ip address to determine the most likely connection point.

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-27 210205.png>) ![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-27 210234.png>)

**Answer:** 165.232.170.151:80

### The attacker has discovered that the current access is a local administrator. What is the name of the process used by the attacker to execute a UAC bypass?

UAC byspass can elvate privileges in windows without triggering the UAC promp one such way is through DLL Hijacking with DLL being mentioned in previous questions giving a potential clue. To verify we can search using review.dat which controls the DLL Register Server. 

```
review.dat
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-27 211840.png>)

**Answer:** fodhelper.exe

We can see that the attacker uses fodhelper.exe which is used in fileless attacks as they can be used to execute commands with elavted privileges without triggering a UAC prompt.

### Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. What is the GitHub link used by the attacker to download a tool for credential dumping?

Since we know that the attacker accessed the tool via github we can use that as the key word to search through the logs. 

```
github.com
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-27 212306.png>)

**Answer:** https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

### After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. What is the username and hash of the new credential pair? (format: username:hash)

We know they used the new tool mimikatz.exe inorder to be able do this so we can search using this tool to find the log that reveals the credential pair.

```
mimikatz.exe
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-27 212932.png>)

**Answer:** itadmin:F84769D250EB95EB2D7D8B4A1C5613F2

### Using the new credentials, the attacker attempted to enumerate accessible file shares. What is the name of the file accessed by the attacker from a remote share?

The attacker now has priveleged accessed meaning they can continue deeper into their attack. To check for enumeration we can look on the CEO's device and see if they have used powershell to look through the different files. 

```
host.name: "WKSTN-0051.quicklogistics.org" and powershell.exe
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-28 122422.png>)

**Answer:** IT_Automation.ps1

### After getting the contents of the remote file, the attacker used the new credentials to move laterally. What is the new set of credentials discovered by the attacker? (format: username:password)

In the same set of logs we can also find the new credentials that the attacker found to move laterally.

```
host.name: "WKSTN-0051.quicklogistics.org" and powershell.exe
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-28 122355.png>)

**Answer:** QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987

### What is the hostname of the attacker's target machine for its lateral movement attempt?

```
allan.smith
```

We can now search with the allan smith name and then find the hostname of the device by see the commonality of host names. 

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-28 125626.png>)

**Answer:** WKSTN-1327

### Using the malicious command executed by the attacker from the first machine to move laterally, what is the parent process name of the malicious command executed on the second compromised machine?

Searching with the host device and checking for process creation with event id 1 the new process can be found. 

```
host.hostname: WKSTN-1327 and event.code: 1
```

**Answer:** wsmprovhost.exe

### The attacker then dumped the hashes in this second machine. What is the username and hash of the newly dumped credentials? (format: username:hash)

The attacker will likely use the same tool to dump the credentials as lasttime but on this host now and so we will search for that tool plus WKSTN-1327.

```
host.hostname: "WKSTN-1327" and "mimikatz"
```

**Answer:** administrator:00f80f2538dcb54e7adc715c0e7091ec

### After gaining access to the domain controller, the attacker attempted to dump the hashes via a DCSync attack. Aside from the administrator account, what account did the attacker dump?

DCSync attacks can be search for by checking for DC01.

```
host.hostname: "DC01" and process.name: "mimikatz.exe"
```

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-28 132503.png>)

**Answer:** backupda

### After dumping the hashes, the attacker attempted to download another remote file to execute ransomware. What is the link used by the attacker to download the ransomware binary?

We can check for a process being created during the DCSync attack using event id 1 and see if any new processes stands out. 

![alt text](<../assets/images/Posts/Boogeyman3-Lab/Screenshot 2026-01-28 133236.png>)

**Answer:** http://ff.sillytechninja.io/ransomboogey.exe