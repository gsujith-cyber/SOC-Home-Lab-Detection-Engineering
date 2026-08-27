# SOC Home Lab — Splunk Detection Queries

This document contains the Splunk SPL detection queries used in the SOC Home Lab for security monitoring, attack detection, event analysis, correlation, and incident investigation.

---

## 1. Nmap Port Scan — T1046

**MITRE ATT&CK:** T1046 — Network Service Discovery

**Log Source:** `/var/log/kern.log`

**Detection:** High-rate multi-port scanning

### SPL Query

    index=main source="/var/log/kern.log" IPTABLES_SCAN
    | rex "SRC=(?<SourceIP>\d+\.\d+\.\d+\.\d+)"
    | rex "DST=(?<DestinationIP>\d+\.\d+\.\d+\.\d+)"
    | rex "DPT=(?<DestinationPort>\d+)"
    | rex "PROTO=(?<Protocol>\w+)"
    | bin _time span=1m
    | stats dc(DestinationPort) as unique_ports values(DestinationPort) as ports_hit earliest(_time) as first_seen latest(_time) as last_seen by SourceIP DestinationIP _time
    | eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
    | eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
    | where unique_ports > 15

### Detection Logic

The query extracts the source IP, destination IP, destination port, and protocol from iptables telemetry.

Events are grouped into one-minute windows. The number of unique destination ports contacted by each source is then calculated.

A source contacting more than 15 unique destination ports within one minute is identified as potential automated network scanning.

### Observed Result

- Source IP: `10.148.52.135`
- Target IP: `10.148.52.71`
- Unique destination ports: `1,002`
- Detection window: `12:41:00`

The activity was consistent with automated Nmap reconnaissance.

---

## 2. SSH Brute Force — T1110.001

**MITRE ATT&CK:** T1110.001 — Password Guessing

**Log Source:** `/var/log/auth.log`

**Detection:** Multiple failed SSH authentication attempts followed by successful authentication

### SPL Query

    index=main source="/var/log/auth.log" ("Failed password" OR "Accepted password")
    | rex "(?<AuthenticationResult>Failed|Accepted) password for (?:invalid user )?(?<Username>\S+) from (?<SourceIP>\d+\.\d+\.\d+\.\d+) port (?<SourcePort>\d+)"
    | eval Result=if(AuthenticationResult="Accepted","SUCCESS","FAILED")
    | table _time SourceIP SourcePort Username Result host
    | sort _time

### Detection Logic

The query searches for both failed and successful SSH authentication attempts.

The authentication result is normalized into `FAILED` and `SUCCESS`, allowing the analyst to investigate repeated authentication failures followed by a successful login.

### Observed Result

- Source IP: `10.148.52.135`
- Target account: `sujith`
- Failed attempts: `7`
- Successful attempts: `1`
- Time range: approximately `12:44:29–12:45:37`

The seven failed attempts were followed by a successful authentication from the same Kali source.

### Analyst Investigation

Review:

- Source IP
- Target username
- Number of failed attempts
- Successful authentication
- Authentication timestamps
- Activity performed after successful authentication

---

## 3. SQL Injection Against DVWA — T1190

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application

**Log Source:** `/var/log/apache2/access.log`

**Detection:** Requests targeting the DVWA SQL injection endpoint

### SPL Query

    index=main source="/var/log/apache2/access.log" "/dvwa/vulnerabilities/sqli/"
    | rex "^(?<SourceIP>\S+) \S+ \S+ \[(?<ApacheTime>[^\]]+)\] \"(?<Method>\S+) (?<URI>\S+) (?<Protocol>[^\"]+)\" (?<Status>\d+) (?<Bytes>\d+)"
    | table _time SourceIP Method URI Status Bytes
    | sort _time

### Detection Logic

The query searches Apache access logs for requests to the DVWA SQL injection endpoint.

The `rex` command extracts:

- Source IP
- HTTP method
- URI
- HTTP protocol
- HTTP status
- Response size

### Observed Result

- Source IP: `10.148.52.135`
- Target application: DVWA
- Six SQL injection-module requests were observed.
- Activity occurred approximately between `12:47:18–12:48:10`.
- Requests returned HTTP `200`.
- Activity progressed from parameter requests to URL-encoded SQL injection activity.
- A blind SQL injection request was subsequently observed.

### Observed Payload Pattern

    id=%27+OR+%271%27%3D%271

### Analyst Investigation

Review:

- Client/source IP
- Requested URI
- HTTP parameters
- HTTP status
- Response size
- Application logs
- Database logs

### Evidence Limitation

The Apache logs establish SQL injection activity against DVWA.

They do not independently prove that this activity resulted in compromise of the Windows endpoint.

---

## 4. Encoded PowerShell — T1059.001

**MITRE ATT&CK:** T1059.001 — PowerShell

**Log Source:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`

**Event ID:** 1 — Process Creation

**Detection:** PowerShell execution with encoded command and process lineage

### SPL Query

    index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    earliest="08/04/2026:12:52:00" latest="08/04/2026:12:53:00"
    | rex "Image:\s+(?<ProcessImage>[^\r\n]+)"
    | rex "ParentImage:\s+(?<ParentImage>[^\r\n]+)"
    | rex "CommandLine:\s+(?<CommandLine>[^\r\n]+)"
    | rex "User:\s+(?<User>[^\r\n]+)"
    | search ProcessImage="*powershell.exe" OR Image="*powershell.exe"
    | table _time User ProcessImage ProcessId ParentImage CommandLine ProcessGuid
    | sort _time

### Detection Logic

The query searches Sysmon Event ID 1 for PowerShell process creation.

The detection extracts:

- User
- Process image
- Process ID
- Parent image
- Command line
- Process GUID

The time window is restricted to the relevant Atomic Red Team execution.

### Observed Result

At approximately `12:52:22`, the Windows endpoint recorded:

    cmd.exe
        |
        └── powershell.exe
                |
                └── -EncodedCommand

The execution occurred under:

    Sujith\SUJITH

### Analyst Investigation

Review:

- Executing user
- Parent process
- PowerShell process
- Command line
- Process ID
- Process GUID
- Encoded payload
- Related processes

The encoded command should be safely decoded and analyzed during investigation.

---

## 5. Local User Creation — T1136.001

**MITRE ATT&CK:** T1136.001 — Local Account

**Log Source:** `WinEventLog:Security`

**Event ID:** 4720 — User Account Created

**Detection:** Creation of new local Windows accounts

### SPL Query

    index=main source="WinEventLog:Security" EventCode=4720
    | rex "Subject:\s*(?s).*?Account Name:\s+(?<SubjectUserName>[^\r\n]+)"
    | rex "New Account:\s*(?s).*?Account Name:\s+(?<TargetUserName>[^\r\n]+)"
    | rex "New Account:\s*(?s).*?Security ID:\s+(?<TargetSID>[^\r\n]+)"
    | table _time SubjectUserName TargetUserName TargetSID host
    | sort _time

### Detection Logic

Windows Security Event 4720 is used to identify local account creation.

The query extracts:

- Subject username
- New account username
- Target SID
- Host
- Timestamp

### Observed Result

The account:

    attacker

was observed in account-creation events.

The account was observed at approximately:

    13:09:48

and again at:

    13:18:08

with different SIDs.

### Analyst Investigation

Review:

- Account creator
- New account name
- SID
- Host
- Creation time
- Subsequent authentication
- Subsequent privilege changes

Unexpected account creation should be investigated as a possible persistence or unauthorized-account activity.

---

## 6. Add User to Administrators — T1098

**MITRE ATT&CK:** T1098 — Account Manipulation

**Log Source:** `WinEventLog:Security`

**Event ID:** 4732 — Member Added to Security-Enabled Local Group

**Detection:** Addition of an account to the local Administrators group

### SPL Query

    index=main source="WinEventLog:Security" EventCode=4732
    | rex "Subject:\s*(?s).*?Account Name:\s+(?<SubjectUserName>[^\r\n]+)"
    | rex "Member:\s*(?s).*?Account Name:\s+(?<MemberName>[^\r\n]+)"
    | rex "Member:\s*(?s).*?Security ID:\s+(?<MemberSID>[^\r\n]+)"
    | rex "Group:\s*(?s).*?Group Name:\s+(?<GroupName>[^\r\n]+)"
    | search GroupName="Administrators"
    | table _time SubjectUserName MemberName MemberSID GroupName host
    | sort _time

### Detection Logic

The query searches for Windows Security Event 4732 and filters for the local Administrators group.

The query extracts:

- Subject username
- Member account
- Member SID
- Group name
- Host
- Timestamp

### Observed Result

At approximately:

    13:18:15

the account:

    attacker

was added to the local Administrators group.

This occurred approximately seven seconds after the second account-creation event.

### Analyst Investigation

Review:

- Account performing the change
- Account added to the group
- Target group
- Host
- Timestamp
- Related account-creation events
- Subsequent privileged activity

### Event Selection

Event `4732` is used to detect a member being added to a security-enabled local group.

Event `4672` represents special privileges assigned to a logon and should not be substituted for the group-membership detection.

---

## 7. Scheduled Task Creation — T1053.005

**MITRE ATT&CK:** T1053.005 — Scheduled Task

**Log Source:** `WinEventLog:Security`

**Event ID:** 4698 — Scheduled Task Created

**Detection:** Creation of Windows scheduled tasks

### SPL Query

    index=main source="WinEventLog:Security" EventCode=4698
    | rex "Subject:\s*(?s).*?Account Name:\s+(?<SubjectUserName>[^\r\n]+)"
    | rex "Task Name:\s+(?<TaskName>[^\r\n]+)"
    | rex "Task Content:\s*(?<TaskContent>[\s\S]*)"
    | table _time SubjectUserName TaskName TaskContent host
    | sort _time

### Detection Logic

Windows Security Event 4698 records the creation of a scheduled task.

The query extracts:

- Subject username
- Task name
- Task content/XML
- Host
- Timestamp

### Observed Result

At approximately:

    13:40:14

the Windows host recorded creation of:

    \SOC_Task

The task contained a TimeTrigger with:

    StartBoundary: 2026-08-04T23:59:00

### Analyst Investigation

Review:

- Task name
- Creating account
- Task XML
- Trigger
- Action/command
- Execution context
- Creation timestamp

A scheduled task should not automatically be considered malicious solely because Event 4698 exists. The task action, creator, trigger, and execution context must be validated.

---

# Cross-Detection Correlation

The detections can be investigated together to reconstruct the activity observed in the lab.

    12:41
    Nmap Port Scan
    T1046
        |
        v
    12:44–12:45
    SSH Brute Force
    T1110.001
    7 FAILED -> 1 SUCCESS
        |
        v
    12:47–12:48
    SQL Injection against DVWA
    T1190
        |
        v
    12:52
    Encoded PowerShell
    T1059.001
        |
        v
    13:09
    Local Account Creation
    T1136.001
        |
        v
    13:18
    Local Account Creation
    T1136.001
        |
        v
    13:18
    Added to Administrators
    T1098
        |
        v
    13:40
    Scheduled Task Creation
    T1053.005

---

# Detection-to-MITRE Mapping

| Detection | Event / Source | MITRE ATT&CK | Tactic |
|---|---|---|---|
| Nmap Port Scan | iptables / kern.log | T1046 | Reconnaissance |
| SSH Brute Force | auth.log | T1110.001 | Credential Access |
| SQL Injection | Apache access.log | T1190 | Initial Access |
| Encoded PowerShell | Sysmon Event 1 | T1059.001 | Execution |
| Local Account Creation | Security 4720 | T1136.001 | Persistence |
| Administrators Group Addition | Security 4732 | T1098 | Privilege Escalation |
| Scheduled Task Creation | Security 4698 | T1053.005 | Persistence |

---

# IOC Summary

| Indicator | Value | Context |
|---|---|---|
| Kali Source IP | `10.148.52.135` | Nmap, SSH brute force, DVWA activity |
| Target IP | `10.148.52.71` | Linux/DVWA target |
| SSH Target Account | `sujith` | SSH brute-force activity |
| Suspicious Local Account | `attacker` | Account creation and privilege modification |
| Suspicious Process | `powershell.exe` | Encoded PowerShell execution |
| Parent Process | `cmd.exe` | Parent of PowerShell |
| Scheduled Task | `\SOC_Task` | Scheduled task creation |
| Windows Host | `Sujith` | Windows security telemetry |

---

# Detection Engineering Opportunities

## SSH Brute Force

Correlate repeated failures followed by successful authentication.

    Multiple FAILED attempts
            +
    Same Source IP
            +
    Same Username
            +
    SUCCESS
            =
    High-priority authentication alert

## Account Creation and Privilege Escalation

Correlate:

    Event 4720
    Local account created
            |
            v
    Event 4732
    Added to privileged local group
            |
            v
    High-value privilege escalation indicator

## PowerShell

Increase detection confidence when PowerShell execution contains:

    PowerShell
        +
    EncodedCommand
        +
    Suspicious parent process
        +
    Unusual execution context

## Scheduled Tasks

Increase investigation priority when a scheduled task:

- Is created by an unexpected account
- Executes PowerShell, cmd, or scripts
- Executes from an unusual directory
- Uses an unusual trigger
- Was created outside normal administrative activity
- Contains suspicious command-line arguments

---

# Analyst Response Summary

| Detection | Immediate Triage | Recommended Response |
|---|---|---|
| Nmap Port Scan | Validate source and scanned ports | Review exposed services and contain unauthorized scanning source |
| SSH Brute Force | Confirm failure-to-success sequence | Reset credentials, contain source, review SSH activity |
| SQL Injection | Inspect URI, parameters, and responses | Review application/database logs and remediate vulnerability |
| Encoded PowerShell | Review command line, parent process, and user | Validate Atomic test or isolate endpoint if unauthorized |
| Event 4720 | Identify creator and new account | Validate authorization and disable/remove unauthorized account |
| Event 4732 | Identify member and target group | Remove unauthorized membership and investigate privileged activity |
| Event 4698 | Inspect task XML, trigger, and action | Validate task and remove unauthorized persistence |

---

# Evidence Integrity

The Kali source IP:

    10.148.52.135

is directly evidenced for:

- Nmap activity
- SSH brute-force activity
- DVWA SQL injection activity

The Windows execution and account/persistence events are independently supported by:

- Sysmon telemetry
- Windows Security Event 4720
- Windows Security Event 4732
- Windows Security Event 4698

The available evidence does not independently prove a network-level pivot from the Kali/DVWA environment to the Windows endpoint.

Therefore, the project deliberately avoids making an unsupported claim of network-level lateral movement.

This reflects an important SOC investigation principle:

**Only make conclusions that are supported by available telemetry.**

---

# Future Detection Improvements

The detection capability can be expanded by adding:

1. Sysmon Event ID 3 network connection telemetry
2. DNS telemetry
3. Scheduled Splunk alerts
4. Risk-based alert prioritization
5. Threat-intelligence enrichment
6. IOC enrichment
7. C2 detection
8. Data-exfiltration detection
9. Process-tree correlation
10. Authentication baselines
11. Threat-hunting workflows
12. Wazuh integration
13. Microsoft Sentinel integration
14. AI-assisted SOC investigation
15. Automated alert enrichment

---

# SOC Analyst Detection Workflow

    Telemetry Collection
            |
            v
    Log Ingestion
            |
            v
    Field Extraction
            |
            v
    SPL Detection
            |
            v
    Detection Validation
            |
            v
    Event Correlation
            |
            v
    Investigation
            |
            v
    IOC Identification
            |
            v
    MITRE ATT&CK Mapping
            |
            v
    Timeline Reconstruction
            |
            v
    Incident Analysis
            |
            v
    Response Recommendation

---

# Project Outcome

This detection-engineering exercise demonstrates how centralized security telemetry can be used to identify and investigate simulated attack activity across Linux, web application, and Windows environments.

The project focuses on:

- Security telemetry collection
- Splunk SIEM
- SPL detection engineering
- Linux log analysis
- Windows Security Event analysis
- Sysmon process telemetry
- Event correlation
- MITRE ATT&CK mapping
- IOC identification
- Incident timeline reconstruction
- SOC triage
- Evidence-based investigation

The project demonstrates a practical SOC workflow:

**Telemetry → Detection → Correlation → Investigation → MITRE Mapping → Incident Analysis → Response**

---

# Disclaimer

This project was performed in an isolated and intentionally vulnerable home-lab environment for cybersecurity learning and defensive detection-engineering purposes.

All attack simulations were conducted against systems controlled for the purpose of the lab.

No unauthorized systems were intentionally targeted.

---

# Author

**G Sujith**

Cybersecurity / SOC Analyst Candidate

**Project:** SOC Home Lab — Detection Engineering & Incident Analysis
