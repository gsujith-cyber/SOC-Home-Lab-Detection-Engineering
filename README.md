# SOC Home Lab — Detection Engineering & Incident Analysis

Hands-on SOC home lab using Splunk Enterprise to ingest multi-source security telemetry, develop SPL detections, correlate attack activity, map events to MITRE ATT&CK, and reconstruct an incident timeline.

## Project Focus

- Splunk SIEM and SPL
- Detection engineering
- Linux and Windows log analysis
- Sysmon and Windows Security Event analysis
- MITRE ATT&CK mapping
- Incident timeline reconstruction
- IOC identification
- SOC triage and response

## Lab Stack

Splunk Enterprise · Kali Linux · Nmap · Hydra · Apache2 · DVWA · Sysmon · Windows Security Logs · iptables · Atomic Red Team

## Simulated Attack Chain

| Activity | MITRE ATT&CK | Evidence |
|---|---|---|
| Nmap Port Scan | T1046 — Network Service Discovery | iptables / kern.log |
| SSH Brute Force | T1110.001 — Password Guessing | auth.log |
| SQL Injection against DVWA | T1190 — Exploit Public-Facing Application | Apache access.log |
| Encoded PowerShell | T1059.001 — PowerShell | Sysmon Event 1 |
| Local Account Creation | T1136.001 — Local Account | Security Event 4720 |
| Add Account to Administrators | T1098.007 — Additional Local or Domain Groups | Security Event 4732 |
| Scheduled Task Creation | T1053.005 — Scheduled Task | Security Event 4698 |

## Key Detection Examples

### SSH Brute Force

The lab identified seven failed SSH authentication attempts followed by a successful authentication from the same Kali source.

### Encoded PowerShell

Sysmon captured `cmd.exe → powershell.exe -EncodedCommand`, preserving the process lineage and command line for investigation.

### Account Escalation

A local account creation event (4720) was followed seven seconds later by a privileged local-group membership change (4732). This provides a high-value correlation opportunity.

### Scheduled Task

Event 4698 captured creation of `\SOC_Task`. The task XML and trigger were preserved so the analyst could validate the actual task action.

## Evidence Integrity

The Kali source `10.148.52.135` is directly evidenced for the Nmap, SSH and DVWA activity.

The Windows execution and account/persistence events are supported independently by Sysmon and Windows Security telemetry.

The available evidence does **not** independently prove a network-level pivot from Kali/DVWA to Windows, so the project deliberately avoids making that unsupported claim.

## Detection Engineering Opportunities

- Detect repeated SSH failures followed by success
- Detect high-rate port scanning
- Detect encoded PowerShell with suspicious process lineage
- Correlate 4720 → 4732 account escalation
- Detect suspicious scheduled-task creation
- Add network and DNS telemetry for future C2/exfiltration detection

## Future Improvements

1. Enable Sysmon Event ID 3.
2. Add DNS telemetry.
3. Convert searches into scheduled Splunk alerts.
4. Build a dedicated SOC dashboard.
5. Add risk-based alert prioritization.
6. Simulate C2 and data exfiltration.
7. Extend the lab with Wazuh and Microsoft Sentinel.
8. Add threat-hunting and AI-assisted SOC workflows.

## Disclaimer

This project was performed in an isolated, intentionally vulnerable home-lab environment for cybersecurity learning and defensive detection engineering. No unauthorized systems were targeted.

## Author

**G Sujith**

Cybersecurity / SOC Analyst Candidate
