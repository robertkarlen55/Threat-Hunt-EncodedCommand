# Threat-Hunt-EncodedCommand
Threat Hunt Report: Suspicious PowerShell Activity

Scenario Creation

Platforms and Languages Leveraged:

Windows 10 Virtual Machine (Local or Microsoft Azure)

EDR Platform: Microsoft Defender for Endpoint

Query Language: Kusto Query Language (KQL)

Simulated Tool: Windows PowerShell

Scenario

Cybersecurity leadership requested proactive hunting of suspicious PowerShell usage after receiving industry threat intelligence indicating a spike in malicious actors using encoded PowerShell commands and script files dropped in user-writable directories like Downloads and Temp. The objective was to simulate potential attacker behavior, generate realistic logs, and validate detection coverage for unauthorized PowerShell script creation, obfuscated execution, and potential exfiltration or callback activity.

High-Level PowerShell-Related IoC Discovery Plan

Check DeviceFileEvents for .ps1 file creation in user-accessible directories.

Check DeviceProcessEvents for PowerShell run with -File or -EncodedCommand.

Check DeviceNetworkEvents for outbound connections initiated by powershell.exe.

Steps Taken

1. Searched the DeviceFileEvents Table

A PowerShell script named open_calc.ps1 was created in the Downloads folder by the user "robertkarlen55" at 2025-05-10T13:43:00Z.

Query used:

DeviceFileEvents
| where FileName endswith ".ps1"
| where FolderPath has_any("Downloads", "Desktop", "Temp", "Public")
| project Timestamp, DeviceName, RequestAccountName, FileName, FolderPath

2. Searched the DeviceProcessEvents Table for Script Execution

The file was executed directly via PowerShell with -ExecutionPolicy Bypass.

Timestamp: 2025-05-10T13:45:00Z

Query used:

DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has ".ps1"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

3. Searched the DeviceProcessEvents Table for EncodedCommand Usage

The same command was then base64-encoded and executed using the -EncodedCommand flag.

Timestamp: 2025-05-10T13:50:00Z

Query used:

DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

4. Searched the DeviceNetworkEvents Table for PowerShell Callouts

A simulated outbound connection to https://example.com was generated using Invoke-WebRequest, triggering a network event from PowerShell.

Timestamp: 2025-05-10T13:53:00Z

Query used:

DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemoteUrl

Chronological Event Timeline

Script Creation - open_calc.ps1Timestamp: 2025-05-10T13:43:00ZAction: File created in Downloads folder.Path: C:\Users\robertkarlen55\Downloads\open_calc.ps1

Script Execution via PowerShell -FileTimestamp: 2025-05-10T13:45:00ZCommand: powershell -ExecutionPolicy Bypass -File open_calc.ps1

EncodedCommand ExecutionTimestamp: 2025-05-10T13:50:00ZCommand: powershell -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACIAYwBhAGwAYwAuAGUAeABlACIA

Outbound Web Call - Invoke-WebRequestTimestamp: 2025-05-10T13:53:00ZCommand: Invoke-WebRequest -Uri "https://example.com" -UseBasicParsing

Summary

User "robertkarlen55" on the local Windows 10 VM created and executed a PowerShell script using both standard and obfuscated (Base64-encoded) command lines. Network telemetry confirmed outbound HTTP connections were made using PowerShell, simulating data exfiltration or C2 beacon behavior. This validates detection capability for multiple PowerShell abuse techniques commonly seen in real-world attacks.

Response Taken

All activity was simulated in a safe, isolated lab VM. No actual threat was present. Logs were preserved for training and detection tuning. No user or system remediation was required.

