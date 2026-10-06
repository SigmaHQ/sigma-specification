# product: windows, category: process_creation

```yaml
logsource:
    product: windows
    category: process_creation
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
  - [Microsoft Windows Security Auditing](#microsoft-windows-security-auditing)
  - [Microsoft-Windows-Sysmon](#microsoft-windows-sysmon)
- [Points of Attention](#points-of-attention)
  - [Microsoft Windows Security Auditing](#microsoft-windows-security-auditing-1)
  - [Microsoft-Windows-Sysmon](#microsoft-windows-sysmon-1)
- [Fields](#fields)
  - [Microsoft Windows Security Auditing / EventID: 4688](#microsoft-windows-security-auditing--eventid-4688)
  - [Microsoft-Windows-Sysmon / EventID: 1](#microsoft-windows-sysmon--eventid-1)

<!-- mdformat-toc end -->

## Description

Processes started on a Windows host. Two event sources write the events of this category, the process creation event of the Windows security auditing and the process create event of Sysmon.

## Telemetry

### Microsoft Windows Security Auditing

- Provider: Microsoft Windows Security Auditing
- Channel: Security
- EventID: 4688

### Microsoft-Windows-Sysmon

- Provider: Microsoft-Windows-Sysmon
- Channel: Microsoft-Windows-Sysmon/Operational
- EventID: 1
- Sysmon event: ProcessCreate

## Points of Attention

This section copies the logsource guide [`documentation/logsource-guides/windows/category/process_creation.md`](https://github.com/SigmaHQ/sigma/blob/master/documentation/logsource-guides/windows/category/process_creation.md) of the rules repository.

- The two event sources don't write the same fields. The fields of the Sysmon event, `Image`, `CommandLine`, `ParentImage` and `ParentCommandLine` for example, have no equivalent in the event of the `Security` channel. A rule has to match on the fields of the event source it is written for.
- The rules that need a field that the event source doesn't write declare the enrichment in their `definition`, for example `Requirements: ParentUser field needs sysmon >= 13.30`.
- `ParentUser` is only written by Sysmon from version 13.30.
- The events of the `Security` channel are only written when the `Audit Process Creation` subcategory is enabled, they are high volume.

### Microsoft Windows Security Auditing

- Subcategory GUID: `{0CCE922B-69AE-11D9-BED3-505054503030}`
- Event volume: high

Enable the subcategory with the Advanced Audit Policy Configuration of the `gpedit.msc` or of an equivalent tool:

```text
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit Process Creation
                            - Success and Failure
```

Or with `auditpol`:

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

[Learn more about this subcategory](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)

A command line is only in the event when the policy that includes it is enabled:

```text
- Computer Configuration
    - Administrative Templates
        - System
            - Audit Process Creation
                - Include Command Line In Process Creation Events
```

### Microsoft-Windows-Sysmon

- Event volume: high

Install Sysmon with a configuration that includes a `<ProcessCreate>` element, the [sysmonconfig-export.xml](https://github.com/Neo23x0/sysmon-config/blob/master/sysmonconfig-export.xml) configuration is an example:

```powershell
sysmon -i /path/to/config
```

[Download Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Fields

### Microsoft Windows Security Auditing / EventID: 4688

- `SubjectUserSid`
- `SubjectUserName`
- `SubjectDomainName`
- `SubjectLogonId`
- `NewProcessId`
- `NewProcessName`
- `TokenElevationType`
- `ProcessId`
- `CommandLine`
- `TargetUserSid`
- `TargetUserName`
- `TargetDomainName`
- `TargetLogonId`
- `ParentProcessName`
- `MandatoryLabel`

### Microsoft-Windows-Sysmon / EventID: 1

| Field Name        | Example Value                                                                             | Comment |
| ----------------- | ----------------------------------------------------------------------------------------- | ------- |
| UtcTime           | 2019-03-02 08:51:00.008                                                                   |         |
| ProcessGuid       | {c1b49677-43f4-5c7a-0000-0010d3dd8044}                                                    |         |
| ProcessId         | 1028                                                                                      |         |
| Image             | C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe                                 |         |
| FileVersion       | 1.3.28.13                                                                                 |         |
| Description       | Google Installer                                                                          |         |
| Product           | Google Update                                                                             |         |
| Company           | Google Inc.                                                                               |         |
| OriginalFileName  | GoogleUpdate.exe                                                                          |         |
| CommandLine       | "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /ua /installsource scheduler  |         |
| CurrentDirectory  | C:\\Windows\\system32                                                                     |         |
| User              | NT AUTHORITY\\SYSTEM                                                                      |         |
| LogonGuid         | {c1b49677-3fb9-5c09-0000-0020e7030000}                                                    |         |
| LogonId           | 0x3e7                                                                                     |         |
| TerminalSessionId | 0                                                                                         |         |
| IntegrityLevel    | System                                                                                    |         |
| Hashes            | MD5=CCF1D1573F175299ADE01C07791A6541,IMPHASH=E96A73C7BF33A464C510EDE582318BF2             |         |
| imphash           | E96A73C7BF33A464C510EDE582318BF2                                                          |         |
| md5               | CCF1D1573F175299ADE01C07791A6541                                                          |         |
| sha1              | 0AE1F9071C5E8FE4A69D3F671937935D242D8A6C                                                  |         |
| sha256            | 68A15A34C2E28B9B521A240B948634617D72AD619E3950BC6DC769E60A0C3CF2                          |         |
| ParentProcessGuid | {c1b49677-6b43-5c78-0000-00107fb77544}                                                    |         |
| ParentProcessId   | 1724                                                                                      |         |
| ParentImage       | C:\\Windows\\System32\\taskeng.exe                                                        |         |
| ParentCommandLine | taskeng.exe {88F94E5C-5DC3-4606-AEFA-BDCA976D6113} S-1-5-18:NT AUTHORITY\\System:Service: |         |
| ParentUser        | NT AUTHORITY\\SYSTEM                                                                      |         |
