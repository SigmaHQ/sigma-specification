# product: windows, service: system

```yaml
logsource:
    product: windows
    service: system
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-Eventlog / EventID: 26](#microsoft-windows-eventlog--eventid-26)
  - [Microsoft-Windows-Eventlog / EventID: 104](#microsoft-windows-eventlog--eventid-104)
  - [Microsoft-Windows-Ntfs / EventID: 98](#microsoft-windows-ntfs--eventid-98)
  - [Service Control Manager / EventID: 7023](#service-control-manager--eventid-7023)
  - [Service Control Manager / EventID: 7034](#service-control-manager--eventid-7034)
  - [Service Control Manager / EventID: 7036](#service-control-manager--eventid-7036)
  - [Service Control Manager / EventID: 7045](#service-control-manager--eventid-7045)

<!-- mdformat-toc end -->

## Telemetry

- Channel: System

## Fields

The rules of this log source use the following field names:

- `AccountName`
- `Caption`
- `Channel`
- `Description`
- `DeviceName`
- `EventID`
- `HiveName`
- `ImagePath`
- `IsatapRouter`
- `Origin`
- `ProcessId`
- `Provider_Name`
- `ServiceName`
- `param1`
- `param2`
- `param3`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-Eventlog / EventID: 26

- `ChannelPath`

### Microsoft-Windows-Eventlog / EventID: 104

- `SubjectUserName`
- `SubjectDomainName`
- `Channel`
- `BackupPath`

### Microsoft-Windows-Ntfs / EventID: 98

- `DriveName`
- `DeviceName`
- `CorruptionActionState`

### Service Control Manager / EventID: 7023

- `param1`
- `param2`
- `__binLength`
- `BinaryData`

### Service Control Manager / EventID: 7034

- `param1`
- `param2`
- `__binLength`
- `BinaryData`

### Service Control Manager / EventID: 7036

- `param1`
- `param2`
- `__binLength`
- `BinaryData`

### Service Control Manager / EventID: 7045

- `ServiceName`
- `ImagePath`
- `ServiceType`
- `StartType`
- `AccountName`

<!-- event-fields:end -->
