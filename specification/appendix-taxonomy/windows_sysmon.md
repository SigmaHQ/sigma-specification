# product: windows, service: sysmon

```yaml
logsource:
    product: windows
    service: sysmon
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Microsoft-Windows-Sysmon / EventID: 16](#microsoft-windows-sysmon--eventid-16)
  - [Microsoft-Windows-Sysmon / EventID: 27](#microsoft-windows-sysmon--eventid-27)
  - [Microsoft-Windows-Sysmon / EventID: 28](#microsoft-windows-sysmon--eventid-28)
  - [Microsoft-Windows-Sysmon / EventID: 29](#microsoft-windows-sysmon--eventid-29)

<!-- mdformat-toc end -->

## Description

Events written by Sysmon when it blocks an operation or when its configuration is changed. The other events of Sysmon use the Sigma category that describes them, for example `category: file_event, product: windows`, with the fields of the Sysmon schema.

## Telemetry

Events written by Sysmon.

- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: SysmonConfigChange, FileBlockExecutable, FileBlockShredding, FileExecutableDetected

## Points of Attention

- Only the configuration changes of Sysmon and the operations it blocked or denied are written to this log source. The rules for the other Sysmon events use the category that describes the event.

## Fields

The rules of this log source use the following field names:

- `EventID`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-Sysmon / EventID: 16

- `UtcTime`
- `Configuration`
- `ConfigurationFileHash`

### Microsoft-Windows-Sysmon / EventID: 27

- `RuleName`
- `UtcTime`
- `ProcessGuid`
- `ProcessId`
- `User`
- `Image`
- `TargetFilename`
- `Hashes`

### Microsoft-Windows-Sysmon / EventID: 28

- `RuleName`
- `UtcTime`
- `ProcessGuid`
- `ProcessId`
- `User`
- `Image`
- `TargetFilename`
- `Hashes`
- `IsExecutable`

### Microsoft-Windows-Sysmon / EventID: 29

- `RuleName`
- `UtcTime`
- `ProcessGuid`
- `ProcessId`
- `User`
- `Image`
- `TargetFilename`
- `Hashes`

<!-- event-fields:end -->
