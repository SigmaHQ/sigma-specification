# product: windows, service: windefend

```yaml
logsource:
    product: windows
    service: windefend
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Microsoft-Windows-Windows Defender / EventID: 1009](#microsoft-windows-windows-defender--eventid-1009)
  - [Microsoft-Windows-Windows Defender / EventID: 1013](#microsoft-windows-windows-defender--eventid-1013)
  - [Microsoft-Windows-Windows Defender / EventID: 1116](#microsoft-windows-windows-defender--eventid-1116)
  - [Microsoft-Windows-Windows Defender / EventID: 1121](#microsoft-windows-windows-defender--eventid-1121)
  - [Microsoft-Windows-Windows Defender / EventID: 5001](#microsoft-windows-windows-defender--eventid-5001)
  - [Microsoft-Windows-Windows Defender / EventID: 5007](#microsoft-windows-windows-defender--eventid-5007)
  - [Microsoft-Windows-Windows Defender / EventID: 5010](#microsoft-windows-windows-defender--eventid-5010)
  - [Microsoft-Windows-Windows Defender / EventID: 5012](#microsoft-windows-windows-defender--eventid-5012)
  - [Microsoft-Windows-Windows Defender / EventID: 5013](#microsoft-windows-windows-defender--eventid-5013)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-Windows Defender/Operational

## Points of Attention

- The rules set `definition: 'Requirements:Enabled Block process creations originating from PSExec and WMI commands from Attack Surface Reduction (GUID: d1e49aac-8f56-4280-b9ba-993a6d77406c)'`.

## Fields

The rules of this log source use the following field names:

- `EventID`
- `Feature_Name`
- `NewValue`
- `OldValue`
- `Path`
- `ProcessName`
- `Reason`
- `SourceName`
- `Value`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-Windows Defender / EventID: 1009

- `Product Name`
- `Product Version`
- `Unused`
- `Unused2`
- `Unused3`
- `Unused4`
- `Unused5`
- `Domain`
- `User`
- `SID`
- `Threat Name`
- `Threat ID`
- `Severity ID`
- `Category ID`
- `FWLink`
- `Path`
- `Unused6`
- `Unused7`
- `Unused8`
- `Unused9`
- `Unused10`
- `Unused11`
- `Unused12`
- `Unused13`
- `Severity Name`
- `Category Name`
- `Security intelligence Version`
- `Engine Version`

### Microsoft-Windows-Windows Defender / EventID: 1013

- `Product Name`
- `Product Version`
- `Timestamp`
- `Unused`
- `Unused2`
- `Unused3`
- `Unused4`
- `Domain`
- `User`
- `SID`

### Microsoft-Windows-Windows Defender / EventID: 1116

- `Product Name`
- `Product Version`
- `Detection ID`
- `Detection Time`
- `Unused`
- `Unused2`
- `Threat ID`
- `Threat Name`
- `Severity ID`
- `Severity Name`
- `Category ID`
- `Category Name`
- `FWLink`
- `Status Code`
- `Status Description`
- `State`
- `Source ID`
- `Source Name`
- `Process Name`
- `Detection User`
- `Unused3`
- `Path`
- `Origin ID`
- `Origin Name`
- `Execution ID`
- `Execution Name`
- `Type ID`
- `Type Name`
- `Pre Execution Status`
- `Action ID`
- `Action Name`
- `Unused4`
- `Error Code`
- `Error Description`
- `Unused5`
- `Post Clean Status`
- `Additional Actions ID`
- `Additional Actions String`
- `Remediation User`
- `Unused6`
- `Security intelligence Version`
- `Engine Version`

### Microsoft-Windows-Windows Defender / EventID: 1121

- `Product Name`
- `Product Version`
- `Unused`
- `ID`
- `Detection Time`
- `User`
- `Path`
- `Process Name`
- `Security intelligence Version`
- `Engine Version`
- `RuleType`
- `Target Commandline`
- `Parent Commandline`
- `Involved File`
- `Inhertiance Flags`

### Microsoft-Windows-Windows Defender / EventID: 5001

- `Product Name`
- `Product Version`

### Microsoft-Windows-Windows Defender / EventID: 5007

- `Product Name`
- `Product Version`
- `Old Value`
- `New Value`

### Microsoft-Windows-Windows Defender / EventID: 5010

- `Product Name`
- `Product Version`

### Microsoft-Windows-Windows Defender / EventID: 5012

- `Product Name`
- `Product Version`

### Microsoft-Windows-Windows Defender / EventID: 5013

- `Product Name`
- `Product Version`
- `Changed Type`
- `Value`

<!-- event-fields:end -->
