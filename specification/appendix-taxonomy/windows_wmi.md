# product: windows, service: wmi

```yaml
logsource:
    product: windows
    service: wmi
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Microsoft-Windows-WMI-Activity / EventID: 5858](#microsoft-windows-wmi-activity--eventid-5858)
  - [Microsoft-Windows-WMI-Activity / EventID: 5859](#microsoft-windows-wmi-activity--eventid-5859)
  - [Microsoft-Windows-WMI-Activity / EventID: 5861](#microsoft-windows-wmi-activity--eventid-5861)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-WMI-Activity/Operational

## Points of Attention

- The rules set `definition: 'WMI Namespaces Auditing and SACL should be configured, EventID 5861 and 5859 detection requires Windows 10, 2012 and higher'`.

## Fields

The rules of this log source use the following field names:

- `EventID`
- `Operation`
- `PossibleCause`
- `Provider`
- `Query`
- `User`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-WMI-Activity / EventID: 5858

- `Id`
- `ClientMachine`
- `User`
- `ClientProcessId`
- `Component`
- `Operation`
- `ResultCode`
- `PossibleCause`

### Microsoft-Windows-WMI-Activity / EventID: 5859

- `NamespaceName`
- `Query`
- `User`
- `processid`
- `providerName`
- `queryid`
- `PossibleCause`

### Microsoft-Windows-WMI-Activity / EventID: 5861

- `Namespace`
- `ESS`
- `CONSUMER`
- `PossibleCause`

<!-- event-fields:end -->
