# product: windows, service: iis-configuration

```yaml
logsource:
    product: windows
    service: iis-configuration
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-IIS-Configuration / EventID: 29](#microsoft-windows-iis-configuration--eventid-29)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-IIS-Configuration/Operational

## Fields

The rules of this log source use the following field names:

- `Configuration`
- `EventID`
- `NewValue`
- `OldValue`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-IIS-Configuration / EventID: 29

- `Configuration`
- `ConfigPath`

<!-- event-fields:end -->
