# product: windows, service: firewall-as

```yaml
logsource:
    product: windows
    service: firewall-as
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-Windows Firewall With Advanced Security / EventID: 2009](#microsoft-windows-windows-firewall-with-advanced-security--eventid-2009)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall

## Fields

The rules of this log source use the following field names:

- `Action`
- `ApplicationPath`
- `EventID`
- `ModifyingApplication`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-Windows Firewall With Advanced Security / EventID: 2009

- `ErrorCode`

<!-- event-fields:end -->
