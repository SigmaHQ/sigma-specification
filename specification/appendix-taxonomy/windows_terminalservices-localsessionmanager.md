# product: windows, service: terminalservices-localsessionmanager

```yaml
logsource:
    product: windows
    service: terminalservices-localsessionmanager
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-TerminalServices-LocalSessionManager / EventID: 21](#microsoft-windows-terminalservices-localsessionmanager--eventid-21)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational

## Fields

The rules of this log source use the following field names:

- `Address`
- `EventID`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-TerminalServices-LocalSessionManager / EventID: 21

- `User`
- `SessionID`
- `Address`

<!-- event-fields:end -->
