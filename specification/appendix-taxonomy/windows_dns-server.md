# product: windows, service: dns-server

```yaml
logsource:
    product: windows
    service: dns-server
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-DNS-Server-Service / EventID: 6004](#microsoft-windows-dns-server-service--eventid-6004)

<!-- mdformat-toc end -->

## Telemetry

- Channel: DNS Server

## Fields

The rules of this log source use the following field names:

- `EventID`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-DNS-Server-Service / EventID: 6004

- `param1`
- `param2`

<!-- event-fields:end -->
