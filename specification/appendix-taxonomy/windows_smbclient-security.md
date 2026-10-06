# product: windows, service: smbclient-security

```yaml
logsource:
    product: windows
    service: smbclient-security
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-SMBClient / EventID: 31017](#microsoft-windows-smbclient--eventid-31017)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-SmbClient/Security

## Fields

The rules of this log source use the following field names:

- `EventID`
- `ServerName`
- `UserName`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-SMBClient / EventID: 31017

- `UserNameLength`
- `UserName`
- `ServerNameLength`
- `ServerName`

<!-- event-fields:end -->
