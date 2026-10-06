# product: windows, service: bits-client

```yaml
logsource:
    product: windows
    service: bits-client
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-Bits-Client / EventID: 3](#microsoft-windows-bits-client--eventid-3)
  - [Microsoft-Windows-Bits-Client / EventID: 16403](#microsoft-windows-bits-client--eventid-16403)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-Bits-Client/Operational

## Fields

The rules of this log source use the following field names:

- `EventID`
- `LocalName`
- `RemoteName`
- `processPath`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-Bits-Client / EventID: 3

- `string`
- `string2`
- `string3`

### Microsoft-Windows-Bits-Client / EventID: 16403

- `User`
- `jobTitle`
- `jobId`
- `jobOwner`
- `fileCount`
- `RemoteName`
- `LocalName`
- `processId`
- `ClientProcessStartKey`

<!-- event-fields:end -->
