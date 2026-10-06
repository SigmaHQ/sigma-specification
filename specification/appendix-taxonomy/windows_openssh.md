# product: windows, service: openssh

```yaml
logsource:
    product: windows
    service: openssh
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [OpenSSH / EventID: 4](#openssh--eventid-4)

<!-- mdformat-toc end -->

## Telemetry

- Channel: OpenSSH/Operational

## Fields

The rules of this log source use the following field names:

- `EventID`
- `payload`
- `process`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### OpenSSH / EventID: 4

- `process`
- `payload`

<!-- event-fields:end -->
