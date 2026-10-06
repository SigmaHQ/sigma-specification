# product: windows, service: appmodel-runtime

```yaml
logsource:
    product: windows
    service: appmodel-runtime
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-AppModel-Runtime / EventID: 201](#microsoft-windows-appmodel-runtime--eventid-201)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-AppModel-Runtime/Admin

## Fields

The rules of this log source use the following field names:

- `EventID`
- `ImageName`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-AppModel-Runtime / EventID: 201

- `ProcessID`
- `PackageName`
- `ImageName`
- `ApplicationName`
- `Message`

<!-- event-fields:end -->
