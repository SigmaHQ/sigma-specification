# product: windows, service: capi2

```yaml
logsource:
    product: windows
    service: capi2
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Microsoft-Windows-CAPI2 / EventID: 70](#microsoft-windows-capi2--eventid-70)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-CAPI2/Operational

## Points of Attention

- The rules set `definition: 'Requirements: The CAPI2 Operational log needs to be enabled'`.

## Fields

The rules of this log source use the following field names:

- `EventID`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-CAPI2 / EventID: 70

- `EventWriteData`

<!-- event-fields:end -->
