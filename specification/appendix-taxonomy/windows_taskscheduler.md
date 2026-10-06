# product: windows, service: taskscheduler

```yaml
logsource:
    product: windows
    service: taskscheduler
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Microsoft-Windows-TaskScheduler / EventID: 129](#microsoft-windows-taskscheduler--eventid-129)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-TaskScheduler/Operational

## Points of Attention

- The rules set `definition: 'Requirements: The "Microsoft-Windows-TaskScheduler/Operational" is disabled by default and needs to be enabled in order for this detection to trigger'`. 3 rules use the same requirement.

## Fields

The rules of this log source use the following field names:

- `EventID`
- `Path`
- `TaskName`
- `UserName`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-TaskScheduler / EventID: 129

- `TaskName`
- `Path`
- `ProcessID`
- `Priority`

<!-- event-fields:end -->
