# product: windows, service: application

```yaml
logsource:
    product: windows
    service: application
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Application Error / EventID: 1000](#application-error--eventid-1000)
  - [Application-Addon-Event-Provider / EventID: 1](#application-addon-event-provider--eventid-1)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Application

## Points of Attention

- 4 different requirements are declared in the `definition` of the rules of this log source, they are written rule by rule.

## Fields

The rules of this log source use the following field names:

- `AppName`
- `Data`
- `EventID`
- `ExceptionCode`
- `Level`
- `Message`
- `Provider_Name`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Application Error / EventID: 1000

- `AppName`
- `AppVersion`
- `AppTimeStamp`
- `ModuleName`
- `ModuleVersion`
- `ModuleTimeStamp`
- `ExceptionCode`
- `FaultingOffset`
- `ProcessId`

### Application-Addon-Event-Provider / EventID: 1

- `Application`
- `AddonName`
- `Publisher`
- `Version`

<!-- event-fields:end -->
