# product: windows, service: lsa-server

```yaml
logsource:
    product: windows
    service: lsa-server
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [LsaSrv / EventID: 300](#lsasrv--eventid-300)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-LSA/Operational

## Points of Attention

- The rules set `definition: 'Requirements: Microsoft-Windows-LSA/Operational (199FE037-2B82-40A9-82AC-E1D46C792B99) Event Log must be enabled and collected in order to use this rule.'`.

## Fields

The rules of this log source use the following field names:

- `EventID`
- `SidList`
- `TargetUserSid`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### LsaSrv / EventID: 300

- `TargetUserSid`
- `TargetUserName`
- `TargetDomainName`
- `TargetLogonId`
- `TargetLogonGuid`
- `EventOrginal`
- `EventCountTotal`
- `SidList`

<!-- event-fields:end -->
