# product: windows, service: dns-client

```yaml
logsource:
    product: windows
    service: dns-client
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Microsoft-Windows-DNS-Client / EventID: 3008](#microsoft-windows-dns-client--eventid-3008)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-DNS Client Events/Operational

## Points of Attention

- The rules set `definition: 'Requirements: Microsoft-Windows-DNS Client Events/Operational Event Log must be enabled/collected in order to receive the events.'`. 6 rules use the same requirement.

## Fields

The rules of this log source use the following field names:

- `EventID`
- `QueryName`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-DNS-Client / EventID: 3008

- `QueryName`
- `QueryType`
- `QueryOptions`
- `QueryStatus`
- `QueryResults`

<!-- event-fields:end -->
