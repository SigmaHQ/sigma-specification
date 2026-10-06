# product: windows, service: ldap

```yaml
logsource:
    product: windows
    service: ldap
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Microsoft-Windows-LDAP-Client / EventID: 30](#microsoft-windows-ldap-client--eventid-30)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-LDAP-Client/Debug

## Points of Attention

- The rules set `definition: 'Requirements: Microsoft-Windows-LDAP-Client/Debug ETW logging'`.

## Fields

The rules of this log source use the following field names:

- `DistinguishedName`
- `EventID`
- `SearchFilter`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-LDAP-Client / EventID: 30

- `ScopeOfSearch`
- `SearchFilter`
- `DistinguishedName`
- `AttributeList`
- `ProcessId`

<!-- event-fields:end -->
