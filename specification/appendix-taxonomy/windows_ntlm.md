# product: windows, service: ntlm

```yaml
logsource:
    product: windows
    service: ntlm
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Microsoft-Windows-NTLM / EventID: 8001](#microsoft-windows-ntlm--eventid-8001)
  - [Microsoft-Windows-NTLM / EventID: 8002](#microsoft-windows-ntlm--eventid-8002)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-NTLM/Operational

## Points of Attention

- The rules set `definition: 'Requires events from Microsoft-Windows-NTLM/Operational'`. 3 rules use the same requirement.

## Fields

The rules of this log source use the following field names:

- `EventID`
- `TargetName`
- `WorkstationName`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-NTLM / EventID: 8001

- `TargetName`
- `UserName`
- `DomainName`
- `CallerPID`
- `ProcessName`
- `ClientLUID`
- `ClientUserName`
- `ClientDomainName`
- `MechanismOID`

### Microsoft-Windows-NTLM / EventID: 8002

- `CallerPID`
- `ProcessName`
- `ClientLUID`
- `ClientUserName`
- `ClientDomainName`
- `MechanismOID`

<!-- event-fields:end -->
