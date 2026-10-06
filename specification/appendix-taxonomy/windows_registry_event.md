# category: registry_event, product: windows

```yaml
logsource:
    category: registry_event
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventIDs:
  - 12
  - 13
  - 14
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: RegistryAddOrDelete, RegistrySetValue, RegistryRename

## Points of Attention

- The registry creations and deletions are written in the same Sysmon event, `EventType` tells which of them was logged.

## Fields

The rules of this log source use the following field names:

- `Details`
- `EventID`
- `EventType`
- `Image`
- `NewName`
- `TargetObject`
