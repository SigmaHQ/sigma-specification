# category: registry_add, product: windows

```yaml
logsource:
    category: registry_add
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventID: 12
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: RegistryAddOrDelete

## Points of Attention

- The Sysmon event of this log source is written for the creations and for the deletions, `EventType` tells which of them was logged, `CreateKey`, `DeleteKey`, `CreateValue` or `DeleteValue`.

## Fields

The rules of this log source use the following field names:

- `EventType`
- `TargetObject`
