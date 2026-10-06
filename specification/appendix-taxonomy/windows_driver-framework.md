# product: windows, service: driver-framework

```yaml
logsource:
    product: windows
    service: driver-framework
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-DriverFrameworks-UserMode/Operational

## Points of Attention

- The rules set `definition: 'Requires enabling and collection of the Microsoft-Windows-DriverFrameworks-UserMode/Operational eventlog'`.

## Fields

The rules of this log source use the following field names:

- `EventID`
