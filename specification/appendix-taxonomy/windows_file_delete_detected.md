# category: file_delete_detected, product: windows

```yaml
logsource:
    category: file_delete_detected
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventID: 26
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: FileDeleteDetected

## Points of Attention

- Sysmon has to be installed and the events of this log source have to be enabled in its configuration, see the [example configurations](https://github.com/SwiftOnSecurity/sysmon-config).
