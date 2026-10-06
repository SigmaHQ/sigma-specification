# category: file_block_shredding, product: windows

```yaml
logsource:
    category: file_block_shredding
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventID: 28
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: FileBlockShredding

## Points of Attention

- Sysmon has to be installed and the events of this log source have to be enabled in its configuration, see the [example configurations](https://github.com/SwiftOnSecurity/sysmon-config).
