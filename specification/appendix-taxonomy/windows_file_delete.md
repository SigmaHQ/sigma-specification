# category: file_delete, product: windows

```yaml
logsource:
    category: file_delete
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventID: 23
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: FileDelete

## Points of Attention

- Sysmon has to be installed and the events of this log source have to be enabled in its configuration, see the [example configurations](https://github.com/SwiftOnSecurity/sysmon-config).

## Fields

The rules of this log source use the following field names:

- `Image`
- `TargetFilename`
- `User`
