# category: create_remote_thread, product: windows

```yaml
logsource:
    category: create_remote_thread
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventID: 8
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: CreateRemoteThread

## Points of Attention

- Sysmon has to be installed and the events of this log source have to be enabled in its configuration, see the [example configurations](https://github.com/SwiftOnSecurity/sysmon-config).

## Fields

The rules of this log source use the following field names:

- `SourceCommandLine`
- `SourceImage`
- `SourceParentImage`
- `StartAddress`
- `StartFunction`
- `StartModule`
- `TargetImage`
- `TargetParentProcessId`
