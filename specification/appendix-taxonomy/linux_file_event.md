# category: file_event, product: linux

```yaml
logsource:
    category: file_event
    product: linux
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Files created on a Linux host monitored by Sysmon for Linux.

## Telemetry

Events written by Sysmon for Linux, with the field names of the Sysmon schema of the Windows agent.

- EventID: 11
- Sysmon events: FileCreate

## Points of Attention

- Sysmon has to be installed and the events of this log source have to be enabled in its configuration, see the [example configurations](https://github.com/SwiftOnSecurity/sysmon-config).

## Fields

The rules of this log source use the following field names:

- `Image`
- `TargetFilename`
