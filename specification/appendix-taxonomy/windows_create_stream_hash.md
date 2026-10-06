# category: create_stream_hash, product: windows

```yaml
logsource:
    category: create_stream_hash
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventID: 15
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: FileCreateStreamHash

## Points of Attention

- Sysmon has to be installed and the events of this log source have to be enabled in its configuration, see the [example configurations](https://github.com/SwiftOnSecurity/sysmon-config).
- The rules set `definition: 'Requirements: Sysmon config with Imphash logging activated'`.
- The rules set `definition: 'Requirements: Sysmon or equivalent configured with Imphash logging'`.

## Fields

The rules of this log source use the following field names:

- `Contents`
- `Hash`
- `Image`
- `TargetFilename`
