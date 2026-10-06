# category: image_load, product: windows

```yaml
logsource:
    category: image_load
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventID: 7
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: ImageLoad

## Points of Attention

- Sysmon has to be installed and the events of this log source have to be enabled in its configuration, see the [example configurations](https://github.com/SwiftOnSecurity/sysmon-config).

## Fields

The rules of this log source use the following field names:

- `CommandLine`
- `Company`
- `Description`
- `Hashes`
- `Image`
- `ImageLoaded`
- `OriginalFileName`
- `Product`
- `Signature`
- `SignatureStatus`
- `Signed`
