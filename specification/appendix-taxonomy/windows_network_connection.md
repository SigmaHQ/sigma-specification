# category: network_connection, product: windows

```yaml
logsource:
    category: network_connection
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventID: 3
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: NetworkConnect

## Points of Attention

- Sysmon has to be installed and the events of this log source have to be enabled in its configuration, see the [example configurations](https://github.com/SwiftOnSecurity/sysmon-config).
- The rules set `definition: 'Requirements: The CommandLine field enrichment is required in order for this rule to be used.'`.
- The rules set `definition: 'Requirements: Field enrichment is required for the filters to work. As field such as CommandLine and ParentImage are not available by default on this event type'`.

## Fields

The rules of this log source use the following field names:

- `CommandLine`
- `DestinationHostname`
- `DestinationIp`
- `DestinationPort`
- `Image`
- `Initiated`
- `ParentImage`
- `Protocol`
- `SourceHostname`
- `SourceIp`
- `SourceIsIpv6`
- `SourcePort`
