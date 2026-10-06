# category: network_connection, product: linux

```yaml
logsource:
    category: network_connection
    product: linux
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Network connections established by a process on a Linux host monitored by Sysmon for Linux.

## Telemetry

Events written by Sysmon for Linux, with the field names of the Sysmon schema of the Windows agent.

- EventID: 3
- Sysmon events: NetworkConnect

## Points of Attention

- Sysmon has to be installed and the events of this log source have to be enabled in its configuration, see the [example configurations](https://github.com/SwiftOnSecurity/sysmon-config).

## Fields

The rules of this log source use the following field names:

- `DestinationHostname`
- `DestinationIp`
- `DestinationPort`
- `Image`
- `Initiated`
