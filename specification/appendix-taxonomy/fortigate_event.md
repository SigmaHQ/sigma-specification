# product: fortigate, service: event

```yaml
logsource:
    product: fortigate
    service: event
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Events of a Fortinet FortiGate firewall, with the configuration path of the object that the event is about in `cfgpath`.

## Points of Attention

- The action that was applied is in `action`, the values depend on the log type of the FortiGate.

## Fields

The rules of this log source use the following field names:

- `action`
- `cfgpath`
