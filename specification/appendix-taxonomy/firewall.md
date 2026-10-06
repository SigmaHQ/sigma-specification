# category: firewall

```yaml
logsource:
    category: firewall
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Connections allowed or blocked by a firewall, with the action that was taken.

## Points of Attention

- The field names come from the log format of the firewall product, they differ between the vendors and have to be mapped to these names.

## Fields

The rules of this log source use the following field names:

- `action`
- `blocked`
- `dst_port`
