# product: bitbucket, service: audit

```yaml
logsource:
    product: bitbucket
    service: audit
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Audit events of a Bitbucket repository, read from the audit log of the instance.

## Points of Attention

- The kind of the action is in `auditType.category` and the action itself in `auditType.action`.
- The audit events are only sent when the log level of the instance is set to `ADVANCED` or to `BASIC`.

## Fields

The rules of this log source use the following field names:

- `auditType.action`
- `auditType.category`
