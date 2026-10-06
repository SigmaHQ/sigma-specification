# category: application, product: kubernetes, service: audit

```yaml
logsource:
    category: application
    product: kubernetes
    service: audit
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Audit events of the API server of Kubernetes, as they are written in the audit log of the cluster.

## Points of Attention

- The audited object is in `objectRef`, the action that was applied to it is in `verb` and its API group in `apiGroup`.

## Fields

The rules of this log source use the following field names:

- `apiGroup`
- `capabilities`
- `hostPath`
- `objectRef.namespace`
- `objectRef.resource`
- `objectRef.subresource`
- `verb`
