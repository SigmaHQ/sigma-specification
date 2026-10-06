# product: kubernetes, service: audit

```yaml
logsource:
    product: kubernetes
    service: audit
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Audit events of the API server of Kubernetes, read from the audit log of the cluster.

## Points of Attention

- The rule of the request is in `verb`, the audited object in `objectRef` and the answer of the API server in `responseStatus.code`.

## Fields

The rules of this log source use the following field names:

- `objectRef.apiGroup`
- `objectRef.resource`
- `requestURI`
- `responseStatus.code`
- `userAgent`
- `verb`
