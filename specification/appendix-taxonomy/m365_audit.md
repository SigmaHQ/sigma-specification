# product: m365, service: audit

```yaml
logsource:
    product: m365
    service: audit
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Audit log of Microsoft 365, read with the Office 365 Management API.

## Points of Attention

- A record is identified by `Workload`, for example `Exchange`, by `Operation` and by `ResultStatus`.

## Fields

The rules of this log source use the following field names:

- `ApplicationId`
- `DeliveryAction`
- `Directionality`
- `ObjectId`
- `Operation`
- `RequestType`
- `ResultStatus`
- `Workload`
