# product: azure, service: riskdetection

```yaml
logsource:
    product: azure
    service: riskdetection
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Risk detections of the Identity Protection of Azure Active Directory.

## Points of Attention

- The rules match on `riskEventType`.

## Fields

The rules of this log source use the following field names:

- `riskEventType`
