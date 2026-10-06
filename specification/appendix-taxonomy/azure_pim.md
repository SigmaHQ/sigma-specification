# product: azure, service: pim

```yaml
logsource:
    product: azure
    service: pim
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Events of the Azure Privileged Identity Management, that is the activations and the requests for the privileged roles.

## Points of Attention

- The rules match on `riskEventType`.

## Fields

The rules of this log source use the following field names:

- `riskEventType`
