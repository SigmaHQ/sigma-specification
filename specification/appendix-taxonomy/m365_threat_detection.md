# product: m365, service: threat_detection

```yaml
logsource:
    product: m365
    service: threat_detection
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Threat detection events of Exchange Online, read with the Office 365 Management API.

## Points of Attention

- The event is in `eventName`, the result of the detection is in `status`.

## Fields

The rules of this log source use the following field names:

- `eventName`
- `eventSource`
- `status`
