# product: m365, service: threat_management

```yaml
logsource:
    product: m365
    service: threat_management
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Threat management alerts of Microsoft 365, read with the Microsoft Graph API.

## Points of Attention

- The rules set `definition: 'Requires the 'eDiscovery search or exported' alert to be enabled'`.
- The detail of the alert is in `Payload`, the type of the event is in `eventName` and the result of the action that was taken is in `status`.

## Fields

The rules of this log source use the following field names:

- `Payload`
- `eventName`
- `eventSource`
- `status`
