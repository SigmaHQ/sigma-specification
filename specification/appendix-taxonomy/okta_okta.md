# product: okta, service: okta

```yaml
logsource:
    product: okta
    service: okta
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

System log events of Okta, read from the Okta system log API.

## Points of Attention

- An event type is written in the `eventType` field and in the `legacyEventType` field, the rules of the repository match on one or on the other.
- The result of the event is in `outcome.result`, the reason of a failure is in `outcome.reason`.

## Fields

The rules of this log source use the following field names:

- `actor.alternateId`
- `debugContext.debugData.requestUri`
- `displayMessage`
- `eventType`
- `legacyEventType`
- `outcome.reason`
- `outcome.result`
- `securityContext.isProxy`
- `target.displayName`
