# product: onelogin, service: onelogin.events

```yaml
logsource:
    product: onelogin
    service: onelogin.events
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Events of the audit log of OneLogin, read from the OneLogin API.

## Points of Attention

- The rules match on `event_type_id`, the identifier of the event type of the OneLogin audit log.

## Fields

The rules of this log source use the following field names:

- `event_type_id`
