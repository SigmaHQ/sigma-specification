# product: gcp, service: google_workspace.login

```yaml
logsource:
    product: gcp
    service: google_workspace.login
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Login events of the users of Google Workspace.

## Points of Attention

- The login events are in the `login_success` and in the `login_failure` streams, the event is in `protoPayload.metadata.event.eventName`.

## Fields

The rules of this log source use the following field names:

- `protoPayload.metadata.event.eventName`
- `protoPayload.serviceName`
